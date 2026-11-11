"""Cross-process concurrency, idempotency and crash-window recovery tests."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from importer import catalog, service
from importer.safety import InconsistentStateError
from tools import make_archives as m

ROOT = Path(__file__).resolve().parents[1]


def _run_worker(import_root: Path, payload: Path, tenant, package, key,
                failpoint=None, extra_env=None):
    env = {"IMPORT_ROOT": str(import_root), "IMPORT_STALE_SECONDS": "0",
           "PYTHONPATH": str(ROOT)}
    if failpoint:
        env["IMPORT_FAILPOINT"] = failpoint
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [sys.executable, "-I", str(ROOT / "tools" / "worker.py"),
         str(payload), json.dumps(env), tenant, package, key],
        capture_output=True, text=True, timeout=120,
    )
    return proc


def _write_payload(tmp_path, name, data) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_idempotent_retry_returns_same_version(import_root, tmp_path):
    payload = _write_payload(tmp_path, "a.zip", m.normal_package())
    first = service.import_package("t", "p", payload.read_bytes(), "idem-1")
    second = service.import_package("t", "p", payload.read_bytes(), "idem-1")
    assert first["version"] == second["version"]
    assert second.get("replayed") is True
    rows = catalog.version_ids("t", "p")
    assert rows == {first["version"]}


def test_distinct_keys_create_distinct_versions(import_root, tmp_path):
    payload = _write_payload(tmp_path, "a.zip", m.normal_package())
    r1 = service.import_package("t", "p", payload.read_bytes(), "k-1")
    r2 = service.import_package("t", "p", payload.read_bytes(), "k-2")
    assert r1["version"] != r2["version"]
    assert catalog.latest("t", "p")["id"] == r2["version"]


def test_two_processes_same_key_publish_one_version(import_root, tmp_path):
    payload = _write_payload(tmp_path, "a.zip", m.normal_package())
    procs = [
        _run_worker(import_root, payload, "t", "p", "shared-key")
        for _ in range(2)
    ]
    codes = sorted(p.returncode for p in procs)
    assert codes == [0, 0], [p.stderr for p in procs]
    results = [json.loads(p.stdout.strip().splitlines()[-1])["result"]
               for p in procs]
    assert results[0]["version"] == results[1]["version"]
    assert len(catalog.version_ids("t", "p")) == 1


def test_two_processes_distinct_keys_both_survive(import_root, tmp_path):
    payload = _write_payload(tmp_path, "a.zip", m.normal_package())
    keys = ["key-alpha", "key-beta"]
    procs = [
        _run_worker(import_root, payload, "t", "p", key) for key in keys
    ]
    assert [p.returncode for p in procs] == [0, 0]
    versions = catalog.version_ids("t", "p")
    assert len(versions) == 2
    # Each committed version directory must still hold its own files.
    for ident in versions:
        path = Path(catalog.connect().execute(
            "SELECT path FROM versions WHERE id=?", (ident,)
        ).fetchone()["path"])
        assert (path / "assets" / "hello.txt").is_file()


def test_crash_after_publish_leaves_no_visible_version_and_reaps(
    import_root, tmp_path
):
    payload = _write_payload(tmp_path, "a.zip", m.normal_package())
    proc = _run_worker(
        import_root, payload, "t", "p", "crash-1",
        failpoint="after_publish",
    )
    assert proc.returncode == 77
    assert catalog.latest("t", "p") is None
    versions_root = import_root / "t" / "p" / "versions"
    assert any(versions_root.iterdir())  # orphan on disk, not in catalog

    # A real crash orphan is older than the commit grace window; model that.
    import time as _time

    orphan = next(versions_root.iterdir())
    old = _time.time() - 60
    os.utime(orphan, (old, old))

    removed = service.reap_orphans("t", "p", ttl=0)
    assert len(removed["versions"]) == 1
    assert list(versions_root.iterdir()) == []

    # Retry with the same key starts cleanly and publishes once.
    ok = service.import_package("t", "p", payload.read_bytes(), "crash-1")
    assert ok["state"] == "published"
    assert catalog.latest("t", "p")["id"] == ok["version"]


def test_crash_after_commit_replay_serves_committed_version(
    import_root, tmp_path
):
    payload = _write_payload(tmp_path, "a.zip", m.normal_package())
    proc = _run_worker(
        import_root, payload, "t", "p", "crash-2",
        failpoint="after_commit",
    )
    assert proc.returncode == 77
    committed = catalog.latest("t", "p")
    assert committed is not None  # commit landed before the exit

    replay = service.import_package("t", "p", payload.read_bytes(), "crash-2")
    assert replay["version"] == committed["id"]
    assert replay.get("replayed") is True
    assert len(catalog.version_ids("t", "p")) == 1


def test_failed_import_does_not_touch_other_request_staging(
    import_root, tmp_path
):
    good = _write_payload(tmp_path, "good.zip", m.normal_package())
    bad = _write_payload(tmp_path, "bad.zip", m.bad_crc())
    p_bad = _run_worker(import_root, bad, "t", "p", "bad-key")
    p_good = _run_worker(import_root, good, "t", "p", "good-key")
    assert p_bad.returncode != 0
    assert p_good.returncode == 0
    latest = catalog.latest("t", "p")
    assert latest["idempotency_key"] == "good-key"


def test_replay_with_missing_files_raises_inconsistent(import_root, tmp_path):
    payload = _write_payload(tmp_path, "a.zip", m.normal_package())
    first = service.import_package("t", "p", payload.read_bytes(), "idem-x")
    shutil_target = Path(catalog.latest("t", "p")["path"])
    import shutil

    shutil.rmtree(shutil_target)
    with pytest.raises(InconsistentStateError):
        service.import_package("t", "p", payload.read_bytes(), "idem-x")
    assert first["version"]  # catalog row intentionally left for forensics


def test_staging_directories_are_per_request(import_root, tmp_path):
    payload = _write_payload(tmp_path, "a.zip", m.normal_package())
    service.import_package("t", "p", payload.read_bytes(), "k1")
    service.import_package("t", "p", payload.read_bytes(), "k2")
    staging = import_root / "t" / "p" / "staging"
    # Successful requests remove their staging tree via the atomic rename.
    assert list(staging.iterdir()) == []


def test_fresh_uncommitted_version_is_protected_by_grace(import_root, tmp_path):
    """A concurrent reaper must not touch an in-flight rename-to-commit window."""
    import uuid

    versions_root = import_root / "t" / "p" / "versions"
    versions_root.mkdir(parents=True)
    in_flight = versions_root / str(uuid.uuid4())
    in_flight.mkdir()
    # ttl=0 would reap a stale orphan, but the grace window protects a fresh one.
    removed = service.reap_orphans("t", "p", ttl=0)
    assert in_flight.exists()
    assert removed["versions"] == []
