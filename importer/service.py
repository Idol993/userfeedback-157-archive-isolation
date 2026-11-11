"""Import orchestration: isolated staging, atomic publish, crash recovery.

On-disk layout per tenant/package::

    $IMPORT_ROOT/<tenant>/<package>/staging/<uuid>    # per-request scratch
    $IMPORT_ROOT/<tenant>/<package>/versions/<uuid>   # immutable published versions

Crash windows and their recovery:
* after the staging tree is renamed into ``versions/`` but before the DB
  transaction commits (failpoint ``after_publish``): the version directory is an
  orphan, reaped by ``reap_orphans``; no ``current`` pointer ever names it, so
  no half-finished version is visible.
* after the DB commit but before the response is sent (failpoint
  ``after_commit``): a retry carrying the same ``idempotency_key`` finds the
  committed row and returns its stored manifest instead of creating a second
  version.

Each request uses its own UUID staging directory, so a failed or concurrent
request never deletes another request's files.
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path

from . import audit, catalog
from .extract import extract_report
from .safety import (
    InconsistentStateError,
    validate_idempotency_key,
    validate_label,
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
DEFAULT_STALE_SECONDS = 3600
# A directory in versions/ that has no catalog row is normally a crash orphan,
# but during a healthy concurrent import it briefly exists between the atomic
# rename and the DB commit. Never reap it younger than this grace window.
VERSION_GRACE_SECONDS = 30


def _stale_seconds() -> int:
    try:
        return int(os.environ.get("IMPORT_STALE_SECONDS", DEFAULT_STALE_SECONDS))
    except ValueError:
        return DEFAULT_STALE_SECONDS


def _package_root(tenant: str, package: str):
    base = catalog.root() / tenant / package
    return base, base / "staging", base / "versions"


def _is_old(path, ttl: int) -> bool:
    try:
        return time.time() - path.stat().st_mtime > ttl
    except FileNotFoundError:
        return False


def reap_orphans(tenant: str, package: str, ttl: int | None = None) -> dict:
    """Remove abandoned staging trees and un-published version directories.

    Only UUID-named directories are eligible, and version directories are
    deleted only when the catalog has no matching version row.  Everything
    deleted here is at least ``ttl`` seconds old, so an in-flight request is
    never reaped.
    """
    tenant = validate_label(tenant, "tenant")
    package = validate_label(package, "package")
    ttl = _stale_seconds() if ttl is None else ttl
    _, staging_root, versions_root = _package_root(tenant, package)
    removed = {"staging": [], "versions": []}

    for root, bucket in ((staging_root, "staging"), (versions_root, "versions")):
        if not root.exists():
            continue
        known_ids = catalog.version_ids(tenant, package) if bucket == "versions" else set()
        age_threshold = ttl
        if bucket == "versions":
            # Honor the caller's ttl but never undercut the commit grace window.
            age_threshold = max(ttl, VERSION_GRACE_SECONDS)
        for child in root.iterdir():
            if not child.is_dir() or not _UUID_RE.fullmatch(child.name):
                continue
            if bucket == "versions" and child.name in known_ids:
                continue
            if not _is_old(child, age_threshold):
                continue
            shutil.rmtree(child, ignore_errors=True)
            if not child.exists():
                removed[bucket].append(child.name)
                audit.record(
                    "orphan_reaped",
                    tenant=tenant,
                    package=package,
                    bucket=bucket,
                    ident=child.name,
                )
    return removed


def _replay(row) -> dict:
    path = Path(row["path"])
    if not path.is_dir():
        audit.record(
            "inconsistent_state",
            reason="published version directory missing",
            ident=row["id"],
        )
        raise InconsistentStateError(
            f"published version {row['id']} is missing its files; operator "
            f"recovery required"
        )
    names = json.loads(row.get("manifest") or "[]")
    return {
        "version": row["id"],
        "files": names,
        "state": "published",
        "replayed": True,
    }


def import_package(tenant, package, data, key):
    tenant = validate_label(tenant, "tenant")
    package = validate_label(package, "package")
    key = validate_idempotency_key(key)

    # Repeated requests with the same key always get the committed answer.
    existing = catalog.find_idempotent(tenant, package, key)
    if existing is not None:
        audit.record(
            "import_idempotent_replay",
            tenant=tenant,
            package=package,
            ident=existing["id"],
        )
        return _replay(existing)

    # Best-effort cleanup from earlier crashes; never let GC fail a new import.
    try:
        reap_orphans(tenant, package)
    except Exception as exc:  # pragma: no cover - defensive
        audit.record("orphan_reap_failed", tenant=tenant, package=package, error=exc)

    ident = str(uuid.uuid4())
    base, staging_root, versions_root = _package_root(tenant, package)
    staging = staging_root / ident
    published = versions_root / ident
    staging.mkdir(parents=True, exist_ok=False)
    names: list[str] = []

    try:
        report = extract_report(io.BytesIO(data), staging)
        names = report.names

        versions_root.mkdir(parents=True, exist_ok=True)
        # Same filesystem (both under the package directory), so this rename is
        # an atomic move; the version becomes visible to reapers only now.
        os.replace(staging, published)

        if os.environ.get("IMPORT_FAILPOINT") == "after_publish":
            audit.record(
                "failpoint_after_publish", tenant=tenant, package=package, ident=ident
            )
            os._exit(77)

        committed_id, outcome = catalog.publish(
            tenant,
            package,
            ident,
            published,
            key,
            json.dumps(names, ensure_ascii=False),
        )

        if os.environ.get("IMPORT_FAILPOINT") == "after_commit":
            audit.record(
                "failpoint_after_commit", tenant=tenant, package=package, ident=ident
            )
            os._exit(77)

        if outcome == "idempotent_replay":
            # A concurrent request won the key race. Our directory is not in the
            # catalog; remove only our own tree, never the winner's files.
            shutil.rmtree(published, ignore_errors=True)
            row = catalog.find_idempotent(tenant, package, key)
            audit.record(
                "import_idempotent_lost_race",
                tenant=tenant,
                package=package,
                ident=ident,
                winner=committed_id,
            )
            return _replay(row)

        audit.record(
            "import_published",
            tenant=tenant,
            package=package,
            ident=ident,
            entries=report.entries,
            bytes=report.total_uncompressed,
            idempotent=bool(key),
        )
        return {"version": ident, "files": names, "state": "published"}

    except Exception as exc:
        # Roll back only this request's own directories.
        for own in (staging, published):
            if own.exists():
                shutil.rmtree(own, ignore_errors=True)
        audit.record(
            "import_rejected",
            tenant=tenant,
            package=package,
            reason=exc.__class__.__name__,
            detail=str(exc)[:200],
            idempotent=bool(key),
        )
        raise
