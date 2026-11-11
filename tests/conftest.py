"""Shared pytest fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def import_root(tmp_path, monkeypatch):
    root = tmp_path / "imports"
    monkeypatch.setenv("IMPORT_ROOT", str(root))
    # GC must be immediate in tests; real default is one hour.
    monkeypatch.setenv("IMPORT_STALE_SECONDS", "0")
    monkeypatch.delenv("IMPORT_FAILPOINT", raising=False)
    return root


@pytest.fixture()
def sentinel(tmp_path):
    """A file outside IMPORT_ROOT that must never be modified."""
    sentinel_dir = tmp_path / "outside"
    sentinel_dir.mkdir()
    marker = sentinel_dir / "sentinel.txt"
    marker.write_text("untouched")
    return marker
