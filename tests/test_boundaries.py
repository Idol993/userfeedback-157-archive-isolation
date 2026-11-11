"""Exact-boundary tests: limits are inclusive on the allowed side."""
from __future__ import annotations

import random

import pytest

from importer import catalog, service
from importer.safety import (
    MAX_ENTRIES,
    MAX_FILE_SIZE,
    MAX_TOTAL_SIZE,
    ResourceLimitError,
)
from tools import make_archives as m


def _incompressible(size: int, seed: int = 1234) -> bytes:
    # Deterministic high-entropy payload so the ratio rule does not fire first.
    return random.Random(seed).randbytes(size)


def test_exactly_max_entries_accepted(import_root):
    data = m.archive([(f"f{i:04d}.txt", b"x") for i in range(MAX_ENTRIES)])
    result = service.import_package("t", "p", data, "k")
    assert result["state"] == "published"
    assert len(result["files"]) == MAX_ENTRIES


def test_one_over_max_entries_rejected(import_root):
    with pytest.raises(ResourceLimitError):
        service.import_package("t", "p", m.too_many_entries(), "k")


def test_file_exactly_at_size_cap_accepted(import_root):
    data = m.archive([("edge.bin", _incompressible(MAX_FILE_SIZE))])
    result = service.import_package("t", "p", data, "k")
    assert result["state"] == "published"


def test_total_exactly_at_cap_accepted(import_root):
    # Four files at the per-file cap land exactly on the 32 MiB total cap.
    data = m.archive(
        [
            (f"part{i}.bin", _incompressible(MAX_FILE_SIZE, seed=i))
            for i in range(4)
        ]
    )
    result = service.import_package("t", "p", data, "k")
    assert result["state"] == "published"
    assert catalog.latest("t", "p") is not None


def test_one_byte_over_total_cap_rejected(import_root):
    # Five files just under the per-file cap that collectively exceed 32 MiB.
    per = MAX_TOTAL_SIZE // 5 + 1
    data = m.archive(
        [(f"f{i}.bin", _incompressible(per, seed=i)) for i in range(5)]
    )
    with pytest.raises(ResourceLimitError):
        service.import_package("t", "p", data, "k")
    assert catalog.latest("t", "p") is None
