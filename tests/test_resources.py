"""Streaming resource-limit and corruption regression tests."""
from __future__ import annotations

import zipfile

import pytest

from importer import catalog, service
from importer.safety import ResourceLimitError, UnsafePackageError
from tools import make_archives as m


def _reject(sample, import_root):
    with pytest.raises((UnsafePackageError, zipfile.BadZipFile)):
        service.import_package("team-a", "pkg", sample, "")
    # Limits/corruption must fail the whole import, never publish a half tree.
    assert catalog.latest("team-a", "pkg") is None
    versions = import_root / "team-a" / "pkg" / "versions"
    if versions.exists():
        assert list(versions.iterdir()) == []


def test_zip_bomb_ratio_rejected(import_root):
    _reject(m.zip_bomb_ratio(), import_root)


def test_too_many_entries_rejected(import_root):
    _reject(m.too_many_entries(), import_root)


def test_total_size_limit_rejected(import_root):
    _reject(m.over_total_size(), import_root)


def test_per_file_limit_rejected(import_root):
    _reject(m.over_file_size(), import_root)


def test_header_size_lie_still_enforced(import_root):
    # The header claims one byte; the real stream must still be measured.
    with pytest.raises(ResourceLimitError):
        service.import_package("team-a", "pkg", m.header_size_lie(), "")


def test_bad_crc_rejected(import_root):
    with pytest.raises(zipfile.BadZipFile):
        service.import_package("team-a", "pkg", m.bad_crc(), "")
    assert catalog.latest("team-a", "pkg") is None


def test_truncated_archive_rejected(import_root):
    _reject(m.truncated(), import_root)


def test_not_a_zip_rejected(import_root):
    _reject(m.not_a_zip(), import_root)


def test_encrypted_flag_spoof_rejected(import_root):
    _reject(m.fake_encrypted(), import_root)


def test_limits_are_streaming_not_header_based(import_root):
    """A correct-size header that streams past the cap must trip the limit."""
    from importer.safety import MAX_FILE_SIZE

    info = zipfile.ZipInfo("x.bin")
    info.compress_type = zipfile.ZIP_STORED
    info.file_size = 10  # lie
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as bundle:
        bundle.writestr(info, b"q" * (MAX_FILE_SIZE + 64))
    with pytest.raises(ResourceLimitError):
        service.import_package("team-a", "pkg", buf.getvalue(), "")
