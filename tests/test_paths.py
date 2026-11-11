"""Path escape, link, encoding and name-conflict regression tests."""
from __future__ import annotations

import io
import os
import stat
import zipfile
from pathlib import Path

import pytest

from importer import catalog, service
from importer.safety import UnsafePackageError
from tools import make_archives as m


def _import_expect_reject(sample, import_root, sentinel):
    with pytest.raises(UnsafePackageError):
        service.import_package("team-a", "pkg", sample, "")
    # No half-visible version may remain.
    assert catalog.latest("team-a", "pkg") is None
    assert sentinel.read_text() == "untouched"
    staging = import_root / "team-a" / "pkg" / "staging"
    if staging.exists():
        assert list(staging.iterdir()) == []


def test_normal_package_keeps_chinese_nested_and_empty(import_root):
    result = service.import_package("team-a", "assets", m.normal_package(), "k1")
    assert result["state"] == "published"
    version_dir = Path(catalog.latest("team-a", "assets")["path"])
    assert (version_dir / "中文目录" / "多层" / "nested.txt").read_text(encoding="utf-8") == "中文内容"
    assert (version_dir / "assets" / "hello.txt").read_text() == "hello"
    assert (version_dir / "empty.txt").is_file()
    assert (version_dir / "empty.txt").stat().st_size == 0


def test_parent_traversal_blocked(import_root, sentinel):
    _import_expect_reject(m.parent_traversal(), import_root, sentinel)
    # Only the original sentinel may exist in the outside directory.
    assert {p.name for p in sentinel.parent.iterdir()} == {sentinel.name}


def test_deep_traversal_blocked(import_root, sentinel):
    _import_expect_reject(m.deep_traversal(), import_root, sentinel)


def test_backslash_traversal_blocked(import_root, sentinel):
    _import_expect_reject(m.backslash_traversal(), import_root, sentinel)


def test_absolute_posix_blocked(import_root, sentinel):
    _import_expect_reject(m.absolute_posix(), import_root, sentinel)


def test_windows_drive_blocked(import_root, sentinel):
    _import_expect_reject(m.windows_drive(), import_root, sentinel)


def test_windows_unc_blocked(import_root, sentinel):
    _import_expect_reject(m.windows_unc(), import_root, sentinel)


def test_windows_device_and_ads_blocked(import_root, sentinel):
    _import_expect_reject(m.windows_device(), import_root, sentinel)
    _import_expect_reject(m.windows_ads(), import_root, sentinel)


def test_nul_byte_blocked(import_root, sentinel):
    _import_expect_reject(m.nul_byte(), import_root, sentinel)


def test_trailing_dot_blocked(import_root, sentinel):
    _import_expect_reject(m.trailing_dot(), import_root, sentinel)


def test_symlink_entry_blocked(import_root, sentinel):
    _import_expect_reject(m.symlink_entry(), import_root, sentinel)


def test_duplicate_entries_blocked(import_root, sentinel):
    with pytest.warns(UserWarning):
        sample = m.duplicate_entries()
    _import_expect_reject(sample, import_root, sentinel)


def test_case_fold_collision_blocked(import_root, sentinel):
    _import_expect_reject(m.case_collision(), import_root, sentinel)


def test_unicode_normalization_collision_blocked(import_root, sentinel):
    _import_expect_reject(m.unicode_collision(), import_root, sentinel)


def test_file_directory_same_name_blocked(import_root, sentinel):
    _import_expect_reject(m.file_dir_conflict(), import_root, sentinel)


def test_preexisting_symlink_in_destination_not_followed(import_root, sentinel):
    """A link planted inside the destination cannot redirect writes outside."""
    stage = import_root / "team-a" / "pkg" / "staging" / "planted"
    stage.mkdir(parents=True)
    link = stage / "escape"
    try:
        os.symlink(str(sentinel.parent), link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation requires privilege on this Windows host")
    from importer.extract import extract_report

    data = m.archive([("escape/inside.txt", "x")])
    with pytest.raises(UnsafePackageError):
        extract_report(io.BytesIO(data), stage)
    assert sentinel.read_text() == "untouched"
    assert not (sentinel.parent / "inside.txt").exists()


def test_unix_symlink_mode_detected_via_central_header(import_root):
    data = m.symlink_entry()
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        info = bundle.infolist()[0]
        assert stat.S_ISLNK(info.external_attr >> 16)
