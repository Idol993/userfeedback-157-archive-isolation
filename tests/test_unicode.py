"""NFKC / Unicode lookalike hardening for the path primitives themselves."""
from __future__ import annotations

from pathlib import Path

import pytest

from importer.safety import (
    UnsafePackageError,
    ensure_within,
    safe_join,
    validate_member_name,
)


def test_fullwidth_traversal_rejected_by_every_primitive(tmp_path):
    # U+FF0E fullwidth full stop: NFKC maps '．．' -> '..'
    evil = "．．/x"
    with pytest.raises(UnsafePackageError):
        validate_member_name(evil)
    with pytest.raises(UnsafePackageError):
        safe_join(tmp_path, evil)
    with pytest.raises(UnsafePackageError):
        ensure_within(tmp_path, evil)


def test_fullwidth_slash_is_a_plain_single_component(tmp_path):
    # NFKC maps '／' -> '/'; the raw character itself is an ordinary filename
    # character on both POSIX and Windows, so the single component stays inside.
    name = "a／b"
    result = validate_member_name(name)
    assert "/" not in result or result == name
    joined = safe_join(tmp_path, name)
    assert str(joined.resolve()).startswith(str(tmp_path.resolve()))
    contained = ensure_within(tmp_path, name)
    assert str(contained.resolve()).startswith(str(tmp_path.resolve()))


def test_fullwidth_traversal_via_download_api(import_root):
    """The download endpoint shares the same NFKC-hardened primitives."""
    from fastapi.testclient import TestClient

    from importer.api import app
    from tools import make_archives as m

    client = TestClient(app)
    client.post(
        "/tenants/t/packages/p/imports?idempotency_key=k",
        content=m.normal_package(),
        headers={"X-Tenant": "t"},
    )
    import urllib.parse

    encoded = urllib.parse.quote("．．/etc")
    resp = client.get(
        f"/tenants/t/packages/p/files/{encoded}", headers={"X-Tenant": "t"}
    )
    assert resp.status_code in (400, 404)
