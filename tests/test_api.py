"""HTTP-level tests: tenant isolation, download containment, labels, audit."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from importer.api import app
from importer import catalog
from tools import make_archives as m

client = TestClient(app)


def _post(tenant, package, data, key="", x_tenant=None):
    headers = {"X-Tenant": x_tenant or tenant}
    url = f"/tenants/{tenant}/packages/{package}/imports"
    if key:
        url += f"?idempotency_key={key}"
    return client.post(url, content=data, headers=headers)


def test_full_api_flow_and_download(import_root):
    resp = _post("team-a", "assets", m.normal_package(), "k1")
    assert resp.status_code == 201
    body = resp.json()
    version = body["version"]

    meta = client.get(
        "/tenants/team-a/packages/assets", headers={"X-Tenant": "team-a"}
    )
    assert meta.status_code == 200 and meta.json()["id"] == version

    dl = client.get(
        "/tenants/team-a/packages/assets/files/assets/hello.txt",
        headers={"X-Tenant": "team-a"},
    )
    assert dl.status_code == 200 and dl.text == "hello"

    dl_cn = client.get(
        "/tenants/team-a/packages/assets/files/中文目录/多层/nested.txt",
        headers={"X-Tenant": "team-a"},
    )
    assert dl_cn.status_code == 200 and dl_cn.text == "中文内容"


def test_tenant_header_mismatch_forbidden(import_root):
    resp = _post("team-a", "assets", m.normal_package(), x_tenant="team-b")
    assert resp.status_code == 403


def test_cross_tenant_read_isolated(import_root):
    _post("team-a", "assets", m.normal_package(), "k1")
    resp = client.get(
        "/tenants/team-a/packages/assets", headers={"X-Tenant": "team-b"}
    )
    assert resp.status_code == 403
    resp = client.get(
        "/tenants/team-b/packages/assets", headers={"X-Tenant": "team-b"}
    )
    assert resp.status_code == 404


def test_download_traversal_param_blocked(import_root):
    _post("team-a", "assets", m.normal_package(), "k1")
    for evil in ("../../../../etc/passwd", "..\\..\\windows", "C:/x",
                 "/absolute", "CON", "a/../b"):
        resp = client.get(
            f"/tenants/team-a/packages/assets/files/{evil}",
            headers={"X-Tenant": "team-a"},
        )
        assert resp.status_code in (400, 404), (evil, resp.status_code)


def test_attack_archive_returns_400_not_500(import_root):
    resp = _post("team-a", "assets", m.parent_traversal(), "k2")
    assert resp.status_code == 400
    assert "UnsafePackageError" in resp.text


def test_invalid_labels_rejected(import_root):
    # Labels that still match the route shape must be rejected by validation.
    for bad_tenant in ("a b", "a" * 65, "-lead", "dot."):
        resp = _post(bad_tenant, "pkg", m.normal_package(), x_tenant=bad_tenant)
        assert resp.status_code == 400, bad_tenant
    # A slash never reaches the handler because the route itself won't match.
    resp = _post("a", "../pkg", m.normal_package())
    assert resp.status_code in (400, 404)
    resp = _post("team-a", "pkg", m.normal_package(), key="bad key!")
    assert resp.status_code == 400


def test_idempotent_posts_return_one_version(import_root):
    r1 = _post("team-a", "assets", m.normal_package(), "same-key")
    r2 = _post("team-a", "assets", m.normal_package(), "same-key")
    assert r1.status_code == r2.status_code == 201
    assert r1.json()["version"] == r2.json()["version"]
    assert r2.json().get("replayed") is True


def test_audit_log_records_acceptance_and_rejection(import_root):
    _post("team-a", "assets", m.normal_package(), "k1")
    _post("team-a", "assets", m.parent_traversal(), "k2")
    lines = (import_root / "audit.log").read_text(encoding="ascii").splitlines()
    events = [json.loads(line)["event"] for line in lines]
    assert "import_published" in events
    assert "import_rejected" in events
    for line in lines:  # append-only, ASCII-safe JSON per line
        entry = json.loads(line)
        assert "ts" in entry and "event" in entry
