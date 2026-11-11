"""HTTP layer. Tenant identity comes from a trusted proxy's X-Tenant header."""
from __future__ import annotations

from pathlib import Path
import zipfile

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse

from . import catalog, service
from .safety import (
    InconsistentStateError,
    InvalidLabelError,
    UnsafePackageError,
    ensure_within,
    validate_idempotency_key,
    validate_label,
    validate_member_name,
)

# Archive-level failures that make an import invalid rather than a server bug.
_CLIENT_ERRORS = (UnsafePackageError, InvalidLabelError, zipfile.BadZipFile)

app = FastAPI(title="Tenant Package Import")


def _check_tenant(tenant: str, x_tenant: str) -> None:
    # Validate both strings before comparing so malformed labels cannot reach
    # the filesystem layer even when the proxy is misconfigured.
    try:
        validate_label(tenant, "tenant")
        validate_label(x_tenant, "X-Tenant")
    except InvalidLabelError as exc:
        raise HTTPException(400, f"InvalidLabelError: {exc}")
    if x_tenant != tenant:
        raise HTTPException(403, "tenant mismatch")


@app.post(
    "/tenants/{tenant}/packages/{package}/imports", status_code=201
)
async def upload(
    tenant: str,
    package: str,
    request: Request,
    idempotency_key: str = "",
    x_tenant: str = Header(...),
):
    _check_tenant(tenant, x_tenant)
    try:
        validate_label(package, "package")
        validate_idempotency_key(idempotency_key)
        return service.import_package(
            tenant, package, await request.body(), idempotency_key
        )
    except _CLIENT_ERRORS as exc:
        raise HTTPException(400, f"{exc.__class__.__name__}: {exc}")
    except InconsistentStateError as exc:
        raise HTTPException(500, str(exc))


@app.get("/tenants/{tenant}/packages/{package}")
def get_package(tenant: str, package: str, x_tenant: str = Header(...)):
    try:
        _check_tenant(tenant, x_tenant)
        validate_label(package, "package")
    except InvalidLabelError as exc:
        raise HTTPException(400, f"InvalidLabelError: {exc}")
    row = catalog.latest(tenant, package)
    if not row:
        raise HTTPException(404, "package not found")
    return row


@app.get("/tenants/{tenant}/packages/{package}/files/{filename:path}")
def download(
    tenant: str, package: str, filename: str, x_tenant: str = Header(...)
):
    try:
        _check_tenant(tenant, x_tenant)
        validate_label(package, "package")
    except InvalidLabelError as exc:
        raise HTTPException(400, f"InvalidLabelError: {exc}")
    row = catalog.latest(tenant, package)
    if not row:
        raise HTTPException(404, "package not found")
    try:
        # Same strict rules as extraction: no traversal, backslash, drive,
        # device names or symlinks; the final resolved path must stay inside
        # the published immutable version directory.
        validate_member_name(filename)
        path = ensure_within(Path(row["path"]), filename)
    except UnsafePackageError as exc:
        raise HTTPException(400, f"invalid file path: {exc}")
    if not path.is_file():
        raise HTTPException(404, "file not found")
    return FileResponse(str(path))
