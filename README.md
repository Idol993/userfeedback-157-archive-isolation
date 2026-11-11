# Tenant Package Import

Local ZIP import and file serving service, Python 3.12+ and SQLite.

```text
python -m pip install -r requirements.txt
python tools/make_archives.py
python -m uvicorn importer.api:app --host 127.0.0.1 --port 8257
python -m pytest -q
```

POST raw ZIP bytes with `Content-Type: application/zip` to `/tenants/{tenant}/packages/{package}/imports?idempotency_key=...`.
Pass `X-Tenant` on all requests. In this local model the header represents an identity supplied by a trusted authenticating proxy; implementing real login is outside this service.
GET `/tenants/{tenant}/packages/{package}` returns current metadata.
GET `/tenants/{tenant}/packages/{package}/files/{filename}` downloads from the current version.
`IMPORT_ROOT` controls both metadata and files; default is `var/imports`.
`IMPORT_FAILPOINT=after_publish|after_commit` terminates the importing process at the named boundary.

The baseline only has a happy-path test, unbounded ZIP reading and a shared staging directory.
Use private temporary directories for crafted fixtures and sentinel checks. Do not run attack samples against outside paths or services.
