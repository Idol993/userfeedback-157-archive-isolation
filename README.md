# Tenant Package Import — Hardened

Local ZIP import and file-serving service (Python 3.12+, FastAPI, SQLite) with
a security-hardened extraction and publishing pipeline. All attack samples are
synthetic and are only generated inside this project's own temporary
directories and exercised against the local test service.

## Quick start

```text
python -m pip install -r requirements.txt
python tools/make_archives.py --out fixtures/generated   # 23 local samples
python -m pytest -q                                      # full regression suite
python -m uvicorn importer.api:app --host 127.0.0.1 --port 8257
```

POST raw ZIP bytes (`Content-Type: application/zip`) to
`/tenants/{tenant}/packages/{package}/imports?idempotency_key=...`.
Send `X-Tenant` on every request; in this local model the header represents an
identity supplied by a trusted authenticating proxy. Real authentication is
outside this service's boundary.

* `GET /tenants/{tenant}/packages/{package}` — current version metadata
* `GET /tenants/{tenant}/packages/{package}/files/{filename}` — download from
  the current immutable version
* `IMPORT_ROOT` — metadata DB, files, staging and audit log (default
  `var/imports`)
* `IMPORT_STALE_SECONDS` — orphan GC age threshold (default 3600; tests use 0)
* `IMPORT_FAILPOINT=after_publish|after_commit` — `os._exit(77)` at the named
  crash boundary, for recovery drills

## Threat model and trust boundaries

**In scope.** A tenant authenticated by the upstream proxy can upload an
arbitrary ZIP and may try to (a) write files outside its extraction directory,
(b) exhaust CPU/disk via compression or entry counts, (c) confuse name
handling across platforms, (d) race a concurrent import of the same package,
and (e) read another tenant's files through the download endpoint.

**Explicitly out of scope.** Authenticating the `X-Tenant` header (the proxy
is trusted), denial of service from the raw HTTP body size itself (put a body
limit at the proxy), malicious SQLite file replacement, and OS-level attacks
against the host. Audit logs record events and reasons but do not contain
archive payloads.

## Extraction defenses (`importer/extract.py`, `importer/safety.py`)

Every member is validated **before any filesystem operation**, and the final
*resolved* path meaning is checked rather than the raw string. Unsupported
forms are rejected with a recorded reason — names are never sanitized and
silently accepted.

* **Path traversal** — `.`/`..` segments, absolute POSIX paths, Windows drive
  letters (`C:`), UNC (`//server/share`), backslashes, reserved device names
  (`CON`, `COM1`, `LPT1` …), NTFS ADS (`file:stream`), trailing dots/spaces,
  control characters, NUL bytes, forbidden characters (`<>:"|?*`).
* **Final-word containment** — `safe_join` resolves each candidate with
  `Path.resolve()` and asserts it stays under the staging root, and refuses to
  traverse any component that is a symlink (this also covers a link already
  present in the destination before extraction).
* **ZIP-level symlinks and special files** — entries whose Unix mode is
  `S_IFLNK`, FIFO/socket/device are rejected outright.
* **Encoding tricks** — the raw filename bytes are read straight from the
  local file header (bypassing `ZipFile`'s NUL truncation/decoding), required
  to round-trip the declared encoding; non-ASCII names without the UTF-8 flag
  are rejected as ambiguous.
* **Name conflicts** — duplicate names, case-fold collisions and NFKC Unicode
  normalization collisions, and file/directory same-name conflicts (including
  implicit parent directories).
* **Streaming resource limits** — enforced on the bytes actually read, never
  trusted from ZIP headers: max 2000 entries, 8 MiB per file, 32 MiB total,
  compression ratio ≤ 100 (measured against compressed bytes consumed via the
  underlying file pointer). CRC-32 and truncation are verified by reading each
  member to EOF; any failure aborts the whole import and the per-request
  staging tree is removed, so no half version is ever visible.
* Files are created with exclusive mode (`xb`) and directories with
  `exist_ok=False`; benign Chinese directory names, nested trees and empty
  files remain fully supported.

## Publishing, concurrency and crash recovery (`importer/service.py`)

```text
$IMPORT_ROOT/<tenant>/<package>/staging/<uuid>     per-request scratch
$IMPORT_ROOT/<tenant>/<package>/versions/<uuid>    immutable published versions
$IMPORT_ROOT/catalog.db                            versions + current pointer
$IMPORT_ROOT/audit.log                             append-only JSONL audit trail
```

* Each request gets its own UUID staging directory, so concurrent imports never
  share or delete each other's files.
* Extraction is validated first; the tree is then atomically `os.replace`d into
  `versions/`, and only afterward is a single `BEGIN IMMEDIATE` SQLite
  transaction inserting the version and flipping the `current` pointer
  committed. A partial unique index enforces one version per
  `(tenant, package, idempotency_key)`.
* **Crash window 1 — files published, DB not committed
  (`after_publish`):** the version directory has no catalog row and no
  `current` pointer, so it is invisible. `reap_orphans` (run before each
  import) removes un-catalogued version directories older than a 30-second
  commit grace window (`VERSION_GRACE_SECONDS`, which `IMPORT_STALE_SECONDS`
  cannot undercut) and staging directories older than the stale threshold;
  a retried request with the same key then publishes cleanly. The grace
  window ensures a concurrent reaper can never delete another request's tree
  during its rename-to-commit interval.
* **Crash window 2 — DB committed, response not sent (`after_commit`):** the
  retry with the same `idempotency_key` finds the committed row and returns the
  stored manifest (flagged `replayed: true`) instead of creating a second
  version. If the committed files are missing on disk, the service raises
  `InconsistentStateError` (HTTP 500) and leaves the catalog row for
  forensics rather than pretending the version exists.
* Two processes importing the same tenant/package with the **same** key
  serialize on the SQLite write transaction; the loser deletes only its own
  tree and replays the winner's result. With **different** keys both versions
  survive and both file trees remain intact; last committer becomes current.
* Failed imports roll back only their own staging/published directories and
  emit an `import_rejected` audit record; orphan reclamation emits
  `orphan_reaped`.

## Tenant isolation and input contracts

* Tenant id and package name must match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
  (validated both in the URL path and against `X-Tenant`, before any
  filesystem use); idempotency keys match `[A-Za-z0-9._:-]{1,128}`.
* Downloads apply the same structural name rules as extraction and resolve the
  final path inside the current immutable version directory, so
  `..`, backslashes, drive names and symlinks cannot escape the tenant's
  published tree. A header/path tenant mismatch returns 403; an unknown
  package returns 404.

## Platform differences

* All Windows-specific rules (backslash, drive, UNC, device names, ADS,
  trailing dots/spaces) are enforced on every OS, because an archive accepted
  on POSIX may later be served to a Windows client.
* Symlink creation in tests is skipped where the Windows host denies the
  privilege; ZIP-declared symlink entries are rejected regardless of host.
* `os.chmod` on archive-provided permission bits is best-effort and ignored on
  Windows; SQLite uses WAL plus a 30 s busy timeout for cross-process locking.
* Filenames are stored as UTF-8; CP437-only non-ASCII ZIP names are rejected.

## Reproducing the attacks

```text
python tools/make_archives.py --out fixtures/generated
python -m pytest -q
```

The generator (`tools/make_archives.py`) builds 23 samples including traversal
variants, a real S_IFLNK entry, case/Unicode collisions, a 1000:1 zip bomb, a
header-size lie, a CRC-corrupted member, a truncated archive and an
encryption-flag spoof (several use a hand-rolled local/central header writer
because the high-level API cannot express them). `tests/` covers path bypass,
links, conflicts, resource caps, corruption, cross-tenant reads, cross-process
concurrency (real subprocesses via `tools/worker.py`) and both crash windows.
Sentinel files live outside `IMPORT_ROOT` and are asserted unchanged after
every rejection test.

## Residual risks

1. **HTTP body size is unbounded at this layer** — a proxy/ingress limit is
   required; streaming limits only bound what gets extracted.
2. **Same-key semantic change** — idempotency keys guarantee one version per
   key, but a retry with a *different* payload and the same key receives the
   original result by design (standard idempotency semantics).
3. **Filename entropy, not encryption** — version UUIDs are unguessable but
   access control still depends entirely on the trusted `X-Tenant` proxy.
4. **GC timing** — orphans younger than `IMPORT_STALE_SECONDS` remain on disk
   until the next eligible import or an explicit `reap_orphans` call; they are
   never served.
5. **Audit log is best-effort** — if `IMPORT_ROOT` is unwritable the event is
   redirected to stderr; the import itself does not fail on audit I/O errors.
6. **Single-host storage** — the atomic-rename/SQLite guarantees assume one
   shared filesystem; multi-host deployments need an object store and a
   coordinating database.
