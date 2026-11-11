"""Shared security primitives: name validation, path containment, error types.

All rules here are enforced on *every* platform, even when a rule only exists
because of Windows path semantics: an archive extracted on one host may later
be served to a client on another, so accepting Windows-dangerous names on POSIX
would just move the vulnerability across the deployment.
"""
from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path

# --- Resource limits (enforced while streaming, never trusted from headers) ---
MAX_ENTRIES = 2000
MAX_FILE_SIZE = 8 * 1024 * 1024          # 8 MiB per extracted file
MAX_TOTAL_SIZE = 32 * 1024 * 1024        # 32 MiB per archive
MAX_COMPRESSION_RATIO = 100              # uncompressed / compressed
READ_CHUNK = 64 * 1024

MAX_NAME_LENGTH = 240
MAX_COMPONENT_LENGTH = 128
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")

_FORBIDDEN_CHARS = set('<>:"|?*')
_RESERVED_WINDOWS = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class UnsafePackageError(ValueError):
    """The archive violates a security rule; the whole import must fail."""


class ResourceLimitError(UnsafePackageError):
    """A streaming resource limit was exceeded."""


class InvalidLabelError(ValueError):
    """A tenant id, package name or idempotency key is outside its contract."""


class InconsistentStateError(RuntimeError):
    """Published metadata and on-disk files disagree; needs operator action."""


def validate_label(value: str, what: str) -> str:
    """Validate a tenant id / package name used both in URLs and on disk."""
    if not isinstance(value, str) or not LABEL_RE.fullmatch(value):
        raise InvalidLabelError(
            f"{what} must be 1-64 chars of [A-Za-z0-9._-] starting with a "
            f"letter or digit"
        )
    if value.endswith((".", "-", "_")) or ".." in value:
        raise InvalidLabelError(f"{what} has an unsupported trailing/double mark")
    return value


def validate_idempotency_key(key: str) -> str:
    if key == "":
        return key
    if not isinstance(key, str) or not IDEMPOTENCY_RE.fullmatch(key):
        raise InvalidLabelError(
            "idempotency_key must be 1-128 chars of [A-Za-z0-9._:-]"
        )
    return key


def _check_structural(name: str) -> list[str]:
    """Structural validation of a ZIP member name. Returns its path parts."""
    if not name:
        raise UnsafePackageError("empty entry name")
    if "\x00" in name:
        raise UnsafePackageError("NUL byte in entry name")
    if "\\" in name:
        # ZIP's separator is '/'. A backslash is either a traversal attempt
        # against Windows or an illegal/incompatible filename; reject instead
        # of silently keeping a weird character.
        raise UnsafePackageError("backslash is not allowed in entry names")
    if any(ord(c) < 0x20 for c in name):
        raise UnsafePackageError("control character in entry name")
    if any(c in _FORBIDDEN_CHARS for c in name):
        raise UnsafePackageError("forbidden Windows character in entry name")
    if name.startswith("/"):
        raise UnsafePackageError("absolute path entry is not allowed")
    if re.match(r"^[A-Za-z]:", name):
        raise UnsafePackageError("Windows drive letter in entry name")
    if name.startswith("//"):
        raise UnsafePackageError("UNC path entry is not allowed")
    if len(name) > MAX_NAME_LENGTH:
        raise UnsafePackageError("entry name too long")

    trailing_slash = name.endswith("/")
    body = name[:-1] if trailing_slash else name
    parts = body.split("/")
    if any(part == "" for part in parts):
        raise UnsafePackageError("empty path component in entry name")
    for part in parts:
        if part in (".", ".."):
            raise UnsafePackageError("relative traversal segment in entry name")
        if len(part) > MAX_COMPONENT_LENGTH:
            raise UnsafePackageError("path component too long")
        # NTFS silently strips trailing dots/spaces, which enables confusion
        # attacks; ADS ('a:b') is already caught by the forbidden-char set.
        if part.rstrip(" .") != part:
            raise UnsafePackageError("trailing dot/space is not allowed")
        stem = part.split(".", 1)[0].upper()
        if stem in _RESERVED_WINDOWS:
            raise UnsafePackageError(f"reserved Windows device name: {part}")
    return parts


def _validated_parts(name: str) -> list[str]:
    """Structural rules plus an NFKC re-check of the compatibility-normalized
    form, so full-width lookalikes (e.g. '．．/x' -> '../x') cannot bypass a
    path primitive that is reached without going through validate_member_name.
    """
    parts = _check_structural(name)
    normalized = unicodedata.normalize("NFKC", name)
    if normalized != name:
        _check_structural(normalized)
    return parts


def validate_member_name(name: str) -> str:
    """Validate one ZIP member name and return its normalized POSIX form."""
    if not isinstance(name, str):
        raise UnsafePackageError("non-string entry name")
    parts = _validated_parts(name)
    return "/".join(parts)


def collision_key(name: str) -> str:
    """Key used to detect case-fold / Unicode-normalization collisions."""
    return unicodedata.normalize("NFKC", name).casefold()


def safe_join(destination: Path, relative: str) -> Path:
    """Resolve *relative* under *destination*, refusing symlink escapes.

    The destination of an import is a freshly created empty staging directory,
    so under normal operation no symlinks exist; the checks nevertheless make
    a pre-existing planted link (or a link an earlier entry tried to create)
    unable to redirect writes outside the destination.
    """
    base = Path(destination).resolve(strict=False)
    parts = _validated_parts(relative)
    candidate = base.joinpath(*parts)
    walked = base
    for part in parts:
        walked = walked / part
        if walked.is_symlink():
            raise UnsafePackageError(
                f"refusing to traverse symlink inside staging tree: {relative}"
            )
    try:
        resolved = walked.resolve(strict=False)
        resolved.relative_to(base)
    except (ValueError, OSError) as exc:
        raise UnsafePackageError(
            f"entry resolves outside the extraction directory: {relative}"
        ) from exc
    return candidate


def ensure_within(base: os.PathLike | str, relative: str) -> Path:
    """Final-word containment check used by the download path as well."""
    base_res = Path(base).resolve(strict=False)
    parts = _validated_parts(relative)
    walked = base_res.joinpath(*parts)
    probe = base_res
    for part in parts:
        probe = probe / part
        if probe.is_symlink():
            raise UnsafePackageError("refusing to follow a symlink")
    try:
        resolved = walked.resolve(strict=False)
        resolved.relative_to(base_res)
    except (ValueError, OSError) as exc:
        raise UnsafePackageError("path escapes its allowed directory") from exc
    return walked
