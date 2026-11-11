"""Safe streaming ZIP extraction.

Security properties:
* Every member name is validated before any filesystem operation; unsupported
  forms are rejected with a reason, never rewritten and silently accepted.
* Writes only land inside the destination, and never through a symlink.
* Entry count, per-file size, total size and compression ratio are enforced
  while reading the actual data stream -- ZIP header size fields are not
  trusted.  A CRC error, truncated archive or limit violation aborts the whole
  import; the caller owns and removes the staging directory on failure.
"""
from __future__ import annotations

import os
import stat
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .safety import (
    MAX_COMPRESSION_RATIO,
    MAX_ENTRIES,
    MAX_FILE_SIZE,
    MAX_TOTAL_SIZE,
    READ_CHUNK,
    ResourceLimitError,
    UnsafePackageError,
    collision_key,
    safe_join,
    validate_member_name,
)

_MODE_PERM_MASK = 0o777


@dataclass
class ExtractionReport:
    names: list[str] = field(default_factory=list)
    total_uncompressed: int = 0
    entries: int = 0


def _entry_kind(entry: zipfile.ZipInfo) -> str:
    mode = entry.external_attr >> 16
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode) or entry.is_dir():
        return "dir"
    if mode == 0 or stat.S_ISREG(mode):
        return "file"
    if mode & 0o170000 == 0:
        # DOS-origin entries (create_system=0) and plain writestr data carry
        # permission bits but no POSIX type field: treat as a regular file.
        return "file"
    return "special"  # fifo, socket, device, ...


def _read_local_header(
    bundle: zipfile.ZipFile, entry: zipfile.ZipInfo
) -> tuple[int, bytes]:
    """Return (general-purpose flags, raw filename bytes) of the local header."""
    try:
        bundle.fp.seek(entry.header_offset)
        header = bundle.fp.read(30)
        if len(header) < 30 or header[:4] != b"PK\x03\x04":
            raise UnsafePackageError(
                f"bad local file header for entry {entry.filename!r}"
            )
        _, _, flags, _, _, _, _, _, _, name_len, extra_len = struct.unpack(
            "<IHHHHHIIIHH", header
        )
        raw_name = bundle.fp.read(name_len)
        return flags, raw_name
    except UnsafePackageError:
        raise
    except (OSError, struct.error) as exc:
        raise UnsafePackageError(
            f"unreadable local file header for {entry.filename!r}"
        ) from exc


def extract(archive, destination) -> list[str]:
    """Backward-compatible wrapper used by the original happy-path callers."""
    return extract_report(archive, destination).names


def extract_report(archive, destination) -> ExtractionReport:
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    # A staging directory must be empty: otherwise a planted symlink or leftover
    # file could interact with the new extraction.
    if any(destination.iterdir()):
        raise UnsafePackageError("staging directory is not empty")

    report = ExtractionReport()
    seen_names: set[str] = set()
    seen_collisions: set[str] = set()
    # Track which paths are known directories (explicit entries plus parents)
    # so 'a' followed by 'a/b' cannot silently turn a file into a directory.
    known_dirs: set[str] = set()
    known_files: set[str] = set()

    try:
        bundle = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise UnsafePackageError(f"not a valid ZIP archive: {exc}") from exc

    with bundle:
        infos = bundle.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ResourceLimitError(
                f"too many entries: {len(infos)} > {MAX_ENTRIES}"
            )

        for entry in infos:
            report.entries += 1

            # Read flags and the raw filename bytes from the local file header,
            # which governs the data stream. The central-directory values on the
            # ZipInfo can disagree with them in a hand-crafted archive.
            local_flags, raw_name = _read_local_header(bundle, entry)

            # The general-purpose bit in the *local file header* is what
            # applies to the data stream; flag_bits may come from the central
            # directory instead, so check both against spoofed archives.
            if entry.flag_bits & 0x1 or local_flags & 0x1:
                # Encrypted entries are never supported; reject rather than
                # prompt for a password or skip.
                raise UnsafePackageError(
                    f"encrypted entry is not supported: {entry.filename!r}"
                )

            # ZipFile silently truncates filenames at a NUL byte and decodes
            # raw bytes itself; inspect the on-disk bytes so a hidden suffix
            # (e.g. "safe.txt\x00.dll") cannot slip through.
            if b"\x00" in raw_name:
                raise UnsafePackageError("NUL byte in raw entry name")
            flag_utf8 = bool(local_flags & 0x800)
            try:
                if flag_utf8:
                    expected_raw = entry.filename.encode("utf-8", "strict")
                else:
                    # Without the UTF-8 flag the name is CP437 by spec; reject
                    # ambiguous non-ASCII bytes instead of guessing an encoding.
                    if any(b >= 0x80 for b in raw_name):
                        raise UnsafePackageError(
                            "non-ASCII entry name without UTF-8 flag is ambiguous"
                        )
                    expected_raw = entry.filename.encode("cp437", "strict")
                if entry.is_dir() and not expected_raw.endswith(b"/"):
                    expected_raw += b"/"
                if expected_raw != raw_name:
                    raise UnsafePackageError(
                        "entry name was rewritten by ZIP decoding; refusing"
                    )
            except UnicodeEncodeError as exc:
                raise UnsafePackageError(
                    "entry name cannot round-trip its declared encoding"
                ) from exc

            kind = _entry_kind(entry)
            if kind == "symlink":
                raise UnsafePackageError(
                    f"symlink entries are not supported: {entry.filename!r}"
                )
            if kind == "special":
                raise UnsafePackageError(
                    f"non-regular entry type is not supported: {entry.filename!r}"
                )

            normalized = validate_member_name(entry.filename)
            if normalized in seen_names:
                raise UnsafePackageError(f"duplicate entry name: {normalized}")
            key = collision_key(normalized)
            if key in seen_collisions:
                raise UnsafePackageError(
                    f"entry name collides after case/Unicode folding: {normalized}"
                )

            parts = normalized.split("/")
            # File/directory same-name conflicts against earlier entries.
            if kind != "dir":
                for ancestor in ("/".join(parts[:i]) for i in range(1, len(parts))):
                    if ancestor in known_files:
                        raise UnsafePackageError(
                            f"directory/file conflict at {ancestor}"
                        )
            else:
                if normalized in known_files:
                    raise UnsafePackageError(
                        f"directory entry conflicts with existing file: {normalized}"
                    )
            if kind != "dir" and normalized in known_dirs:
                raise UnsafePackageError(
                    f"file entry conflicts with existing directory: {normalized}"
                )

            target = safe_join(destination, normalized)

            if kind == "dir":
                target.mkdir(parents=True, exist_ok=False)
                seen_names.add(normalized)
                seen_collisions.add(key)
                known_dirs.add(normalized)
                report.names.append(entry.filename)
                continue

            # Implicit parents: create each missing component as a plain dir.
            parent_rel = ""
            for part in parts[:-1]:
                parent_rel = part if not parent_rel else f"{parent_rel}/{part}"
                if parent_rel in known_files:
                    raise UnsafePackageError(
                        f"directory/file conflict at {parent_rel}"
                    )
                if parent_rel not in known_dirs:
                    safe_join(destination, parent_rel).mkdir(
                        parents=True, exist_ok=True
                    )
                    known_dirs.add(parent_rel)

            # Header-declared sizes are advisory; stream the real bytes instead.
            # ZipExtFile.tell() reports *uncompressed* position, so the ratio is
            # measured through the underlying file handle, which advances with
            # the compressed bytes actually pulled from the archive.
            stream = bundle.open(entry)
            fp_start = bundle.fp.tell()
            file_size = 0
            # Exclusive create: refuse to overwrite or follow anything that
            # already exists at this path.
            with stream, target.open("xb") as out:
                while True:
                    try:
                        chunk = stream.read(READ_CHUNK)
                    except zipfile.BadZipFile:
                        # CRC mismatch or truncated member: whole import fails.
                        raise
                    if not chunk:
                        break
                    file_size += len(chunk)
                    report.total_uncompressed += len(chunk)
                    if file_size > MAX_FILE_SIZE:
                        raise ResourceLimitError(
                            f"file {normalized} exceeds {MAX_FILE_SIZE} bytes"
                        )
                    if report.total_uncompressed > MAX_TOTAL_SIZE:
                        raise ResourceLimitError(
                            f"archive total exceeds {MAX_TOTAL_SIZE} bytes"
                        )
                    out.write(chunk)
                    compressed_consumed = bundle.fp.tell() - fp_start
                    # Skip the first window while the decompressor is buffering;
                    # a real zip bomb crosses 4 KiB of compressed data at once.
                    if (
                        compressed_consumed >= 4096
                        and file_size
                        > compressed_consumed * MAX_COMPRESSION_RATIO
                    ):
                        raise ResourceLimitError(
                            f"compression ratio above {MAX_COMPRESSION_RATIO} "
                            f"for {normalized}"
                        )
            # Reading to EOF makes zipfile verify CRC-32 and detect truncation;
            # either failure raises BadZipFile before the entry is registered.
            compressed_consumed = bundle.fp.tell() - fp_start
            if (
                compressed_consumed > 0
                and file_size > compressed_consumed * MAX_COMPRESSION_RATIO
            ):
                raise ResourceLimitError(
                    f"compression ratio above {MAX_COMPRESSION_RATIO} "
                    f"for {normalized}"
                )

            mode = (entry.external_attr >> 16) & _MODE_PERM_MASK
            if mode:
                try:
                    os.chmod(target, mode)
                except OSError:
                    # Non-POSIX permission bits are harmless on Windows; ignore.
                    pass

            seen_names.add(normalized)
            seen_collisions.add(key)
            known_files.add(normalized)
            report.names.append(entry.filename)

    return report
