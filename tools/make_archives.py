"""Local malicious-ZIP sample generator.

Everything here is synthetic and written only into directories the caller
names (tests use pytest's tmp_path; the CLI defaults to fixtures/generated).
The samples never target outside hosts or real data.

Low-level ZIP construction is used on purpose: some attack shapes (symlink
entries, CRC-corrupted members, truncated archives, encryption flag spoofing)
cannot be produced through the normal high-level ``zipfile`` writer.
"""
from __future__ import annotations

import io
import struct
import sys
import zipfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from importer.safety import MAX_ENTRIES, MAX_FILE_SIZE, MAX_TOTAL_SIZE


# ---------------------------------------------------------------- benign ---
def archive(entries) -> bytes:
    """Write a normal DEFLATE archive from (name, data) pairs."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data in entries:
            bundle.writestr(name, data)
    return output.getvalue()


def normal_package() -> bytes:
    return archive(
        [
            ("assets/hello.txt", "hello"),
            ("中文目录/多层/nested.txt", "中文内容"),
            ("empty.txt", b""),
        ]
    )


# --------------------------------------------------------- path traversal ---
def parent_traversal() -> bytes:
    return archive([("../sentinel.txt", "escaped")])


def deep_traversal() -> bytes:
    return archive([("a/b/../../../../sentinel.txt", "escaped")])


def backslash_traversal() -> bytes:
    # Backslashes are ordinary bytes to the ZIP format; Windows joins them.
    return raw_zip([(b"..\\..\\sentinel.txt", b"escaped", zipfile.ZIP_STORED)])


def absolute_posix() -> bytes:
    return raw_zip([(b"/tmp/sentinel-abs.txt", b"x", zipfile.ZIP_STORED)])


def windows_drive() -> bytes:
    return raw_zip([(b"C:/Windows/Temp/sentinel.txt", b"x", zipfile.ZIP_STORED)])


def windows_unc() -> bytes:
    return raw_zip([(b"//server/share/sentinel.txt", b"x", zipfile.ZIP_STORED)])


def windows_device() -> bytes:
    return raw_zip([(b"CON", b"x", zipfile.ZIP_STORED)])


def windows_ads() -> bytes:
    return raw_zip([(b"notes.txt:hidden", b"x", zipfile.ZIP_STORED)])


def nul_byte() -> bytes:
    return raw_zip([(b"safe.txt\x00.dll", b"x", zipfile.ZIP_STORED)])


def trailing_dot() -> bytes:
    return raw_zip([(b"evil.", b"x", zipfile.ZIP_STORED)])


# ------------------------------------------------------------- link tricks ---
def symlink_entry(target: str = "../sentinel.txt") -> bytes:
    """A real ZIP entry whose Unix mode says S_IFLNK."""
    payload = target.encode()
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (0o120777 << 16)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as bundle:
        bundle.writestr(info, payload)
    return out.getvalue()


# ----------------------------------------------------------- name conflicts ---
def duplicate_entries() -> bytes:
    return archive([("same.txt", "one"), ("same.txt", "two")])


def case_collision() -> bytes:
    return archive([("Data.txt", "a"), ("data.TXT", "b")])


def unicode_collision() -> bytes:
    # U+00E5 single codepoint vs 'a' + combining ring (U+030A): same NFKC.
    return archive([("\u00e5.txt", "a"), ("a\u030a.txt", "b")])


def file_dir_conflict() -> bytes:
    return archive([("x", "i am a file"), ("x/inner.txt", "i need a dir")])


# ------------------------------------------------------------- resource DoS ---
def zip_bomb_ratio() -> bytes:
    """Tiny compressed member expanding far beyond the 100:1 ratio limit."""
    # 10 MiB of zeros compresses to ~10 KiB: ~1000:1, also over 8 MiB/file.
    return archive([("bomb.bin", b"\x00" * (10 * 1024 * 1024))])


def too_many_entries() -> bytes:
    return archive([(f"f{i:04d}.txt", b"x") for i in range(MAX_ENTRIES + 1)])


def over_total_size() -> bytes:
    # Five 7 MiB files: each under the per-file 8 MiB cap, total 35 MiB.
    return archive(
        [(f"big{i}.bin", b"a" * (7 * 1024 * 1024)) for i in range(5)]
    )


def over_file_size() -> bytes:
    return archive([("huge.bin", b"a" * (MAX_FILE_SIZE + 1024))])


def header_size_lie() -> bytes:
    """Declare a tiny header size but stream 9 MiB of real data."""
    data = b"z" * (MAX_FILE_SIZE + 1024 * 1024)
    info = zipfile.ZipInfo("lie.bin")
    info.compress_type = zipfile.ZIP_STORED
    info.file_size = 1  # deliberate lie
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as bundle:
        bundle.writestr(info, data)
    return out.getvalue()


# ------------------------------------------------------------- corruption ---
def bad_crc() -> bytes:
    """Corrupt the declared CRC-32 (central + local header) of one member."""
    good = archive([("data.txt", b"correct contents")])
    broken = bytearray(good)
    with zipfile.ZipFile(io.BytesIO(good)) as bundle:
        info = bundle.infolist()[0]
        raw_crc = struct.pack("<I", info.CRC)
        header_offset = info.header_offset
    # Patch every occurrence of the CRC field: local header at offset 14 and
    # central-directory header at offset 16. Leaving either intact would make
    # different code paths disagree about what is wrong.
    positions = []
    start = 0
    while True:
        idx = broken.find(raw_crc, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    for idx in positions:
        broken[idx] = (broken[idx] + 1) & 0xFF
    assert header_offset + 14 in positions, "local CRC field not patched"
    return bytes(broken)


def truncated() -> bytes:
    good = archive([("data.txt", b"some payload bytes here")])
    return good[: len(good) - 12]  # chop central-directory tail


def not_a_zip() -> bytes:
    return b"this is definitely not a zip file"


def fake_encrypted() -> bytes:
    """Flip the general-purpose encryption bit on an otherwise plain member."""
    good = archive([("secret.txt", b"plain")])
    broken = bytearray(good)
    # General purpose bit flag sits 6 bytes into the local file header.
    broken[6] |= 0x01
    return bytes(broken)


# ------------------------------------------------------- low-level builder ---
def raw_zip(members, *, spoof_encryption: bool = False) -> bytes:
    """Build a ZIP from raw (name_bytes, payload, compress_type) tuples.

    Names are inserted byte-for-byte, bypassing ZipFile's filename encoding
    handling, which lets the samples contain characters the safe path rejects.
    """
    out = io.BytesIO()
    central = []
    offset = 0
    for name, payload, method in members:
        if method == zipfile.ZIP_DEFLATED:
            compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
            blob = compressor.compress(payload) + compressor.flush()
        else:
            blob = payload
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        flags = 0x01 if spoof_encryption else 0
        header = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            flags,
            method,
            0,
            0,
            crc,
            len(blob),
            len(payload),
            len(name),
            0,
        )
        out.write(header)
        out.write(name)
        out.write(blob)
        central.append((name, method, crc, len(blob), len(payload), offset))
        offset += len(header) + len(name) + len(blob)

    cd_start = out.tell()
    for name, method, crc, csize, usize, off in central:
        out.write(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                0x0314,
                20,
                0,
                method,
                0,
                0,
                crc,
                csize,
                usize,
                len(name),
                0,
                0,
                0,
                0,
                0,
                off,
            )
        )
        out.write(name)
    cd_end = out.tell()
    out.write(
        struct.pack(
            "<IHHHHIIH",
            0x06054B50,
            0,
            0,
            len(central),
            len(central),
            cd_end - cd_start,
            cd_start,
            0,
        )
    )
    return out.getvalue()


SAMPLES = {
    "normal.zip": normal_package,
    "parent.zip": parent_traversal,
    "deep_traversal.zip": deep_traversal,
    "backslash.zip": backslash_traversal,
    "absolute_posix.zip": absolute_posix,
    "windows_drive.zip": windows_drive,
    "windows_unc.zip": windows_unc,
    "windows_device.zip": windows_device,
    "windows_ads.zip": windows_ads,
    "nul_byte.zip": nul_byte,
    "trailing_dot.zip": trailing_dot,
    "symlink.zip": symlink_entry,
    "duplicate.zip": duplicate_entries,
    "case_collision.zip": case_collision,
    "unicode_collision.zip": unicode_collision,
    "file_dir_conflict.zip": file_dir_conflict,
    "zip_bomb.zip": zip_bomb_ratio,
    "too_many_entries.zip": too_many_entries,
    "over_total.zip": over_total_size,
    "over_file_size.zip": over_file_size,
    "header_lie.zip": header_size_lie,
    "bad_crc.zip": bad_crc,
    "truncated.zip": truncated,
    "not_a_zip.zip": not_a_zip,
    "fake_encrypted.zip": fake_encrypted,
}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="generate local attack samples")
    parser.add_argument(
        "--out", default="fixtures/generated", help="output directory"
    )
    args = parser.parse_args()
    dest = Path(args.out)
    dest.mkdir(parents=True, exist_ok=True)
    for filename, builder in SAMPLES.items():
        (dest / filename).write_bytes(builder())
    print(dest.resolve())
