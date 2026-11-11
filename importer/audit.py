"""Append-only security audit log.

One JSON object per line under ``$IMPORT_ROOT/audit.log``.  Audit failures must
never break an otherwise successful import, so write errors fall back to
stderr.  Only event metadata and rejection reasons are recorded -- archive
payloads and raw member contents are never copied into the log.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from . import catalog


def _ascii_safe(value) -> str:
    text = str(value)
    return text.encode("ascii", "backslashreplace").decode("ascii")


def record(event: str, **fields) -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        **{k: _ascii_safe(v) for k, v in fields.items()},
    }
    line = json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n"
    try:
        path = Path(catalog.root()) / "audit.log"
        with path.open("a", encoding="ascii") as handle:
            handle.write(line)
    except Exception:  # pragma: no cover - best-effort fallback
        sys.stderr.write("audit-write-failed: " + line)
