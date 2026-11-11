"""Worker for cross-process concurrency and crash-recovery tests.

Runs one import in a fresh process so failpoint-triggered ``os._exit`` only
kills the worker, never the pytest process.
"""
from __future__ import annotations

import json
import os
import sys


def main() -> int:
    payload_path = sys.argv[1]
    env = json.loads(sys.argv[2])
    for key, value in env.items():
        os.environ[key] = value
    sys.path.insert(0, os.environ["PYTHONPATH"])

    from importer import service  # noqa: E402

    data = open(payload_path, "rb").read()
    try:
        result = service.import_package(
            sys.argv[3], sys.argv[4], data, sys.argv[5]
        )
        print(json.dumps({"ok": True, "result": result}))
        return 0
    except BaseException as exc:  # include SystemExit from os._exit handling
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
