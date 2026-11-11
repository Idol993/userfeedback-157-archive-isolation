"""SQLite catalog with transactional version publishing and idempotency."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from .safety import InvalidLabelError, validate_idempotency_key, validate_label


def root() -> Path:
    p = Path(os.environ.get("IMPORT_ROOT", "var/imports"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(root() / "catalog.db", timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=30000")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS versions(
            id TEXT PRIMARY KEY,
            tenant TEXT NOT NULL,
            package TEXT NOT NULL,
            path TEXT NOT NULL,
            idempotency_key TEXT NOT NULL DEFAULT '',
            manifest TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        );
        CREATE TABLE IF NOT EXISTS current(
            tenant TEXT NOT NULL,
            package TEXT NOT NULL,
            version TEXT NOT NULL,
            PRIMARY KEY(tenant, package)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_versions_idem
            ON versions(tenant, package, idempotency_key)
            WHERE idempotency_key <> '';
        """
    )
    return db


def _scoped(tenant: str, package: str) -> tuple[str, str]:
    return validate_label(tenant, "tenant"), validate_label(package, "package")


def find_idempotent(tenant: str, package: str, key: str):
    """Return the already-published row for an idempotency key, if any."""
    tenant, package = _scoped(tenant, package)
    key = validate_idempotency_key(key)
    if not key:
        return None
    with connect() as db:
        row = db.execute(
            "SELECT * FROM versions WHERE tenant=? AND package=? "
            "AND idempotency_key=?",
            (tenant, package, key),
        ).fetchone()
        return dict(row) if row else None


def version_ids(tenant: str, package: str) -> set[str]:
    tenant, package = _scoped(tenant, package)
    with connect() as db:
        rows = db.execute(
            "SELECT id FROM versions WHERE tenant=? AND package=?",
            (tenant, package),
        ).fetchall()
        return {r["id"] for r in rows}


def publish(tenant, package, ident, path, key, manifest) -> str:
    """Publish one immutable version inside a single transaction.

    Returns ``"published"`` for a new version or ``"idempotent_replay"`` when
    another concurrent request committed the same idempotency key first.
    """
    tenant, package = _scoped(tenant, package)
    key = validate_idempotency_key(key)
    db = connect()
    try:
        db.execute("BEGIN IMMEDIATE")
        if key:
            existing = db.execute(
                "SELECT id FROM versions WHERE tenant=? AND package=? "
                "AND idempotency_key=?",
                (tenant, package, key),
            ).fetchone()
            if existing:
                db.rollback()
                return existing["id"], "idempotent_replay"
        db.execute(
            "INSERT INTO versions(id,tenant,package,path,idempotency_key,manifest)"
            " VALUES(?,?,?,?,?,?)",
            (ident, tenant, package, str(path), key, manifest),
        )
        db.execute(
            "INSERT OR REPLACE INTO current(tenant,package,version) VALUES(?,?,?)",
            (tenant, package, ident),
        )
        db.commit()
        return ident, "published"
    except sqlite3.IntegrityError:
        # Unique-index race lost to a concurrent idempotent import.
        db.rollback()
        row = find_idempotent(tenant, package, key)
        if row is None:  # pragma: no cover - defensive
            raise
        return row["id"], "idempotent_replay"
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def latest(tenant, package):
    tenant, package = _scoped(tenant, package)
    with connect() as db:
        row = db.execute(
            "SELECT v.* FROM versions v JOIN current c ON c.version=v.id "
            "WHERE c.tenant=? AND c.package=?",
            (tenant, package),
        ).fetchone()
        return dict(row) if row else None
