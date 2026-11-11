import os, sqlite3
from pathlib import Path

def root():
    p=Path(os.environ.get('IMPORT_ROOT','var/imports')); p.mkdir(parents=True,exist_ok=True); return p
def connect():
    db=sqlite3.connect(root()/'catalog.db',timeout=10); db.row_factory=sqlite3.Row
    db.executescript("""
    CREATE TABLE IF NOT EXISTS versions(id TEXT PRIMARY KEY,tenant TEXT,package TEXT,path TEXT,idempotency_key TEXT);
    CREATE TABLE IF NOT EXISTS current(tenant TEXT,package TEXT,version TEXT,PRIMARY KEY(tenant,package));
    """)
    return db
def publish(tenant,package,ident,path,key):
    with connect() as db:
        db.execute('INSERT INTO versions VALUES(?,?,?,?,?)',(ident,tenant,package,str(path),key))
        db.execute('INSERT OR REPLACE INTO current VALUES(?,?,?)',(tenant,package,ident))
def latest(tenant,package):
    with connect() as db:
        row=db.execute('SELECT v.* FROM versions v JOIN current c ON c.version=v.id WHERE c.tenant=? AND c.package=?',(tenant,package)).fetchone()
        return dict(row) if row else None
