import sqlite3
from contextlib import contextmanager
from app.config import settings

def db_path():
    url=settings.database_url
    return url.removeprefix("sqlite:///") if url.startswith("sqlite:///") else ":memory:"

def init_db():
    with sqlite3.connect(db_path()) as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT NOT NULL,last_login TEXT,disabled INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,token_hash TEXT UNIQUE NOT NULL,expires_at TEXT NOT NULL,created_at TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS password_resets(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,token_hash TEXT UNIQUE NOT NULL,expires_at TEXT NOT NULL,used INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,event TEXT NOT NULL,ip TEXT,created_at TEXT NOT NULL);''')

def connect():
    c=sqlite3.connect(db_path()); c.row_factory=sqlite3.Row; return c
@contextmanager
def transaction():
    c=connect()
    try: yield c; c.commit()
    finally: c.close()
