"""Small SQLite persistence layer.

The schema is deliberately created with explicit columns and indexed lookup
fields.  ``user_version`` provides a lightweight migration boundary until a
full Alembic deployment is introduced.
"""
import sqlite3
from contextlib import contextmanager

from app.config import settings


def db_path() -> str:
    url = settings.database_url
    return url.removeprefix("sqlite:///") if url.startswith("sqlite:///") else ":memory:"


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(db_path(), timeout=10, isolation_level="DEFERRED")
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    with connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT,
                disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
                role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin'))
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
            );
            CREATE TABLE IF NOT EXISTS password_resets (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                event TEXT NOT NULL,
                ip TEXT,
                metadata TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_token_active
                ON sessions(token_hash, revoked, expires_at);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_resets_token_active
                ON password_resets(token_hash, used, expires_at);
            CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_event_time ON audit_logs(event, created_at);
            PRAGMA user_version = 1;
            """
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
        if "role" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        audit_columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_logs)")}
        if "metadata" not in audit_columns:
            connection.execute("ALTER TABLE audit_logs ADD COLUMN metadata TEXT")
        # ADMIN_EMAILS is bootstrap provisioning only; authorization checks role.
        if settings.admin_emails:
            connection.executemany(
                "UPDATE users SET role='admin' WHERE lower(email)=lower(?)",
                [(email,) for email in settings.admin_emails],
            )
        connection.execute(
            "DELETE FROM password_resets WHERE used=1 OR expires_at<=datetime('now')"
        )


@contextmanager
def transaction():
    connection = connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
