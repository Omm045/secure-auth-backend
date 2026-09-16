"""Database connections and the stable transaction interface."""
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
    from alembic import command
    from alembic.config import Config
    migration_config = Config("alembic.ini")
    command.upgrade(migration_config, "head")
    with connect() as connection:
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
