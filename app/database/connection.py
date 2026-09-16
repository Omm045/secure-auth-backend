"""Database connections and the stable transaction interface."""
import sqlite3
from contextlib import contextmanager

from app.config import settings


def db_path() -> str:
    url = settings.database_url
    return url.removeprefix("sqlite:///") if url.startswith("sqlite:///") else ":memory:"


def connect():
    if settings.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        import psycopg
        from psycopg.rows import dict_row
        url = settings.database_url.replace("postgresql+psycopg://", "postgresql://", 1)
        return _PostgresConnection(psycopg.connect(url, row_factory=dict_row))
    connection = sqlite3.connect(db_path(), timeout=10, isolation_level="DEFERRED")
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


class _PostgresConnection:
    def __init__(self, connection):
        self._connection = connection

    def execute(self, query, params=()):
        return self._connection.execute(query.replace("?", "%s"), params)

    def executemany(self, query, params):
        return self._connection.executemany(query.replace("?", "%s"), params)

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


def init_db() -> None:
    from alembic import command
    from alembic.config import Config
    migration_config = Config("alembic.ini")
    command.upgrade(migration_config, "head")
    with connect() as connection:
        if not settings.database_url.startswith("sqlite://"):
            if settings.admin_emails:
                connection.executemany(
                    "UPDATE users SET role='admin' WHERE lower(email)=lower(?)",
                    [(email,) for email in settings.admin_emails],
                )
            connection.commit()
            return
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
