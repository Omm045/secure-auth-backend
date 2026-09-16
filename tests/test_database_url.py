import pytest

from app.config import Settings
from app.database import connection


@pytest.mark.parametrize(
    ("database_url", "expected"),
    [
        ("postgres://user:pass@db:5432/auth", "postgresql://user:pass@db:5432/auth"),
        ("postgresql://user:pass@db:5432/auth", "postgresql://user:pass@db:5432/auth"),
        ("postgresql+psycopg://user:pass@db:5432/auth", "postgresql://user:pass@db:5432/auth"),
    ],
)
def test_postgres_urls_use_postgres_driver(monkeypatch, database_url, expected):
    captured = {}

    class FakeConnection:
        def close(self):
            pass

    def fake_connect(url, row_factory):
        captured["url"] = url
        return FakeConnection()

    monkeypatch.setattr(connection.settings, "database_url", database_url)
    monkeypatch.setattr("psycopg.connect", fake_connect)
    connection.connect()
    assert captured["url"] == expected


@pytest.mark.parametrize("database_url", ["mysql://db/auth", "postgres:/typo", ""])
def test_unknown_database_url_fails_loudly(monkeypatch, database_url):
    monkeypatch.setattr(connection.settings, "database_url", database_url)
    with pytest.raises(ValueError, match="Unsupported DATABASE_URL scheme"):
        connection.connect()


def test_production_requires_postgres_database_url():
    with pytest.raises(ValueError, match="DATABASE_URL must use postgresql"):
        Settings(
            environment="production",
            database_url="mysql://db/auth",
            secret_key="x" * 40,
            session_cookie_secure=True,
            cors_origins=["https://example.test"],
            redis_url="rediss://localhost",
            admin_emails=["admin@example.test"],
            email_provider="smtp",
            smtp_host="smtp.example.test",
            smtp_username="user",
            smtp_password="password",
            email_from="no-reply@example.test",
            app_base_url="https://auth.example.test",
        )

def test_environment_rejects_typos():
    with pytest.raises(ValueError):
        Settings(environment="productionn")
