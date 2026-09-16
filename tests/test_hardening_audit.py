import pytest
from fastapi.testclient import TestClient

from app.config import Settings, settings
from app.database.connection import transaction
from app.main import app
from app.security.rate_limit import _hits


class NoBreach:
    def is_breached(self, password: str) -> bool:
        return False


def test_production_requires_bootstrap_admin_and_redis():
    with pytest.raises(ValueError):
        Settings(
            environment="production",
            secret_key="x" * 40,
            session_cookie_secure=True,
            cors_origins=["https://example.test"],
            redis_url="rediss://localhost",
            admin_emails=[],
        )


def test_admin_uses_role_not_email(monkeypatch):
    import app.api.auth as auth

    monkeypatch.setattr(auth, "breach_checker", NoBreach())
    monkeypatch.setattr(settings, "admin_emails", ["role-test@example.com"])
    with TestClient(app) as client:
        response = client.post(
            "/auth/register",
            json={"email": "role-test@example.com", "password": "correct horse battery staple"},
        )
        assert response.status_code == 201
        client.post("/auth/login", json={"email": "role-test@example.com", "password": "correct horse battery staple"})
        with transaction() as connection:
            connection.execute(
                "UPDATE users SET role='user' WHERE email=?",
                ("role-test@example.com",),
            )
        assert client.get("/admin/stats").status_code == 403

def test_unverified_admin_cannot_access_admin(monkeypatch):
    import app.api.auth as auth
    monkeypatch.setattr(auth, "breach_checker", NoBreach())
    with TestClient(app) as client:
        client.post("/auth/register", json={
            "email": "unverified-admin@example.com",
            "password": "correct horse battery staple",
        })
        client.post("/auth/login", json={"email": "unverified-admin@example.com", "password": "correct horse battery staple"})
        with transaction() as db:
            db.execute("UPDATE users SET role='admin', email_verified=FALSE WHERE email=?",
                       ("unverified-admin@example.com",))
        assert client.get("/admin/stats").status_code == 403


def test_rate_limit_includes_retry_after(monkeypatch):
    _hits.clear()
    monkeypatch.setattr(settings, "rate_limit_per_minute", 1)
    with TestClient(app) as client:
        client.post("/auth/login", json={"email": "limited@example.com", "password": "correct horse battery staple"})
        response = client.post(
            "/auth/login", json={"email": "limited@example.com", "password": "correct horse battery staple"}
        )
        assert response.status_code == 429
        assert response.headers["retry-after"] == "60"
