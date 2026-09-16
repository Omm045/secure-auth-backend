from fastapi.testclient import TestClient
import app.api.auth as auth
from app.config import settings
from app.main import app
from app.database.connection import transaction

class NoBreach:
    def is_breached(self, value):
        return False

def test_admin_stats(monkeypatch):
    monkeypatch.setattr(auth, "breach_checker", NoBreach())
    with TestClient(app) as client:
        client.post("/auth/register", json={"email": "admin@example.com", "password": "correct horse battery staple"})
        client.post("/auth/login", json={"email": "admin@example.com", "password": "correct horse battery staple"})
        with transaction() as db:
            db.execute("UPDATE users SET role='admin', email_verified=TRUE WHERE email=?", ("admin@example.com",))
        response = client.get("/admin/stats")
        assert response.status_code == 200
        assert "password_breaches" in response.json()

def test_admin_email_cannot_self_provision(monkeypatch):
    monkeypatch.setattr(auth, "breach_checker", NoBreach())
    monkeypatch.setattr(settings, "admin_emails", ["bootstrap@example.com"])
    with TestClient(app) as client:
        response = client.post("/auth/register", json={
            "email": "bootstrap@example.com",
            "password": "correct horse battery staple",
        })
    assert response.status_code == 201
    with transaction() as db:
        assert db.execute("SELECT role FROM users WHERE email=?", ("bootstrap@example.com",)).fetchone()["role"] == "user"
