from fastapi.testclient import TestClient
import app.api.auth as auth
from app.config import settings
from app.main import app

class NoBreach:
    def is_breached(self, value):
        return False

def test_admin_stats(monkeypatch):
    monkeypatch.setattr(auth, "breach_checker", NoBreach())
    monkeypatch.setattr(settings, "admin_emails", ["admin@example.com"])
    with TestClient(app) as client:
        client.post("/auth/register", json={"email": "admin@example.com", "password": "abcdefgh"})
        response = client.get("/admin/stats")
        assert response.status_code == 200
        assert "password_breaches" in response.json()
