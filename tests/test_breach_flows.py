from fastapi.testclient import TestClient
import app.api.auth as auth
import app.api.password as password
from app.main import app

class Breached:
    def is_breached(self, value):
        return True

def test_register_and_change_reject_breached(monkeypatch):
    class NoBreach:
        def is_breached(self, value): return False
    monkeypatch.setattr(auth, "breach_checker", NoBreach())
    with TestClient(app) as client:
        assert client.post("/auth/register", json={"email": "breach-flow@example.com", "password": "correct horse battery staple"}).status_code == 201
        client.post("/auth/login", json={"email": "breach-flow@example.com", "password": "correct horse battery staple"})
        monkeypatch.setattr(auth, "breach_checker", Breached())
        csrf = client.get("/csrf").json()["csrf_token"]
        assert client.post("/auth/change-password", headers={"X-CSRF-Token": csrf},
                           json={"current_password": "correct horse battery staple", "new_password": "another secure passphrase"}).status_code == 422

def test_reset_rejects_breached(monkeypatch):
    monkeypatch.setattr(password, "breach_checker", Breached())
    with TestClient(app) as client:
        csrf = client.get("/csrf").json()["csrf_token"]
        assert client.post("/password/reset", headers={"X-CSRF-Token": csrf},
                           json={"token": "invalid", "new_password": "correct horse battery staple"}).status_code == 422
