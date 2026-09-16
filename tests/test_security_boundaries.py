import hashlib
import logging

from fastapi.testclient import TestClient

from app.config import settings
from app.database.connection import transaction
from app.main import app
from app.security import rate_limit


class NoBreach:
    def is_breached(self, value):
        return False


def test_verification_rate_limit_never_contains_raw_token(monkeypatch):
    import app.api.auth as auth
    monkeypatch.setattr(auth, "breach_checker", NoBreach())
    monkeypatch.setattr(settings, "rate_limit_per_minute", 10)
    captured = []
    monkeypatch.setattr(auth, "enforce_rate_limit",
                        lambda request, limit, **kwargs: captured.append(kwargs["identity"]))
    with TestClient(app) as client:
        client.post("/auth/register", json={
            "email": "token-boundary@example.com",
            "password": "correct horse battery staple",
        })
    raw = "raw-verification-token"
    with TestClient(app) as client:
        client.post("/auth/verify-email", params={"token_value": raw})
    assert raw not in captured
    assert hashlib.sha256(raw.encode()).hexdigest() in captured


def test_csrf_missing_and_mismatch_are_rejected():
    with TestClient(app) as client:
        assert client.post("/auth/logout").status_code == 403
        client.get("/csrf")
        assert client.post("/auth/logout", headers={"X-CSRF-Token": "wrong"}).status_code == 403


def test_unauthorized_cors_origin_is_not_allowed():
    with TestClient(app) as client:
        response = client.options(
            "/auth/login",
            headers={
                "Origin": "https://attacker.example",
                "Access-Control-Request-Method": "POST",
            },
        )
    assert "access-control-allow-origin" not in response.headers

def test_frontend_uses_same_origin_scripts_only():
    from pathlib import Path
    frontend = Path(__file__).parents[1] / "frontend"
    for page in frontend.glob("*.html"):
        source = page.read_text(encoding="utf-8")
        assert "cdn.jsdelivr.net" not in source
        assert "<script>" not in source
