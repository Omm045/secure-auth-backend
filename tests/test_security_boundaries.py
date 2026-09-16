import hashlib
import logging
from datetime import datetime, timezone
from starlette.responses import Response

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
        client.post("/auth/verify-email", json={"token_value": raw})
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

def test_auth_credentials_are_not_cached():
    with TestClient(app) as client:
        for method, path, payload in (
            ("get", "/csrf", None),
            ("post", "/auth/login", {"email": "none@example.com", "password": "wrong"}),
            ("post", "/password/forgot", {"email": "none@example.com"}),
        ):
            response = getattr(client, method)(path, json=payload) if payload else getattr(client, method)(path)
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["pragma"] == "no-cache"

def test_development_cookie_names_remain_http_compatible():
    with TestClient(app) as client:
        response = client.get("/csrf")
        assert "csrf_token=" in response.headers["set-cookie"]
        assert "__Host-" not in response.headers["set-cookie"]

def test_production_cookies_use_host_prefix_and_exact_logout_name(monkeypatch):
    from app.security.cookies import set_session_cookie, clear_session_cookie, set_csrf_cookie
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "session_cookie_secure", True)
    response = Response()
    set_session_cookie(response, "session-value", datetime.now(timezone.utc))
    set_csrf_cookie(response, "csrf-value")
    cookies = [value.decode() for key, value in response.raw_headers if key == b"set-cookie"]
    assert any("__Host-session=" in cookie for cookie in cookies)
    assert any("__Host-csrf_token=" in cookie for cookie in cookies)
    assert all("Secure" in cookie and "Path=/" in cookie and "SameSite=lax" in cookie and "Domain=" not in cookie for cookie in cookies)
    cleared = Response()
    clear_session_cookie(cleared)
    assert "__Host-session=" in cleared.headers["set-cookie"]

def test_registration_and_forgot_responses_are_generic(monkeypatch):
    import app.api.auth as auth
    import app.api.password as password_api
    monkeypatch.setattr(auth, "breach_checker", NoBreach())
    monkeypatch.setattr(password_api, "issue_reset_token", lambda *args: None)
    with TestClient(app) as client:
        payload = {"email": "generic@example.com", "password": "correct horse battery staple"}
        first = client.post("/auth/register", json=payload)
        duplicate = client.post("/auth/register", json=payload)
        assert first.status_code == duplicate.status_code == 201
        assert first.json() == duplicate.json()
        existing = client.post("/password/forgot", json={"email": payload["email"]})
        missing = client.post("/password/forgot", json={"email": "absent-generic@example.com"})
        assert existing.status_code == missing.status_code == 200
        assert existing.json() == missing.json()

def test_verification_rejects_query_token():
    with TestClient(app) as client:
        response = client.post("/auth/verify-email?token_value=never-in-url", json={})
    assert response.status_code == 422
