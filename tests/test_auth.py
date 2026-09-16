import pytest
from fastapi.testclient import TestClient
from app.main import app
import app.api.auth as auth
from app.database.connection import transaction,init_db
class NoBreach:
    def is_breached(self,p): return False
@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setattr(auth,'breach_checker',NoBreach())
    init_db()
    with transaction() as c:
        for t in ('sessions','password_resets','audit_logs','users'): c.execute('DELETE FROM '+t)
def test_register_login_logout_and_bearer():
    with TestClient(app) as c:
        csrf=c.get('/csrf').json()['csrf_token']; r=c.post('/auth/register',json={'email':'x@example.com','password':'abcdefgh'}); assert r.status_code==201
        assert c.get('/auth/me').status_code==200
        token=r.cookies['session']; c.post('/auth/logout',headers={'X-CSRF-Token':csrf,'Authorization':'Bearer '+token}); assert c.get('/auth/me').status_code==401
        assert c.post('/auth/login',json={'email':'x@example.com','password':'abcdefgh'}).status_code==200

def test_duplicate_registration_returns_conflict():
    with TestClient(app) as c:
        payload = {'email': 'duplicate@example.com', 'password': 'abcdefgh'}
        assert c.post('/auth/register', json=payload).status_code == 201
        response = c.post('/auth/register', json=payload)
        assert response.status_code == 409
        assert response.json()["detail"] == "Email already registered"

def test_disabled_login_and_last_login():
    with TestClient(app) as c:
        c.post('/auth/register',json={'email':'disabled@example.com','password':'abcdefgh'})
    with transaction() as db:
        db.execute("UPDATE users SET disabled=TRUE WHERE email='disabled@example.com'")
    with TestClient(app) as c:
        assert c.post('/auth/login',json={'email':'disabled@example.com','password':'abcdefgh'}).status_code == 401

def test_failed_account_attempts_do_not_count_successful_login():
    from app.security import rate_limit
    rate_limit._hits.clear()
    rate_limit._account_failures.clear()
    with TestClient(app) as c:
        assert c.post('/auth/register', json={'email': 'victim@example.com', 'password': 'abcdefgh'}).status_code == 201
        for _ in range(5):
            assert c.post('/auth/login', json={'email': 'victim@example.com', 'password': 'wrongpass'}).status_code == 401
        assert c.post('/auth/login', json={'email': 'victim@example.com', 'password': 'abcdefgh'}).status_code == 200

def test_rate_limit(monkeypatch):
    import app.api.auth as module
    from app.security import rate_limit
    rate_limit._hits.clear()
    monkeypatch.setattr(module.settings, "rate_limit_per_minute", 1)
    with TestClient(app) as c:
        assert c.post('/auth/login',json={'email':'none@example.com','password':'abcdefgh'}).status_code == 401
        assert c.post('/auth/login',json={'email':'none@example.com','password':'abcdefgh'}).status_code == 429
