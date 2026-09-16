from fastapi.testclient import TestClient
import app.api.password as pw
import app.api.auth as auth
import app.services.reset_service as reset_service
from app.database.connection import transaction
from app.main import app
class NoBreach:
    def is_breached(self,p): return False
def test_reset_token_hook(monkeypatch):
    monkeypatch.setattr(auth,'breach_checker',NoBreach()); monkeypatch.setattr(pw,'breach_checker',NoBreach())
    captured = {}
    monkeypatch.setattr(reset_service, "deliver_reset_token", lambda email, raw: captured.update(email=email, raw=raw))
    with TestClient(app) as c:
        c.post('/auth/register',json={'email':'r@example.com','password':'correct horse battery staple'})
        c.post('/password/forgot',json={'email':'r@example.com'})
        raw=captured["raw"]; csrf=c.get('/csrf').json()['csrf_token']
        r=c.post('/password/reset',headers={'X-CSRF-Token':csrf},json={'token':raw,'new_password':'another secure passphrase'})
        assert r.status_code==200
        with transaction() as db:
            logs = [row["event"] for row in db.execute("SELECT event FROM audit_logs").fetchall()]
        assert raw not in logs

def test_forgot_password_performs_dummy_verification_for_existing_and_missing(monkeypatch):
    calls = []
    monkeypatch.setattr(pw, "verify_password", lambda password, encoded: calls.append(encoded) or False)
    monkeypatch.setattr(pw, "issue_reset_token", lambda *args: None)
    with TestClient(app) as client:
        client.post("/auth/register", json={
            "email": "forgot-existing@example.com",
            "password": "correct horse battery staple",
        })
        calls.clear()
        existing = client.post("/password/forgot", json={"email": "forgot-existing@example.com"})
        missing = client.post("/password/forgot", json={"email": "forgot-missing@example.com"})
    assert existing.status_code == missing.status_code == 200
    assert existing.json() == missing.json()
    assert calls == [pw.DUMMY_RESET_HASH, pw.DUMMY_RESET_HASH]
