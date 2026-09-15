from fastapi.testclient import TestClient
from app.main import app
def test_headers_and_csrf():
    with TestClient(app) as c:
        r=c.get('/health'); assert r.headers['x-frame-options']=='DENY'; assert r.headers['x-content-type-options']=='nosniff'
        assert c.post('/auth/logout').status_code==403
