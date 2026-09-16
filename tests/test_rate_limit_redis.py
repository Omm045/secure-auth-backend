import hashlib
from app.config import settings
from app.security import rate_limit
import pytest


class FakeRedis:
    def __init__(self):
        self.values = {}
    def get(self, key):
        return self.values.get(key)
    def incr(self, key):
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]
    def expire(self, key, seconds):
        pass
    def delete(self, key):
        self.values.pop(key, None)

class AtomicFakeRedis(FakeRedis):
    def eval(self, script, numkeys, key, ttl):
        return self.incr(key)


def test_account_failures_are_shared_through_redis(monkeypatch):
    client = FakeRedis()
    monkeypatch.setattr(settings, "redis_url", "redis://test")
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(rate_limit, "_redis", client)
    rate_limit._account_failures.clear()

    for _ in range(29):
        rate_limit.record_account_failure("shared@example.com")
    rate_limit.enforce_account_failure_limit("shared@example.com", 10)
    rate_limit.record_account_failure("shared@example.com")
    with pytest.raises(Exception) as error:
        rate_limit.enforce_account_failure_limit("shared@example.com", 10)

    key = hashlib.sha256(b"shared@example.com").hexdigest()[:32]
    assert client.values[f"account-failures:{key}"] == 30
    assert error.value.status_code == 429

def test_redis_increment_uses_atomic_script_when_available(monkeypatch):
    client = AtomicFakeRedis()
    monkeypatch.setattr(rate_limit, "_redis", client)
    monkeypatch.setattr(settings, "redis_url", "redis://test")
    rate_limit._hits.clear()
    from fastapi import Request
    scope = {"type": "http", "client": ("127.0.0.1", 1), "method": "POST", "path": "/"}
    request = Request(scope)
    rate_limit.enforce_rate_limit(request, 2, scope="atomic")
    assert client.values
