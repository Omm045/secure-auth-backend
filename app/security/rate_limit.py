"""Distributed rate limiting with an intentionally explicit local fallback."""
import time
from collections import defaultdict, deque
from fastapi import HTTPException, Request

from app.config import settings
import logging
import hashlib
logger = logging.getLogger("secure_auth.security")

_hits: dict[str, deque[float]] = defaultdict(deque)  # compatibility/test hook
_account_failures: dict[str, deque[float]] = defaultdict(deque)
_redis = None
_ATOMIC_INCREMENT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""


def _increment_with_ttl(client, key: str) -> int:
    if hasattr(client, "eval"):
        return int(client.eval(_ATOMIC_INCREMENT, 1, key, 60))
    count = int(client.incr(key))
    if count == 1:
        client.expire(key, 60)
    return count


def _redis_client():
    global _redis
    if _redis is not None:
        return _redis
    if not settings.redis_url:
        return None
    try:
        import redis
        _redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        _redis.ping()
        return _redis
    except Exception:
        if settings.environment == "production":
            raise HTTPException(503, "Rate limiting unavailable")
        return None


def enforce_rate_limit(request: Request, limit: int, on_limited=None, scope: str = "request",
                       identity: str | None = None):
    dimensions = [f"ip:{request.client.host if request.client else 'unknown'}"]
    if identity:
        identity_digest = hashlib.sha256(identity.strip().lower().encode()).hexdigest()[:32]
        dimensions.append(f"account:{identity_digest}")
    key = f"{scope}:" + "|".join(dimensions)
    try:
        client = _redis_client()
    except HTTPException:
        raise
    if client is not None:
        try:
            count = _increment_with_ttl(client, key)
            if count > limit:
                if on_limited:
                    on_limited()
                logger.warning("Rate limit rejected")
                raise HTTPException(429, "Too many requests", headers={"Retry-After": "60"})
            return
        except HTTPException:
            raise
        except Exception:
            if settings.environment == "production":
                raise HTTPException(503, "Rate limiting unavailable")
    if settings.environment == "production":
        raise HTTPException(503, "Rate limiting unavailable")
    now = time.monotonic()
    queue = _hits[key]
    while queue and now - queue[0] > 60:
        queue.popleft()
    if len(queue) >= limit:
        if on_limited:
            on_limited()
        logger.warning("Rate limit rejected")
        raise HTTPException(429, "Too many requests", headers={"Retry-After": "60"})
    queue.append(now)


def enforce_account_failure_limit(email: str, limit: int) -> None:
    """Check only failed-login events, avoiding account lockout by successes."""
    key = hashlib.sha256(email.strip().lower().encode()).hexdigest()[:32]
    redis_key = f"account-failures:{key}"
    threshold = max(limit * 3, 30)
    client = _redis_client()
    if client is not None:
        try:
            count = int(client.get(redis_key) or 0)
            if count >= threshold:
                logger.warning("Account failed-attempt limit rejected")
                raise HTTPException(429, "Too many failed attempts", headers={"Retry-After": "60"})
            return
        except HTTPException:
            raise
        except Exception:
            if settings.environment == "production":
                raise HTTPException(503, "Rate limiting unavailable")
    if settings.environment == "production":
        raise HTTPException(503, "Rate limiting unavailable")
    now = time.monotonic()
    queue = _account_failures[key]
    while queue and now - queue[0] > 60:
        queue.popleft()
    if len(queue) >= threshold:
        logger.warning("Account failed-attempt limit rejected")
        raise HTTPException(429, "Too many failed attempts", headers={"Retry-After": "60"})


def record_account_failure(email: str) -> None:
    key = hashlib.sha256(email.strip().lower().encode()).hexdigest()[:32]
    client = _redis_client()
    if client is not None:
        try:
            redis_key = f"account-failures:{key}"
            _increment_with_ttl(client, redis_key)
            return
        except Exception:
            if settings.environment == "production":
                raise HTTPException(503, "Rate limiting unavailable")
    if settings.environment == "production":
        raise HTTPException(503, "Rate limiting unavailable")
    _account_failures[key].append(time.monotonic())


def clear_account_failures(email: str) -> None:
    key = hashlib.sha256(email.strip().lower().encode()).hexdigest()[:32]
    client = _redis_client()
    if client is not None:
        try:
            client.delete(f"account-failures:{key}")
            return
        except Exception:
            if settings.environment == "production":
                raise HTTPException(503, "Rate limiting unavailable")
    if settings.environment == "production":
        raise HTTPException(503, "Rate limiting unavailable")
    _account_failures.pop(key, None)
