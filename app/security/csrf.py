import secrets
import logging
import hashlib
import hmac
from fastapi import HTTPException,Request
from app.config import settings
logger = logging.getLogger("secure_auth.security")

def csrf_token():
    nonce = secrets.token_urlsafe(24)
    signature = hmac.new(settings.secret_key.encode(), nonce.encode(), hashlib.sha256).hexdigest()
    return f"{nonce}.{signature}"

def verify_csrf(request:Request):
    cookie_name = "__Host-csrf_token" if settings.environment == "production" else "csrf_token"
    cookie=request.cookies.get(cookie_name); header=request.headers.get("X-CSRF-Token")
    valid = False
    if cookie and header and secrets.compare_digest(cookie,header):
        nonce, separator, signature = cookie.rpartition(".")
        expected = hmac.new(settings.secret_key.encode(), nonce.encode(), hashlib.sha256).hexdigest()
        valid = bool(separator and secrets.compare_digest(signature, expected))
    if not valid:
        logger.warning("CSRF validation failed")
        raise HTTPException(403,"CSRF validation failed")
