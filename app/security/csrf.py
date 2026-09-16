import secrets
import logging
from fastapi import HTTPException,Request
logger = logging.getLogger("secure_auth.security")
def csrf_token(): return secrets.token_urlsafe(24)
def verify_csrf(request:Request):
    cookie=request.cookies.get("csrf_token"); header=request.headers.get("X-CSRF-Token")
    if not cookie or not header or not secrets.compare_digest(cookie,header):
        logger.warning("CSRF validation failed")
        raise HTTPException(403,"CSRF validation failed")
