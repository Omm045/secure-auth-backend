from datetime import datetime
from fastapi import Response
from app.config import settings


def set_session_cookie(response: Response, value: str, expires: datetime) -> None:
    name = "__Host-session" if settings.environment == "production" else "session"
    response.set_cookie(
        name, value, httponly=True, secure=settings.session_cookie_secure,
        samesite="lax", expires=expires, path="/",
    )


def clear_session_cookie(response: Response) -> None:
    name = "__Host-session" if settings.environment == "production" else "session"
    response.delete_cookie(name, path="/")


def set_csrf_cookie(response: Response, value: str) -> None:
    name = "__Host-csrf_token" if settings.environment == "production" else "csrf_token"
    response.set_cookie(
        name, value, httponly=False, secure=settings.session_cookie_secure,
        samesite="lax", path="/",
    )
