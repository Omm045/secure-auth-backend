from datetime import datetime
from fastapi import Response
from app.config import settings


def set_session_cookie(response: Response, value: str, expires: datetime) -> None:
    response.set_cookie(
        "session", value, httponly=True, secure=settings.session_cookie_secure,
        samesite="lax", expires=expires, path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie("session", path="/")


def set_csrf_cookie(response: Response, value: str) -> None:
    response.set_cookie(
        "csrf_token", value, httponly=False, secure=settings.session_cookie_secure,
        samesite="lax", path="/",
    )
