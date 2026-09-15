from datetime import datetime, timedelta, timezone
from app.config import settings
from app.database.connection import transaction
from app.security.tokens import token, token_hash


def deliver_reset_token(email: str, raw_token: str) -> None:
    """Production integration point (email provider); never log or return tokens."""
    return None


def issue_reset_token(user_id: int, email: str) -> None:
    raw = token()
    now = datetime.now(timezone.utc)
    with transaction() as connection:
        connection.execute(
            "INSERT INTO password_resets VALUES(?,?,?,?,0,?)",
            (
                token(),
                user_id,
                token_hash(raw),
                (now + timedelta(minutes=settings.reset_token_expire_minutes)).isoformat(),
                now.isoformat(),
            ),
        )
    deliver_reset_token(email, raw)
