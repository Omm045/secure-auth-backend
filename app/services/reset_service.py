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
        recent = connection.execute(
            "SELECT created_at FROM password_resets WHERE user_id=? ORDER BY created_at DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        if recent:
            created = datetime.fromisoformat(recent["created_at"])
            if (now - created).total_seconds() < settings.reset_cooldown_seconds:
                return
        # A new request invalidates every previous reset token for this account.
        connection.execute("UPDATE password_resets SET used=1 WHERE user_id=? AND used=0", (user_id,))
        connection.execute(
            "INSERT INTO password_resets(id,user_id,token_hash,expires_at,used,created_at) VALUES(?,?,?,?,0,?)",
            (
                token(),
                user_id,
                token_hash(raw),
                (now + timedelta(minutes=settings.reset_token_expire_minutes)).isoformat(),
                now.isoformat(),
            ),
        )
    deliver_reset_token(email, raw)
