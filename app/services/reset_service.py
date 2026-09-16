from datetime import datetime, timedelta, timezone
from app.config import settings
from app.database.connection import transaction
from app.security.tokens import token, token_hash
import smtplib
from email.message import EmailMessage
from urllib.parse import quote


def _deliver(email: str, subject: str, body: str) -> None:
    if not settings.smtp_host:
        if settings.environment == "production":
            raise RuntimeError("SMTP is not configured")
        return
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.email_from
    message["To"] = email
    message.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
        server.starttls()
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password or "")
        server.send_message(message)


def deliver_reset_token(email: str, raw_token: str) -> None:
    """Send a usable reset link without logging or persisting the token."""
    link = f"{settings.app_base_url.rstrip('/')}/password/reset?token={quote(raw_token)}"
    _deliver(email, "Password reset", f"Reset your password using this link:\n{link}")


def deliver_verification_token(email: str, raw_token: str) -> None:
    """Send a usable verification link without logging or persisting the token."""
    link = f"{settings.app_base_url.rstrip('/')}/auth/verify-email?token_value={quote(raw_token)}"
    _deliver(email, "Verify your email", f"Verify your email using this link:\n{link}")


def issue_verification_token(user_id: int, email: str) -> None:
    raw = token()
    now = datetime.now(timezone.utc)
    with transaction() as connection:
        connection.execute("UPDATE email_verification_tokens SET used=1 WHERE user_id=? AND used=0", (user_id,))
        connection.execute(
            "INSERT INTO email_verification_tokens(id,user_id,token_hash,expires_at,used,created_at) VALUES(?,?,?,?,0,?)",
            (token(), user_id, token_hash(raw),
             (now + timedelta(minutes=settings.reset_token_expire_minutes)).isoformat(), now.isoformat()),
        )
    deliver_verification_token(email, raw)


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
