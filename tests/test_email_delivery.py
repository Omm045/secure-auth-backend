from email.message import EmailMessage

from app.services import reset_service


def test_reset_and_verification_messages_contain_tokens(monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def starttls(self):
            pass
        def login(self, *args):
            pass
        def send_message(self, message: EmailMessage):
            sent.append(message)

    monkeypatch.setattr(reset_service.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(reset_service.settings, "smtp_host", "smtp.test")
    monkeypatch.setattr(reset_service.settings, "email_from", "no-reply@test")
    reset_service.deliver_reset_token("user@test", "reset-token")
    reset_service.deliver_verification_token("user@test", "verify-token")

    assert sent[0]["Subject"] == "Password reset"
    assert "reset-token" in sent[0].get_content()
    assert sent[1]["Subject"] == "Verify your email"
    assert "verify-token" in sent[1].get_content()
