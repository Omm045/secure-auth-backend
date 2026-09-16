from app.config import settings
from app.services import reset_service


def test_email_links_use_frontend_base_url(monkeypatch):
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
        def send_message(self, message):
            sent.append(message)

    monkeypatch.setattr(reset_service.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(settings, "smtp_host", "smtp.test")
    monkeypatch.setattr(settings, "email_from", "no-reply@test")
    monkeypatch.setattr(settings, "frontend_base_url", "https://frontend.example.test/account")
    reset_service.deliver_reset_token("user@test", "reset-token")
    reset_service.deliver_verification_token("user@test", "verify-token")

    assert "https://frontend.example.test/account/reset.html#token=reset-token" in sent[0].get_content()
    assert "https://frontend.example.test/account/verify.html#token=verify-token" in sent[1].get_content()
