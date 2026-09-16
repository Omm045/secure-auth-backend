"""Typed, fail-closed application configuration."""
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./app.db"
    secret_key: str = "development-only-change-me"
    access_token_expire_minutes: int = 30
    reset_token_expire_minutes: int = 30
    session_cookie_secure: bool = False
    cors_origins: list[str] = ["http://localhost:3000"]
    admin_emails: list[str] = []
    hibp_api_url: str = "https://api.pwnedpasswords.com/range/"
    hibp_fail_closed: bool = True
    rate_limit_per_minute: int = 10
    redis_url: str | None = None
    reset_cooldown_seconds: int = 60
    email_provider: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    email_from: str | None = None
    app_base_url: str = "http://localhost:8000"
    frontend_base_url: str | None = None
    sentry_dsn: str | None = None
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    @field_validator("environment", mode="before")
    @classmethod
    def normalize_environment(cls, value: Any) -> str:
        return str(value).strip().lower()

    @field_validator("cors_origins", "admin_emails", mode="before")
    @classmethod
    def split_csv(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("rate_limit_per_minute", "access_token_expire_minutes",
                     "reset_token_expire_minutes", "reset_cooldown_seconds")
    @classmethod
    def positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("must be positive")
        return value

    @model_validator(mode="after")
    def production_is_safe(self) -> "Settings":
        if self.environment == "production":
            if len(self.secret_key) < 32 or self.secret_key == "development-only-change-me":
                raise ValueError("SECRET_KEY must be a random value of at least 32 characters in production")
            if not self.session_cookie_secure:
                raise ValueError("SESSION_COOKIE_SECURE must be true in production")
            if not self.cors_origins or any(not _https_url(origin, allow_path=False) for origin in self.cors_origins):
                raise ValueError("production CORS origins must be explicit HTTPS origins")
            if not self.redis_url:
                raise ValueError("REDIS_URL is required in production")
            if not self.redis_url.startswith("rediss://"):
                raise ValueError("REDIS_URL must use rediss:// in production")
            if not self.admin_emails:
                raise ValueError("ADMIN_EMAILS must identify the initial role-provisioning accounts in production")
            if not self.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
                raise ValueError(
                    "DATABASE_URL must use postgresql:// or postgresql+psycopg:// in production"
                )
            if not all((self.email_provider, self.smtp_host, self.smtp_username,
                        self.smtp_password, self.email_from)):
                raise ValueError("SMTP email settings are required in production")
            if not _https_url(self.app_base_url):
                raise ValueError("APP_BASE_URL must be an HTTPS URL in production")
            if not _https_url(self.hibp_api_url):
                raise ValueError("HIBP_API_URL must be an HTTPS URL in production")
            frontend_url = self.frontend_base_url or self.app_base_url
            if not _https_url(frontend_url):
                raise ValueError("FRONTEND_BASE_URL must be an HTTPS URL in production")
        return self


def _https_url(value: str, allow_path: bool = True) -> bool:
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and not parsed.username
            and not parsed.password
            and (allow_path or parsed.path in ("", "/"))
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


settings = Settings()
