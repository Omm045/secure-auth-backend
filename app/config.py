"""Typed, fail-closed application configuration."""
from typing import Any

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    environment: str = "development"
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
            if not self.cors_origins or any(not origin.startswith("https://") for origin in self.cors_origins):
                raise ValueError("production CORS origins must be explicit HTTPS origins")
            if not self.redis_url:
                raise ValueError("REDIS_URL is required in production")
            if not self.admin_emails:
                raise ValueError("ADMIN_EMAILS must identify the initial role-provisioning accounts in production")
        return self


settings = Settings()
