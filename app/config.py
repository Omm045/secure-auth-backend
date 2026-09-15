from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
class Settings(BaseSettings):
    database_url: str = "sqlite:///./app.db"
    secret_key: str = "development-only-change-me"
    access_token_expire_minutes: int = 30
    reset_token_expire_minutes: int = 30
    session_cookie_secure: bool = False
    cors_origins: list[str] = ["http://localhost:3000"]
    admin_emails: list[str] = []
    hibp_api_url: str = "https://api.pwnedpasswords.com/range/"
    rate_limit_per_minute: int = 10
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    @field_validator("cors_origins", "admin_emails", mode="before")
    @classmethod
    def split_csv(cls, v):
        if isinstance(v, str): return [x.strip() for x in v.split(",") if x.strip()]
        return v
settings = Settings()
