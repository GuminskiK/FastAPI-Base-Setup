from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str
    APP_NAME: str
    SECRET_KEY: str = "your-secret-key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ACTIVATE_TOKEN_EXPIRE_DAYS: int = 1
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 60
    FIRST_SUPERUSER: str = "admin123"
    FIRST_SUPERUSER_PASSWORD: str = "changeme"

    MAIL_USERNAME: str | None = None
    MAIL_PASSWORD: str | None = None
    MAIL_FROM: str = "noreply@localhost.com"
    MAIL_PORT: int = 1025
    MAIL_SERVER: str = "localhost"
    FRONTEND_URL: str = "http://localhost:3000"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=True)

settings = Settings()