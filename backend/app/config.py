from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "Password Manager - SentinelVault"
    APP_VERSION: str = "1.0.0"

    DATABASE_URL: str = "sqlite:///./password_manager.db"

    SECRET_KEY: str = "CHANGE_THIS_SECRET_KEY"

    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30


settings = Settings()