"""Application configuration using Pydantic Settings."""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for Active Verification."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "ActiveVerification"
    APP_ENV: str = "development"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Ingestion - Gmail OAuth
    GMAIL_CLIENT_ID: Optional[str] = None
    GMAIL_CLIENT_SECRET: Optional[str] = None
    GMAIL_REFRESH_TOKEN: Optional[str] = None
    GMAIL_POLL_INTERVAL_SECONDS: int = 30

    # Ingestion - IMAP
    IMAP_SERVER: Optional[str] = None
    IMAP_PORT: int = 993
    IMAP_USERNAME: Optional[str] = None
    IMAP_PASSWORD: Optional[str] = None
    IMAP_USE_SSL: bool = True
    IMAP_MAILBOX: str = "INBOX"
    IMAP_POLL_INTERVAL_SECONDS: int = 30

    # Active Verification - CRITICAL: Sandbox mode strictly enforced
    ACTIVE_VERIFICATION_SANDBOX_STRICT: bool = True
    MAX_SYNTHETIC_INTERACTION_TURNS: int = 3

    # Decision Engine Calibrated Thresholds (for ~1% FPR target)
    QUARANTINE_THRESHOLD: float = 0.88
    WARN_THRESHOLD: float = 0.55
    TARGET_FPR: float = 0.01

    # Privacy & Security
    PRIVACY_SALT: str = "active-verification-default-salt-key"
    HASH_PII_ENABLED: bool = True
    STORE_RAW_BODIES: bool = False

    # Models & LLMs
    LLM_PROVIDER: str = "gemini"
    LLM_API_KEY: Optional[str] = None
    DEBERTA_MODEL_NAME: str = "microsoft/deberta-v3-small"
    ENABLE_LOCAL_TRANSFORMER: bool = True


settings = Settings()

