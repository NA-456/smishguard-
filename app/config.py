"""
Configuration — loaded from environment variables or .env file.
All sensitive values (API keys, secrets) must be set in the environment;
they are never hard-coded here.
"""

from pydantic_settings import BaseSettings
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    # ── General ────────────────────────────────────────────────────
    environment: str = "development"
    debug: bool = False
    allowed_origins: List[str] = ["*"]

    # ── AfricasTalking ─────────────────────────────────────────────
    # Register at https://africastalking.com and set these in your env
    at_username: str = "sandbox"
    at_api_key: str = ""                 # Set via AT_API_KEY env var
    at_shortcode: str = ""               # Your SMS shortcode / sender ID
    at_webhook_secret: str = ""          # Optional HMAC webhook signing secret

    # ── Thresholds ─────────────────────────────────────────────────
    danger_threshold: int = 55           # Score >= this → high risk
    suspicious_threshold: int = 25      # Score >= this → suspicious

    # ── Auto-reply settings ────────────────────────────────────────
    # When True the webhook will auto-reply to flagged messages
    enable_auto_reply: bool = False
    auto_reply_danger_msg: str = (
        "WARNING: This message has been flagged as a potential scam. "
        "Do not share your MoMo PIN or personal details. "
        "Report scams: 0800-900-900 (free)"
    )

    # ── Derived (computed from loaded rules) ───────────────────────
    total_rules: int = 0
    gh_rules: int = 0

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        # Environment variable prefix — e.g. AT_API_KEY, AT_USERNAME
        env_prefix = ""
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
