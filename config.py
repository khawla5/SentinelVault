"""
Central configuration for SecureVault.

Values are read from environment variables (or a local .env file) so that no
secret is ever hard-coded. Sensible development defaults are provided, but in
production every secret MUST be overridden via the environment.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Load a local .env file if present, so secrets (DATABASE_URL, JWT secret) can
# live in one gitignored file instead of being re-typed each session.
try:
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env")
except ImportError:
    # python-dotenv is optional; env vars still work without it.
    pass


def _get_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


class Settings:
    # --- Paths ---
    BASE_DIR: Path = BASE_DIR
    DB_PATH: Path = BASE_DIR / "database" / "securevault.db"
    LOG_DIR: Path = BASE_DIR / "logs"

    # --- Database ---
    # Default: local SQLite file. To use Supabase (or any Postgres), set the
    # DATABASE_URL environment variable to your connection string, e.g.
    #   export DATABASE_URL="postgresql://postgres:<password>@db.<ref>.supabase.co:5432/postgres"
    # The db layer normalises the driver + SSL automatically.
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")

    # --- JWT / session ---
    # In production: `export SECUREVAULT_JWT_SECRET=$(openssl rand -hex 32)`
    JWT_SECRET: str = os.getenv("SECUREVAULT_JWT_SECRET", "dev-only-insecure-change-me")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_TTL_MINUTES: int = int(os.getenv("SECUREVAULT_TOKEN_TTL", "5"))

    # --- Session / lockout policy ---
    SESSION_IDLE_TIMEOUT_MINUTES: int = 5      # Phase 7: auto-lock after inactivity
    MAX_FAILED_LOGINS: int = 5                 # Phase: brute-force protection
    LOCKOUT_SECONDS: int = 120                 # 2-minute lockout after threshold
    CLIPBOARD_CLEAR_SECONDS: int = 20          # Phase 6: clear clipboard after copy

    # --- Argon2id parameters (OWASP-recommended baseline) ---
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 64 * 1024        # 64 MiB
    ARGON2_PARALLELISM: int = 4
    ARGON2_HASH_LEN: int = 32
    ARGON2_SALT_LEN: int = 16

    # --- HIBP ---
    HIBP_RANGE_URL: str = "https://api.pwnedpasswords.com/range/"

    DEBUG: bool = _get_bool("SECUREVAULT_DEBUG", True)


settings = Settings()

# Ensure runtime directories exist.
settings.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
settings.LOG_DIR.mkdir(parents=True, exist_ok=True)
