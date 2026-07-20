"""
SQLAlchemy engine and session management.

Supports two backends transparently:

  * SQLite  (default) -- a local file at settings.DB_PATH. Zero setup.
  * Postgres (Supabase / any Postgres) -- enabled by setting the DATABASE_URL
    environment variable to your connection string.

Switch to Supabase without touching any other code:

    pip install "psycopg[binary]"
    export DATABASE_URL="postgresql://postgres:<password>@db.<ref>.supabase.co:5432/postgres"

The encryption model is unchanged: only AES-256-GCM ciphertext + Argon2id hashes
are ever written to the database, whether that database is local or in Supabase.
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from config import settings


def _build_engine():
    url = settings.DATABASE_URL.strip()

    if not url:
        # --- Local SQLite (default) ---
        # check_same_thread=False lets FastAPI use the connection across threads.
        return create_engine(
            f"sqlite:///{settings.DB_PATH}",
            connect_args={"check_same_thread": False},
            future=True,
        )

    # --- Postgres / Supabase ---
    # Supabase hands out URLs starting with "postgresql://" (or "postgres://").
    # Point SQLAlchemy at the modern psycopg (v3) driver.
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)

    connect_args = {}
    # Supabase requires SSL; add it if the caller didn't specify sslmode.
    if "sslmode=" not in url:
        connect_args["sslmode"] = "require"

    return create_engine(
        url,
        connect_args=connect_args,
        pool_pre_ping=True,   # recover dropped cloud connections gracefully
        future=True,
    )


_engine = _build_engine()

SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False, future=True)


def current_backend() -> str:
    """Human-readable name of the active database backend (for logs/health)."""
    return "sqlite" if not settings.DATABASE_URL.strip() else "postgres"


def init_db() -> None:
    """Create all tables. Safe to call repeatedly."""
    from database.models import Base  # local import to avoid circular import
    Base.metadata.create_all(_engine)


def get_session() -> Iterator[Session]:
    """FastAPI dependency that yields a scoped DB session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
