"""
ORM models for SecureVault.

Design principles:
  * Plaintext passwords are NEVER stored -- not the master password, not vault
    entries. The master password is kept only as an Argon2id verifier; vault
    entries store AES-256-GCM ciphertext + iv + tag.
  * `key_salt` lets us re-derive the per-user vault key from the master password
    at login. The key itself is never persisted.
  * Ciphertext / iv / tag are stored as raw bytes (LargeBinary).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    # Argon2id verifier for the master password (embeds its own salt + params).
    master_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    # Salt used to derive the AES vault key from the master password.
    key_salt: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)

    # Brute-force protection state.
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)

    entries: Mapped[list["VaultEntry"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    logs: Mapped[list["ActivityLog"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class VaultEntry(Base):
    __tablename__ = "vault_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)

    label: Mapped[str] = mapped_column(String(128), nullable=False)   # e.g. "Google"
    username: Mapped[str] = mapped_column(String(255), default="")     # account login
    url: Mapped[str] = mapped_column(String(512), default="")

    # AES-256-GCM components -- never plaintext.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    iv: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    tag: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, onupdate=_utcnow, nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="entries")


class ActivityLog(Base):
    """Phase 9: audit trail of security-relevant events."""
    __tablename__ = "activity_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), index=True, nullable=True
    )

    event: Mapped[str] = mapped_column(String(64), nullable=False)   # LOGIN, LOGOUT, ...
    detail: Mapped[str] = mapped_column(String(512), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    machine_name: Mapped[str] = mapped_column(String(128), default="")

    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)

    user: Mapped["User | None"] = relationship(back_populates="logs")
