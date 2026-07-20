"""
Session, JWT and access-control helpers.

The vault key is derived from the master password at login and is required to
decrypt entries. It must NOT be persisted, so we keep it in an in-memory
session store keyed by the token's unique id (jti). The store also tracks
`last_active` to enforce the Phase-7 idle timeout, and is where a session's key
buffer gets wiped on logout.

Note: an in-memory store means sessions live only in this process (fine for a
single-instance desktop-style app). A multi-process deployment would need each
worker to re-derive the key per request from a password re-prompt, or a secure
enclave -- deliberately out of scope here.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, Header, HTTPException, status

from config import settings
from crypto.secure_mem import wipe


@dataclass
class Session:
    user_id: int
    vault_key: bytearray  # mutable so we can wipe it on logout
    last_active: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# jti -> Session
_sessions: dict[str, Session] = {}


def create_session(user_id: int, vault_key: bytes) -> str:
    """Create a session + signed JWT; returns the encoded access token."""
    jti = uuid.uuid4().hex
    _sessions[jti] = Session(user_id=user_id, vault_key=bytearray(vault_key))

    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def destroy_session(jti: str) -> None:
    """Wipe the vault key and drop the session (Phase 7 lock / logout)."""
    sess = _sessions.pop(jti, None)
    if sess is not None:
        wipe(sess.vault_key)


def _decode(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired -- please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")


@dataclass
class CurrentUser:
    user_id: int
    jti: str
    vault_key: bytearray


def get_current_session(authorization: str = Header(default="")) -> CurrentUser:
    """
    FastAPI dependency: validate the bearer token, enforce the idle timeout,
    and return the live session (including the in-memory vault key).
    """
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()

    payload = _decode(token)
    jti = payload.get("jti", "")
    sess = _sessions.get(jti)
    if sess is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session not found -- log in again")

    # Phase 7: idle timeout.
    now = datetime.now(timezone.utc)
    idle_limit = timedelta(minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES)
    if now - sess.last_active > idle_limit:
        destroy_session(jti)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Locked due to inactivity -- log in again")

    sess.last_active = now
    return CurrentUser(user_id=sess.user_id, jti=jti, vault_key=sess.vault_key)


CurrentUserDep = Depends(get_current_session)
