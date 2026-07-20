"""
Key derivation and master-password hashing (Phase 1).

Two distinct uses of Argon2id, kept deliberately separate:

1. verify_master_password / hash_master_password
   Stores a *verifier* for the master password. We never store the password,
   only an Argon2id hash. This is what gates login.

2. derive_vault_key
   Derives the 32-byte symmetric key used by AES-256-GCM to encrypt vault
   entries. The key is derived from the master password + a per-user salt and
   is NEVER persisted -- it lives only in memory for the duration of a session
   and is wiped afterwards (see crypto.secure_mem).

Because the vault key is derived from the master password, the server can
operate on a "zero-knowledge" basis: without the user's master password the
stored ciphertext is unrecoverable, even to an attacker with full DB access.
"""
from __future__ import annotations

import os

from argon2 import Type
from argon2.low_level import hash_secret_raw
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from config import settings

# High-level hasher used for the login verifier (produces an encoded string
# that embeds its own salt + parameters).
_ph = PasswordHasher(
    time_cost=settings.ARGON2_TIME_COST,
    memory_cost=settings.ARGON2_MEMORY_COST,
    parallelism=settings.ARGON2_PARALLELISM,
    hash_len=settings.ARGON2_HASH_LEN,
    salt_len=settings.ARGON2_SALT_LEN,
    type=Type.ID,          # Argon2id: resistant to both GPU and side-channel attacks
)


def hash_master_password(password: str) -> str:
    """Return an encoded Argon2id verifier string for the master password."""
    return _ph.hash(password)


def verify_master_password(stored_hash: str, password: str) -> bool:
    """Constant-time verification of a master password against its stored hash."""
    try:
        _ph.verify(stored_hash, password)
        return True
    except VerifyMismatchError:
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if the stored hash used weaker params than the current policy."""
    return _ph.check_needs_rehash(stored_hash)


def new_key_salt() -> bytes:
    """Generate a fresh 16-byte salt for vault-key derivation."""
    return os.urandom(settings.ARGON2_SALT_LEN)


def derive_vault_key(password: str, key_salt: bytes) -> bytes:
    """
    Derive the 32-byte AES-256 vault key from the master password.

    Uses Argon2id raw output (no encoding). The same (password, salt) pair
    always yields the same key, which is why `key_salt` is stored per-user
    while the derived key itself is never stored.
    """
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=key_salt,
        time_cost=settings.ARGON2_TIME_COST,
        memory_cost=settings.ARGON2_MEMORY_COST,
        parallelism=settings.ARGON2_PARALLELISM,
        hash_len=32,               # exactly 256 bits for AES-256
        type=Type.ID,
    )
