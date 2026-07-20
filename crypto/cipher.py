"""
AES-256-GCM authenticated encryption (Phase 2).

Every stored credential is encrypted with AES-256 in Galois/Counter Mode.
GCM is an AEAD cipher, so it provides:

    * Confidentiality  -> the plaintext password is unreadable at rest
    * Integrity/Authenticity -> tampering with the ciphertext, IV, or
      associated data is detected on decrypt (raises InvalidTag)

We store three components per entry and NEVER the plaintext:
    - ciphertext
    - iv (a.k.a. nonce): 12 random bytes, unique per encryption
    - tag: 16-byte GCM authentication tag

A fresh random 96-bit IV is generated for every encryption. Reusing an IV with
the same key catastrophically breaks GCM, so we never derive or reuse it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IV_LEN = 12   # 96-bit nonce is the GCM-recommended size
TAG_LEN = 16  # 128-bit authentication tag


@dataclass(frozen=True)
class Encrypted:
    """A single AES-256-GCM ciphertext bundle."""
    ciphertext: bytes
    iv: bytes
    tag: bytes


def encrypt(key: bytes, plaintext: str, associated_data: bytes | None = None) -> Encrypted:
    """
    Encrypt `plaintext` with AES-256-GCM under `key` (must be 32 bytes).

    `associated_data` (optional) is authenticated but not encrypted -- useful
    for binding a ciphertext to, e.g., a username or entry id so it cannot be
    silently swapped in the database.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")

    iv = os.urandom(IV_LEN)
    aesgcm = AESGCM(key)
    # cryptography's AESGCM appends the tag to the ciphertext; split it out so
    # we can store the tag separately, matching the Phase-2 storage schema.
    ct_and_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), associated_data)
    ciphertext, tag = ct_and_tag[:-TAG_LEN], ct_and_tag[-TAG_LEN:]
    return Encrypted(ciphertext=ciphertext, iv=iv, tag=tag)


def decrypt(key: bytes, enc: Encrypted, associated_data: bytes | None = None) -> str:
    """
    Decrypt an `Encrypted` bundle. Raises cryptography.exceptions.InvalidTag if
    the key is wrong or the data was tampered with.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(enc.iv, enc.ciphertext + enc.tag, associated_data)
    return plaintext.decode("utf-8")
