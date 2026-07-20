"""
Encrypted vault backup / restore (Phase 8).

Exports the whole vault to a single portable `vault.sec` file, encrypted with
AES-256-GCM under a key derived (Argon2id) from a user-supplied *backup
passphrase* -- independent of the login password so a backup can be restored on
another machine.

vault.sec binary layout:
    magic  : b"SVLT1"          (5 bytes)
    salt   : 16 bytes          (Argon2id salt for the backup key)
    iv     : 12 bytes          (GCM nonce)
    tag    : 16 bytes          (GCM auth tag)
    ct     : remaining bytes   (AES-256-GCM ciphertext of the JSON payload)
"""
from __future__ import annotations

import json
import struct

from crypto import cipher, kdf

MAGIC = b"SVLT1"
_HEADER = struct.Struct(f"<5s16s12s16s")  # magic, salt, iv, tag


def export_vault(entries: list[dict], backup_passphrase: str) -> bytes:
    """Serialize + encrypt a list of {label, username, url, password} dicts."""
    payload = json.dumps({"version": 1, "entries": entries}).encode("utf-8")

    salt = kdf.new_key_salt()
    key = kdf.derive_vault_key(backup_passphrase, salt)
    enc = cipher.encrypt(key, payload.decode("utf-8"))

    return _HEADER.pack(MAGIC, salt, enc.iv, enc.tag) + enc.ciphertext


def import_vault(blob: bytes, backup_passphrase: str) -> list[dict]:
    """Decrypt a vault.sec blob and return the list of entry dicts."""
    if len(blob) < _HEADER.size:
        raise ValueError("Backup file is truncated or corrupt")

    magic, salt, iv, tag = _HEADER.unpack(blob[: _HEADER.size])
    if magic != MAGIC:
        raise ValueError("Not a SecureVault backup file")

    ciphertext = blob[_HEADER.size:]
    key = kdf.derive_vault_key(backup_passphrase, salt)
    enc = cipher.Encrypted(ciphertext=ciphertext, iv=iv, tag=tag)
    plaintext = cipher.decrypt(key, enc)  # raises InvalidTag on wrong passphrase
    data = json.loads(plaintext)
    return data["entries"]
