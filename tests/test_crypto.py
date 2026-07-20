"""Tests for the cryptography layer: KDF, AES-GCM, secure memory."""
import os

import pytest
from cryptography.exceptions import InvalidTag

from crypto import cipher, kdf
from crypto.secure_mem import sensitive_bytes, wipe


def test_master_password_hash_roundtrip():
    h = kdf.hash_master_password("correct horse battery staple")
    assert h != "correct horse battery staple"        # never plaintext
    assert kdf.verify_master_password(h, "correct horse battery staple")
    assert not kdf.verify_master_password(h, "wrong password")


def test_derive_vault_key_is_deterministic_and_32_bytes():
    salt = kdf.new_key_salt()
    k1 = kdf.derive_vault_key("master", salt)
    k2 = kdf.derive_vault_key("master", salt)
    assert k1 == k2
    assert len(k1) == 32
    # Different salt -> different key.
    assert kdf.derive_vault_key("master", kdf.new_key_salt()) != k1


def test_aes_gcm_roundtrip():
    key = os.urandom(32)
    enc = cipher.encrypt(key, "s3cr3t-password")
    assert enc.ciphertext != b"s3cr3t-password"
    assert len(enc.iv) == cipher.IV_LEN
    assert len(enc.tag) == cipher.TAG_LEN
    assert cipher.decrypt(key, enc) == "s3cr3t-password"


def test_aes_gcm_wrong_key_fails():
    enc = cipher.encrypt(os.urandom(32), "hello")
    with pytest.raises(InvalidTag):
        cipher.decrypt(os.urandom(32), enc)


def test_aes_gcm_tamper_detected():
    key = os.urandom(32)
    enc = cipher.encrypt(key, "hello")
    tampered = cipher.Encrypted(
        ciphertext=bytes([enc.ciphertext[0] ^ 0x01]) + enc.ciphertext[1:],
        iv=enc.iv, tag=enc.tag,
    )
    with pytest.raises(InvalidTag):
        cipher.decrypt(key, tampered)


def test_associated_data_binding():
    key = os.urandom(32)
    enc = cipher.encrypt(key, "hello", associated_data=b"user:1")
    # Right AAD works.
    assert cipher.decrypt(key, enc, associated_data=b"user:1") == "hello"
    # Wrong AAD is rejected.
    with pytest.raises(InvalidTag):
        cipher.decrypt(key, enc, associated_data=b"user:2")


def test_key_must_be_32_bytes():
    with pytest.raises(ValueError):
        cipher.encrypt(os.urandom(16), "x")


def test_wipe_zeroes_buffer():
    buf = bytearray(b"secret")
    wipe(buf)
    assert buf == bytearray(len(b"secret"))


def test_sensitive_bytes_context_wipes():
    captured = {}
    with sensitive_bytes(b"topsecret") as buf:
        captured["buf"] = buf
        assert bytes(buf) == b"topsecret"
    assert captured["buf"] == bytearray(len(b"topsecret"))  # wiped on exit
