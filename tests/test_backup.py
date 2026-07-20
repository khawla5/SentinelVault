"""Tests for encrypted vault backup / restore (Phase 8)."""
import pytest
from cryptography.exceptions import InvalidTag

from backend import backup


def _sample():
    return [
        {"label": "Google", "username": "me@example.com", "url": "google.com", "password": "aaa"},
        {"label": "GitHub", "username": "octocat", "url": "github.com", "password": "bbb"},
    ]


def test_export_import_roundtrip():
    blob = backup.export_vault(_sample(), "backup-pass-123")
    assert blob.startswith(backup.MAGIC)
    restored = backup.import_vault(blob, "backup-pass-123")
    assert restored == _sample()


def test_wrong_passphrase_fails():
    blob = backup.export_vault(_sample(), "correct-pass")
    with pytest.raises(InvalidTag):
        backup.import_vault(blob, "wrong-pass")


def test_not_a_backup_file():
    with pytest.raises(ValueError):
        backup.import_vault(b"garbage-bytes-not-a-vault", "whatever")


def test_ciphertext_contains_no_plaintext():
    blob = backup.export_vault(_sample(), "pass")
    assert b"me@example.com" not in blob
    assert b"octocat" not in blob
