"""Tests for the password strength analyzer."""
from crypto.strength import analyze


def test_common_password_is_weak():
    r = analyze("password123")
    assert r.rating in {"Very Weak", "Weak"}
    assert r.entropy_bits < 36


def test_empty_password():
    r = analyze("")
    assert r.rating == "Empty"
    assert r.entropy_bits == 0.0


def test_strong_password_rated_high():
    r = analyze("Z!8dkP@1mz#Qa4vX9wL2")
    assert r.rating in {"Strong", "Very Strong"}
    assert r.entropy_bits >= 80


def test_sequence_penalised():
    weak = analyze("abcd1234")
    assert "sequence" in " ".join(weak.suggestions).lower()


def test_suggestions_present_for_weak():
    r = analyze("alllowercase")
    joined = " ".join(r.suggestions).lower()
    assert "uppercase" in joined
    assert "number" in joined or "symbol" in joined
