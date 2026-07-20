"""
Password strength analyzer (Phase 4).

Estimates entropy in bits from the effective character-pool size and length,
applies penalties for common weaknesses (dictionary words, sequences, repeats),
and returns a rating plus actionable suggestions.

Entropy model:  bits = length * log2(pool_size)
This is the standard "search-space" estimate. It is an upper bound -- real
guessability is lower for predictable passwords -- so we additionally deduct
bits for detectable patterns to avoid over-rating things like "Password123!".
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

UPPER_RE = re.compile(r"[A-Z]")
LOWER_RE = re.compile(r"[a-z]")
DIGIT_RE = re.compile(r"[0-9]")
SYMBOL_RE = re.compile(r"[^A-Za-z0-9]")

# A tiny built-in blocklist. In production, check against a large leaked-password
# corpus (see crypto.hibp) rather than a hard-coded list.
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password123",
    "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "111111",
}

SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop")


@dataclass
class StrengthResult:
    rating: str
    entropy_bits: float
    pool_size: int
    suggestions: list[str] = field(default_factory=list)


def _pool_size(password: str) -> int:
    size = 0
    if LOWER_RE.search(password):
        size += 26
    if UPPER_RE.search(password):
        size += 26
    if DIGIT_RE.search(password):
        size += 10
    if SYMBOL_RE.search(password):
        size += 32  # approximate printable-symbol space
    return size


def _has_sequence(password: str, min_len: int = 4) -> bool:
    p = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - min_len + 1):
            chunk = seq[i:i + min_len]
            if chunk in p or chunk[::-1] in p:
                return True
    return False


def _has_repeats(password: str) -> bool:
    return re.search(r"(.)\1\1", password) is not None  # 3+ identical in a row


def analyze(password: str) -> StrengthResult:
    suggestions: list[str] = []

    if not password:
        return StrengthResult("Empty", 0.0, 0, ["Enter a password"])

    pool = _pool_size(password)
    entropy = len(password) * math.log2(pool) if pool else 0.0

    # Pattern penalties (subtract bits for predictability).
    if password.lower() in COMMON_PASSWORDS:
        entropy = min(entropy, 12.0)
        suggestions.append("This is a commonly used password -- choose something unique")
    if _has_sequence(password):
        entropy -= 12
        suggestions.append("Avoid keyboard or alphabetical sequences (e.g. 'abcd', '1234')")
    if _has_repeats(password):
        entropy -= 8
        suggestions.append("Avoid repeating the same character three or more times")
    entropy = max(entropy, 0.0)

    # Composition suggestions.
    if len(password) < 12:
        suggestions.append("Use at least 12-16 characters")
    if not UPPER_RE.search(password):
        suggestions.append("Add uppercase letters")
    if not LOWER_RE.search(password):
        suggestions.append("Add lowercase letters")
    if not DIGIT_RE.search(password):
        suggestions.append("Add numbers")
    if not SYMBOL_RE.search(password):
        suggestions.append("Add symbols")

    # Rating bands based on estimated entropy.
    if entropy < 28:
        rating = "Very Weak"
    elif entropy < 36:
        rating = "Weak"
    elif entropy < 60:
        rating = "Moderate"
    elif entropy < 80:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return StrengthResult(
        rating=rating,
        entropy_bits=round(entropy, 1),
        pool_size=pool,
        suggestions=suggestions,
    )
