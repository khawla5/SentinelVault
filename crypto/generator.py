"""
Cryptographically secure password generator (Phase 3).

Uses `secrets` (CSPRNG) rather than `random`. Supports length presets of
16 / 20 / 24 / 32 and toggles for uppercase, lowercase, digits and symbols.

When multiple character classes are requested, the generator guarantees at
least one character from each selected class, then fills the remainder and
shuffles -- so a password can never accidentally omit a required class.
"""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
# A curated symbol set that avoids ambiguous / shell-hostile characters.
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


@dataclass
class GeneratorOptions:
    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True


def generate_password(opts: GeneratorOptions) -> str:
    if opts.length < 4:
        raise ValueError("length must be at least 4")

    pools: list[str] = []
    if opts.use_upper:
        pools.append(UPPER)
    if opts.use_lower:
        pools.append(LOWER)
    if opts.use_digits:
        pools.append(DIGITS)
    if opts.use_symbols:
        pools.append(SYMBOLS)

    if not pools:
        raise ValueError("at least one character class must be enabled")

    # Guarantee one char from every selected class.
    chars = [secrets.choice(pool) for pool in pools]

    all_chars = "".join(pools)
    chars += [secrets.choice(all_chars) for _ in range(opts.length - len(chars))]

    # Fisher-Yates shuffle using the CSPRNG so class positions aren't predictable.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)
