"""
Data-leak checker via Have I Been Pwned (Phase 5).

Uses the k-Anonymity range API so the full password -- and even its full hash --
never leaves this machine:

    1. Compute SHA-1(password) and uppercase-hex it.
    2. Send ONLY the first 5 hex characters (the "prefix") to the API.
    3. The API returns every hash suffix that shares that prefix, plus a count.
    4. We look for our suffix locally and read its breach count.

Because ~475 hashes share any given 5-char prefix, the server cannot learn which
password was queried. SHA-1 is used here only as HIBP's index -- it is NOT used
anywhere for storing or protecting user passwords (that's Argon2id + AES-GCM).
"""
from __future__ import annotations

import hashlib

import httpx

from config import settings


def _sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def parse_range_response(body: str, suffix: str) -> int:
    """
    Given the API body (lines of 'SUFFIX:COUNT') and our hash suffix, return the
    breach count (0 if not present). Pure function -> easy to unit test offline.
    """
    for line in body.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix.strip().upper() == suffix.upper():
            try:
                return int(count.strip())
            except ValueError:
                return 0
    return 0


async def check_password(password: str, *, client: httpx.AsyncClient | None = None) -> int:
    """
    Return how many times `password` appears in known breaches (0 == not found).

    Only the first 5 characters of the SHA-1 hash are transmitted.
    """
    digest = _sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=10.0)
    try:
        resp = await client.get(
            settings.HIBP_RANGE_URL + prefix,
            headers={"Add-Padding": "true", "User-Agent": "SecureVault"},
        )
        resp.raise_for_status()
        return parse_range_response(resp.text, suffix)
    finally:
        if owns_client:
            await client.aclose()
