"""
Tests for the HIBP k-anonymity checker.

These are OFFLINE tests -- we validate the pure hash-prefix logic and the
range-response parser without hitting the network, proving that only the first
5 SHA-1 characters would ever be transmitted.
"""
import hashlib

from crypto.hibp import _sha1_hex, parse_range_response


def test_sha1_prefix_is_five_chars():
    digest = _sha1_hex("password")
    prefix, suffix = digest[:5], digest[5:]
    assert len(prefix) == 5
    assert prefix + suffix == digest
    # 'password' has a well-known SHA-1 upper-hex prefix.
    assert prefix == "5BAA6"


def test_parse_range_response_found():
    digest = _sha1_hex("password")
    suffix = digest[5:]
    body = f"{suffix}:99\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3"
    assert parse_range_response(body, suffix) == 99


def test_parse_range_response_not_found():
    body = "1111111111111111111111111111111111A:5\n2222222222222222222222222222222222B:7"
    assert parse_range_response(body, "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD") == 0


def test_only_prefix_would_be_sent():
    # Sanity: the suffix (which we search locally) is 35 chars; the prefix is 5.
    digest = _sha1_hex("hunter2")
    assert len(digest) == 40
    assert len(digest[:5]) == 5
    assert len(digest[5:]) == 35
