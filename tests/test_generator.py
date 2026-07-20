"""Tests for the password generator."""
import string

import pytest

from crypto.generator import GeneratorOptions, generate_password


@pytest.mark.parametrize("length", [16, 20, 24, 32])
def test_length_presets(length):
    pw = generate_password(GeneratorOptions(length=length))
    assert len(pw) == length


def test_includes_each_selected_class():
    pw = generate_password(GeneratorOptions(length=32))
    assert any(c in string.ascii_uppercase for c in pw)
    assert any(c in string.ascii_lowercase for c in pw)
    assert any(c in string.digits for c in pw)


def test_only_selected_classes_used():
    pw = generate_password(GeneratorOptions(
        length=20, use_upper=False, use_symbols=False, use_lower=True, use_digits=True,
    ))
    assert all(c in string.ascii_lowercase + string.digits for c in pw)


def test_no_class_selected_raises():
    with pytest.raises(ValueError):
        generate_password(GeneratorOptions(
            use_upper=False, use_lower=False, use_digits=False, use_symbols=False,
        ))


def test_randomness_produces_distinct_passwords():
    pws = {generate_password(GeneratorOptions(length=24)) for _ in range(50)}
    assert len(pws) == 50  # collisions astronomically unlikely
