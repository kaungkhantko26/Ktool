"""Tests for the password generator's security properties."""

import string

import pytest

import tool


def test_generated_passwords_have_requested_shape():
    values = tool.generate_password_values(length=20, count=5, no_symbols=False, no_ambiguous=False)
    assert len(values) == 5
    assert all(len(value) == 20 for value in values)
    assert len(set(values)) == 5  # no repeats


def test_generated_password_covers_every_character_group():
    values = tool.generate_password_values(length=16, count=25, no_symbols=False, no_ambiguous=False)
    for value in values:
        assert any(c.islower() for c in value)
        assert any(c.isupper() for c in value)
        assert any(c.isdigit() for c in value)
        assert any(not c.isalnum() for c in value)


def test_no_ambiguous_removes_confusable_characters():
    values = tool.generate_password_values(length=40, count=20, no_symbols=True, no_ambiguous=True)
    banned = set("O0oIl1|`'\"")
    for value in values:
        assert banned.isdisjoint(value)


def test_no_symbols_keeps_output_alphanumeric():
    values = tool.generate_password_values(length=24, count=10, no_symbols=True, no_ambiguous=False)
    for value in values:
        assert all(c in string.ascii_letters + string.digits for c in value)


@pytest.mark.parametrize(
    ("length", "count"),
    [(4, 1), (300, 1), (16, 0), (16, 100)],
)
def test_generator_rejects_out_of_bounds(length, count):
    with pytest.raises(ValueError):
        tool.generate_password_values(length=length, count=count, no_symbols=False, no_ambiguous=False)
