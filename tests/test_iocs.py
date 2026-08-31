"""Tests for indicator-of-compromise classification and defanging."""

import pytest

import tool


def test_defang_and_refang_round_trip():
    original = "https://secure-login.example.com/path"
    defanged = tool.defang_value(original)
    assert "https://" not in defanged
    assert "[.]" in defanged
    assert tool.refang_value(defanged) == original


def test_defang_handles_email():
    assert tool.defang_value("admin@example.com") == "admin[@]example[.]com"


def test_classify_ioc_private_ip():
    result = tool.classify_ioc("10.0.0.5")
    assert result["kind"] == "ip"
    assert "private address" in result["reasons"]


def test_classify_ioc_public_ip():
    result = tool.classify_ioc("8.8.8.8")
    assert result["kind"] == "ip"
    assert result["normalized"] == "8.8.8.8"


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ],
)
def test_classify_ioc_hashes(value, kind):
    assert tool.classify_ioc(value)["kind"] == kind


def test_classify_ioc_cleartext_url_is_flagged():
    result = tool.classify_ioc("http://example.com/login")
    assert result["kind"] == "url"
    assert result["severity"] == "medium"
    assert "cleartext URL" in result["reasons"]


def test_classify_ioc_rejects_empty():
    with pytest.raises(ValueError):
        tool.classify_ioc("   ")


def test_ioc_triage_requires_values():
    with pytest.raises(ValueError):
        tool.ioc_triage([])
