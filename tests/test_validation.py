"""Input-validation hardening tests.

These guard against argument injection and control-character smuggling when a
target string is later passed to a wrapped external tool (nmap, gobuster, ...).
"""

import pytest

import tool


@pytest.mark.parametrize(
    "host",
    ["example.com", "sub.example.co.uk", "localhost", "host_name.internal"],
)
def test_validate_host_accepts_normal_hostnames(host):
    assert tool.validate_host(host) == host


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("8.8.8.8", "8.8.8.8"), ("[2001:db8::1]", "2001:db8::1"), ("2001:DB8::1", "2001:db8::1")],
)
def test_validate_host_normalises_ip_literals(raw, expected):
    assert tool.validate_host(raw) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "-oX/tmp/out",        # nmap output-file flag injection
        "--script=vuln",      # nmap script flag injection
        "ex ample.com",       # whitespace splits into extra argv
        "example.com;id",     # shell metacharacter
        "`id`.example.com",   # command substitution
        "ex\x00mple.com",     # NUL byte
        "host\r\nHeader: x",  # CRLF / header injection
        "http://example.com", # URL, not a host
        "10.0.0.0/24",        # CIDR range
        "",
        "   ",
        "a" * 5000,           # oversized
    ],
)
def test_validate_host_rejects_dangerous_input(bad):
    with pytest.raises(ValueError):
        tool.validate_host(bad)


def test_normalize_url_adds_https_scheme():
    assert tool.normalize_url("example.com/app") == "https://example.com/app"


def test_normalize_url_strips_trailing_slash():
    assert tool.normalize_url("https://example.com/") == "https://example.com"


@pytest.mark.parametrize(
    "bad",
    [
        "http://user:pass@evil.example.com",  # embedded credentials
        "ftp://example.com",                  # unsupported scheme
        "https://example.com/\x00",           # NUL byte
        "https://exa mple.com",               # whitespace
        "javascript:alert(1)",
    ],
)
def test_normalize_url_rejects_dangerous_input(bad):
    with pytest.raises(ValueError):
        tool.normalize_url(bad)


def test_run_external_rejects_nul_bytes():
    with pytest.raises(ValueError):
        tool.run_external(["echo", "a\x00b"], timeout=1)


@pytest.mark.parametrize(
    ("value", "count"),
    [("80", [80]), ("common", tool.COMMON_PORTS), ("80,443", [80, 443]), ("20-22", [20, 21, 22])],
)
def test_parse_ports_valid(value, count):
    assert tool.parse_ports(value) == sorted(set(count))


@pytest.mark.parametrize("value", ["0", "70000", "443-1", "-5"])
def test_parse_ports_rejects_out_of_range(value):
    with pytest.raises(ValueError):
        tool.parse_ports(value)
