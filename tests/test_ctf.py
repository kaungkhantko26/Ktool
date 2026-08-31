"""Tests for the CTF toolkit (flag hunting, triage, playbook, completion)."""

import pytest

import tool

# --- flag hunting ---------------------------------------------------------

def test_scan_bytes_finds_known_formats():
    data = b"noise flag{abc_123} more HTB{deadbeef} tail"
    hits = tool.scan_bytes_for_flags(data, "unit", tool.CTF_FLAG_PATTERNS)
    found = {hit["flag"] for hit in hits}
    assert "flag{abc_123}" in found
    assert "HTB{deadbeef}" in found


def test_scan_bytes_dedupes_repeats():
    data = b"flag{x} flag{x} flag{x}"
    hits = tool.scan_bytes_for_flags(data, "unit", {"generic": tool.CTF_FLAG_PATTERNS["generic"]})
    assert len(hits) == 1


def test_flag_hunt_over_directory(tmp_path, capsys):
    (tmp_path / "a.txt").write_text("here is flag{find_me}\n")
    (tmp_path / "b.bin").write_bytes(b"\x00\x01THM{binary_flag}\xff")
    result = tool.ctf_flag_hunt(
        path=str(tmp_path), url=None, read_stdin=False, extra_patterns=[],
        broad=False, max_files=100, max_bytes=1_000_000, authorized=False, timeout=1,
    )
    flags = {hit["flag"] for hit in result["flags"]}
    assert "flag{find_me}" in flags
    assert "THM{binary_flag}" in flags


def test_flag_hunt_requires_a_target():
    with pytest.raises(ValueError):
        tool.ctf_flag_hunt(
            path=None, url=None, read_stdin=False, extra_patterns=[],
            broad=False, max_files=1, max_bytes=1, authorized=False, timeout=1,
        )


def test_flag_hunt_url_needs_authorization():
    with pytest.raises(ValueError, match="authorized"):
        tool.ctf_flag_hunt(
            path=None, url="http://example.com", read_stdin=False, extra_patterns=[],
            broad=False, max_files=1, max_bytes=1, authorized=False, timeout=1,
        )


def test_flag_hunt_rejects_bad_custom_pattern(tmp_path):
    with pytest.raises(ValueError):
        tool.ctf_flag_hunt(
            path=str(tmp_path), url=None, read_stdin=False, extra_patterns=["("],
            broad=False, max_files=1, max_bytes=1, authorized=False, timeout=1,
        )


# --- triage --------------------------------------------------------------

def test_entropy_bounds():
    assert tool._shannon_entropy(b"") == 0.0
    assert tool._shannon_entropy(b"a" * 100) == 0.0
    assert tool._shannon_entropy(bytes(range(256))) == pytest.approx(8.0, abs=0.01)


def test_triage_identifies_signatures(tmp_path, capsys):
    (tmp_path / "img.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    (tmp_path / "arc.zip").write_bytes(b"PK\x03\x04" + b"\x00" * 32)
    result = tool.ctf_triage(str(tmp_path), max_files=10, max_bytes=1_000_000)
    by_name = {entry["path"].split("/")[-1]: entry for entry in result["entries"]}
    assert any("PNG" in m for m in by_name["img.png"]["magic"])
    assert any("ZIP" in m for m in by_name["arc.zip"]["magic"])
    assert "steghide" in by_name["img.png"]["suggested_tools"]


def test_triage_missing_path():
    with pytest.raises(ValueError):
        tool.ctf_triage("/no/such/path", max_files=1, max_bytes=1)


# --- playbook / CLI ------------------------------------------------------

def test_playbook_markdown_contains_target_and_moves():
    result = {
        "target": "10.10.10.10",
        "workspace": "engagements/x",
        "web_url": None,
        "ports": [{"port": 445, "state": "open", "service": "microsoft-ds"}],
        "playbook": [{"port": 445, "moves": ["smbclient -L //10.10.10.10/ -N"]}],
        "generic_playbook": ["nmap -p- 10.10.10.10"],
    }
    md = tool.build_ctf_playbook_markdown(result)
    assert "10.10.10.10" in md
    assert "smbclient" in md


def test_service_playbook_is_sane():
    for port, moves in tool.CTF_SERVICE_PLAYBOOK.items():
        assert isinstance(port, int) and 1 <= port <= 65535
        assert moves and all(isinstance(m, str) for m in moves)


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_completion_script_lists_commands(shell):
    script = tool.generate_completion_script(shell)
    assert "ctf" in script
    assert "learn" in script


def test_ctf_subcommands_parse():
    parser = tool.build_parser()
    assert parser.parse_args(["ctf", "flag", "--stdin"]).ctf_command == "flag"
    assert parser.parse_args(["ctf", "box", "1.2.3.4"]).ctf_command == "box"
    assert parser.parse_args(["ctf", "triage", "."]).ctf_command == "triage"
