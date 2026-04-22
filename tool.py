#!/usr/bin/env python3
"""
Ktool - Linux-friendly ethical security assessment template.

Use this tool only on systems you own or have explicit written permission to
test. The active checks here focus on reconnaissance, defensive visibility,
local posture review, and safe web/network assessment. It does not exploit,
bypass authentication, phish users, maintain access, or brute force credentials.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import getpass
import importlib.util
import ipaddress
import json
import math
import os
import platform
import re
import secrets
import shlex
import shutil
import socket
import ssl
import stat
import string
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


COMMON_PORTS = [
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    2376,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    9200,
    9300,
]

DEFAULT_SUBDOMAINS = [
    "www",
    "mail",
    "webmail",
    "ftp",
    "api",
    "dev",
    "test",
    "staging",
    "admin",
    "portal",
    "vpn",
    "cdn",
    "blog",
    "shop",
    "support",
]

DEFAULT_PATHS = [
    "admin",
    "login",
    "dashboard",
    "uploads",
    "assets",
    "static",
    "backup",
    "config",
    ".well-known/security.txt",
    "robots.txt",
    "sitemap.xml",
]

WEB_EXPOSURE_PATHS = [
    ".env",
    ".git/config",
    ".svn/entries",
    "backup.zip",
    "backup.tar.gz",
    "db.sql",
    "database.sql",
    "phpinfo.php",
    "server-status",
    "debug",
    "actuator/env",
    "actuator/health",
    "wp-admin/",
    "wp-login.php",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS for future visits.",
    "Content-Security-Policy": "Helps reduce cross-site scripting impact.",
    "X-Frame-Options": "Helps prevent clickjacking in older browsers.",
    "X-Content-Type-Options": "Helps prevent MIME-sniffing issues.",
    "Referrer-Policy": "Limits sensitive URL data in referrers.",
    "Permissions-Policy": "Restricts powerful browser features.",
}

TOOL_NAME = "Ktool"
TOOL_OWNER = "Ktool owner"
USER_AGENT = "Ktool/2.0 (+authorized-security-testing)"
TERMINAL_WIDTH = 78

PACKAGE_NAMES = {
    "nmap": {"apt": "nmap", "dnf": "nmap", "pacman": "nmap", "brew": "nmap"},
    "ncat": {"apt": "ncat", "dnf": "nmap-ncat", "pacman": "nmap", "brew": "nmap"},
    "nc": {"apt": "netcat-openbsd", "dnf": "nmap-ncat", "pacman": "openbsd-netcat", "brew": "netcat"},
    "whois": {"apt": "whois", "dnf": "whois", "pacman": "whois", "brew": "whois"},
    "tcpdump": {"apt": "tcpdump", "dnf": "tcpdump", "pacman": "tcpdump", "brew": "tcpdump"},
    "nikto": {"apt": "nikto", "dnf": "nikto", "pacman": "nikto", "brew": "nikto"},
    "iw": {"apt": "iw", "dnf": "iw", "pacman": "iw", "brew": "wireless-tools"},
    "nmcli": {"apt": "network-manager", "dnf": "NetworkManager", "pacman": "networkmanager", "brew": "network-manager"},
}

PYTHON_PACKAGES = {
    "scapy": "scapy",
}

SENSITIVE_REPORT_COMMANDS = {"admin-password", "password-generate"}
HTTP_PORTS = {80, 8000, 8080, 8081, 8888}
SUSPICIOUS_DNS_TLDS = {".zip", ".mov", ".top", ".xyz", ".click", ".country", ".gq", ".tk"}
SUSPICIOUS_DOMAIN_MARKERS = {
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "wallet",
    "free",
    "bonus",
    "auth",
}
DYNAMIC_DNS_MARKERS = {
    "duckdns.org",
    "no-ip.",
    "dyndns.",
    "hopto.org",
    "ddns.net",
    "serveo.net",
}
SUSPICIOUS_PORTS = {
    23: "telnet cleartext admin",
    2323: "alternate telnet",
    4444: "common reverse shell handler",
    5555: "common adb/reverse shell port",
    6667: "irc/botnet control channel",
    1337: "common backdoor port",
    31337: "common backdoor port",
    3389: "remote desktop exposure",
    5900: "vnc exposure",
}
HIGH_RISK_LISTEN_PORTS = {21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200}
LOG_PATTERNS = [
    ("high", "auth failure", re.compile(r"(failed password|authentication failure|invalid user|login failed)", re.I)),
    ("medium", "successful remote login", re.compile(r"(accepted password|accepted publickey|session opened)", re.I)),
    ("medium", "sudo usage", re.compile(r"\bsudo\b|COMMAND=", re.I)),
    ("high", "web attack pattern", re.compile(r"(\.\./|/etc/passwd|union select|<script|%3cscript|cmd=|powershell|/bin/sh|/bin/bash)", re.I)),
    ("medium", "scanner signature", re.compile(r"(nmap|nikto|sqlmap|masscan|zgrab|acunetix|nessus|openvas)", re.I)),
    ("high", "malware staging hint", re.compile(r"(curl .*\|.*sh|wget .*\|.*sh|chmod \+x|/tmp/[^ ]+\.sh)", re.I)),
]


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def color(text: str, code: str) -> str:
    if not supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def cyber_line(label: str, value: str = "", status: str = "*") -> None:
    marker = color(f"[{status}]", "1;32")
    if value:
        print(f"{marker} {color(label.ljust(24), '36')} {value}")
    else:
        print(f"{marker} {color(label, '36')}")


def print_section(title: str) -> None:
    text = f" {title.upper()} "
    if supports_color():
        left = "═" * max(2, (TERMINAL_WIDTH - len(text)) // 2)
        right = "═" * max(2, TERMINAL_WIDTH - len(text) - len(left))
        print(color(f"\n{left}{text}{right}", "1;32"))
    else:
        print(f"\n=== {title} ===")


def print_key_value_table(rows: list[tuple[str, str]]) -> None:
    if not rows:
        return
    width = max(len(key) for key, _ in rows)
    for key, value in rows:
        print(f"  {color(key.ljust(width), '36')} : {value}")


def print_exit_screen(reason: str = "Session closed", exit_code: int = 0) -> None:
    title = "Ktool Security Console"
    lines = [
        title,
        f"Built by: {TOOL_OWNER}",
        "",
        reason,
        "No tasks are still running.",
        "Ktool session complete. Keep authorization documented.",
        "",
        f"Exit code: {exit_code}",
    ]
    width = max(len(line) for line in lines) + 4
    border = "+" + "-" * width + "+"

    print()
    print(color(border, "36"))
    for index, line in enumerate(lines):
        if index == 0:
            rendered = color(line.center(width), "1;36")
        elif line.startswith("Exit code:"):
            rendered = color(line.ljust(width), "90")
        else:
            rendered = line.ljust(width)
        print(color("|", "36") + rendered + color("|", "36"))
    print(color(border, "36"))


def print_startup_banner() -> None:
    banner = r"""
██╗  ██╗████████╗ ██████╗  ██████╗ ██╗
██║ ██╔╝╚══██╔══╝██╔═══██╗██╔═══██╗██║
█████╔╝    ██║   ██║   ██║██║   ██║██║
██╔═██╗    ██║   ██║   ██║██║   ██║██║
██║  ██╗   ██║   ╚██████╔╝╚██████╔╝███████╗
╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
"""
    print(color(banner.rstrip(), "1;32"))
    print(color("        ops console // authorized cyber workbench", "36"))
    print(color(f"        built by: {TOOL_OWNER}", "36"))
    print(color("        scan | sniff | audit | message | report", "90"))
    print(color("        authorization required for target activity", "90"))


def print_menu_panel() -> None:
    menu_items = [
        ("1", "Learning Roadmap"),
        ("2", "Tool Availability Check"),
        ("3", "DNS Lookup"),
        ("4", "WHOIS Lookup"),
        ("5", "TCP Port Scanner"),
        ("6", "Subdomain Resolver"),
        ("7", "HTTP Header Analyzer"),
        ("8", "Common Path Checker"),
        ("9", "Safe Web Baseline"),
        ("10", "Conservative nmap Scan"),
        ("11", "LAN Device Scanner"),
        ("12", "Scapy Packet Sniffer"),
        ("13", "Password Strength Check"),
        ("14", "Password Generator"),
        ("15", "ncat Port Messenger"),
        ("16", "Admin Password Generator"),
        ("17", "Run Ktool as Root"),
        ("18", "Permission Guide"),
        ("19", "Password Policy Audit"),
        ("20", "Packet Capture Sample"),
        ("21", "Wireless Interface Info"),
        ("22", "Vulnerability Lookup"),
        ("23", "Awareness Plan"),
        ("24", "Local Posture Review"),
        ("25", "Install Hints"),
        ("26", "Install Tool"),
        ("27", "Web Vulnerability Search"),
        ("28", "Live Connection Watch"),
        ("29", "Log Watch"),
        ("30", "IOC Triage"),
        ("31", "Authorized Live Workflow"),
        ("32", "Exit"),
    ]
    width = 54
    border = "+" + "-" * width + "+"
    print()
    print(color(border, "32"))
    print(color("|", "32") + color(" KTOOL OPS CONSOLE ".center(width), "1;32") + color("|", "32"))
    print(color("|", "32") + color(" defensive systems only ".center(width), "90") + color("|", "32"))
    print(color(border, "32"))
    for number, label in menu_items:
        line = f" [{number.rjust(2)}] {label}"
        print(color("|", "32") + line.ljust(width) + color("|", "32"))
    print(color(border, "32"))


TOOL_CATEGORIES = {
    "recon": {
        "title": "Reconnaissance",
        "skills": ["DNS lookup", "WHOIS lookup", "Subdomain discovery"],
        "tools": ["whois", "nslookup", "theHarvester", "amass", "sublist3r"],
        "implemented": ["dns", "whois", "subs"],
    },
    "scan": {
        "title": "Scanning and Enumeration",
        "skills": ["TCP scanning", "Service detection", "Basic web exposure checks"],
        "tools": ["nmap", "masscan", "nc", "nikto"],
        "implemented": ["ports", "nmap"],
    },
    "web": {
        "title": "Web Application Testing",
        "skills": ["Security headers", "Common path discovery", "Proxy-based manual testing"],
        "tools": ["burpsuite", "zaproxy", "sqlmap", "ffuf", "nikto", "searchsploit"],
        "implemented": ["headers", "dirs", "web", "web-vuln-search"],
    },
    "passwords": {
        "title": "Password Security Testing",
        "skills": ["Password audit policy", "Weak password review", "Strong password generation"],
        "tools": ["john", "hashcat"],
        "implemented": ["password-audit", "password-check", "password-generate", "admin-password"],
    },
    "network": {
        "title": "Network Security Testing",
        "skills": ["TCP/IP", "Ports", "Firewalls", "VPNs", "Packet capture", "LAN inventory"],
        "tools": ["wireshark", "tcpdump", "scapy", "ncat", "nc"],
        "implemented": [
            "capture",
            "scapy-sniff",
            "lan-scan",
            "ncat-chat",
            "conn-watch",
            "log-watch",
            "ioc-triage",
            "live-workflow",
            "sudo-su",
            "permission-guide",
            "tools",
        ],
    },
    "wireless": {
        "title": "Wireless Security",
        "skills": ["WiFi audit on owned networks only", "Capture analysis"],
        "tools": ["aircrack-ng", "airodump-ng", "kismet", "iw", "nmcli"],
        "implemented": ["wireless-info", "tools"],
    },
    "exploitation": {
        "title": "Exploitation Research",
        "skills": ["Lab validation", "Vulnerability research", "Patch verification"],
        "tools": ["msfconsole", "searchsploit"],
        "implemented": ["vuln-lookup"],
    },
    "awareness": {
        "title": "Social Engineering Awareness",
        "skills": ["Phishing awareness", "Training campaign review"],
        "tools": ["setoolkit"],
        "implemented": ["awareness-plan"],
    },
    "post": {
        "title": "Post-Exploitation Defense Review",
        "skills": ["Privilege escalation concepts", "Incident response perspective"],
        "tools": ["linpeas", "winpeas"],
        "implemented": ["local-posture"],
    },
}

TOOL_ALIASES = {
    "burpsuite": ["burpsuite", "burp-suite", "BurpSuiteCommunity"],
    "zaproxy": ["zaproxy", "owasp-zap", "zap"],
    "sublist3r": ["sublist3r", "Sublist3r"],
    "aircrack-ng": ["aircrack-ng"],
    "airodump-ng": ["airodump-ng"],
    "msfconsole": ["msfconsole"],
    "setoolkit": ["setoolkit", "setoolkit-launcher"],
    "theHarvester": ["theHarvester", "theharvester"],
    "linpeas": ["linpeas", "linpeas.sh"],
    "nikto": ["nikto", "nikto.pl"],
    "ncat": ["ncat", "nc"],
    "nc": ["nc", "ncat", "netcat"],
}

INSTALL_HINTS = {
    "scapy": {
        "Python": "python3 -m pip install --user scapy",
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install python3-scapy",
        "Fedora": "sudo dnf install python3-scapy",
        "Arch": "sudo pacman -S python-scapy",
    },
    "ncat": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install ncat",
        "Arch": "sudo pacman -S nmap",
        "Fedora": "sudo dnf install nmap-ncat",
        "macOS": "brew install nmap",
    },
    "searchsploit": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install exploitdb",
        "Arch": "sudo pacman -S exploitdb",
        "Fedora": "sudo dnf install exploitdb",
        "After install": "searchsploit -u",
    },
    "nmap": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install nmap",
        "Arch": "sudo pacman -S nmap",
        "Fedora": "sudo dnf install nmap",
        "macOS": "brew install nmap",
    },
    "whois": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install whois",
        "Arch": "sudo pacman -S whois",
        "Fedora": "sudo dnf install whois",
    },
    "tcpdump": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install tcpdump",
        "Arch": "sudo pacman -S tcpdump",
        "Fedora": "sudo dnf install tcpdump",
    },
    "nikto": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install nikto",
        "Arch": "sudo pacman -S nikto",
        "Fedora": "sudo dnf install nikto",
    },
    "iw": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install iw",
        "Arch": "sudo pacman -S iw",
        "Fedora": "sudo dnf install iw",
    },
    "nmcli": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install network-manager",
        "Arch": "sudo pacman -S networkmanager",
        "Fedora": "sudo dnf install NetworkManager",
    },
}


@dataclass
class PortResult:
    port: int
    state: str
    service: str | None = None


@dataclass
class SubdomainResult:
    host: str
    addresses: list[str]


@dataclass
class HeaderResult:
    url: str
    status: int | None
    headers: dict[str, str]
    missing_security_headers: list[str]
    error: str | None = None


@dataclass
class DirectoryResult:
    url: str
    status: int | None
    length: int | None = None
    error: str | None = None


def require_authorization(assume_yes: bool) -> None:
    if assume_yes:
        return

    print()
    print(color("[authorization]", "1;33"))
    print("Only scan systems you own or have explicit permission to test.")
    answer = input("Do you have authorization to continue? [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        print_exit_screen("Authorization was not confirmed.", 1)
        raise SystemExit(1)


def normalize_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = f"https://{raw_url}"
        parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid URL: {raw_url}")
    return raw_url.rstrip("/")


def validate_host(host: str) -> str:
    host = host.strip()
    if not host:
        raise ValueError("Target host cannot be empty.")
    if "/" in host:
        raise ValueError("Use a hostname or IP address, not a URL or CIDR range.")
    return host


def parse_ports(value: str) -> list[int]:
    if value == "common":
        return COMMON_PORTS

    ports: set[int] = set()
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Invalid port range: {chunk}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError(f"Ports must be between 1 and 65535: {invalid}")
    return sorted(ports)


def load_words(path: str | None, defaults: list[str]) -> list[str]:
    if not path:
        return defaults

    wordlist = Path(path)
    words = [
        line.strip()
        for line in wordlist.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not words:
        raise ValueError(f"Wordlist is empty: {path}")
    return words


def socket_family(target: str) -> socket.AddressFamily:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return socket.AF_UNSPEC
    return socket.AF_INET6 if ip.version == 6 else socket.AF_INET


def scan_port(target: str, port: int, timeout: float) -> PortResult | None:
    try:
        for family, socktype, proto, _, sockaddr in socket.getaddrinfo(
            target,
            port,
            family=socket_family(target),
            type=socket.SOCK_STREAM,
        ):
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex(sockaddr)
                if result == 0:
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except OSError:
                        service = None
                    return PortResult(port=port, state="open", service=service)
    except socket.gaierror:
        raise ValueError(f"Could not resolve target: {target}") from None
    except OSError:
        return None
    return None


def port_scanner(
    target: str,
    ports: list[int],
    timeout: float,
    workers: int,
    delay: float,
) -> list[PortResult]:
    target = validate_host(target)
    print(f"\n[+] Scanning {target} ({len(ports)} TCP ports)")

    results: list[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {}
        for port in ports:
            future = executor.submit(scan_port, target, port, timeout)
            future_map[future] = port
            if delay:
                time.sleep(delay)

        for future in concurrent.futures.as_completed(future_map):
            result = future.result()
            if result:
                results.append(result)
                service = f" ({result.service})" if result.service else ""
                print(f"[OPEN] {result.port}/tcp{service}")

    if not results:
        print("[i] No open ports found in the selected range.")
    return sorted(results, key=lambda item: item.port)


def subdomain_finder(domain: str, words: list[str]) -> list[SubdomainResult]:
    domain = validate_host(domain).removeprefix("*.").strip(".")
    print(f"\n[+] Resolving common subdomains for {domain}")

    results: list[SubdomainResult] = []
    for subdomain in words:
        host = f"{subdomain.strip('.')}.{domain}"
        try:
            _, _, addresses = socket.gethostbyname_ex(host)
        except socket.gaierror:
            continue
        unique_addresses = sorted(set(addresses))
        results.append(SubdomainResult(host=host, addresses=unique_addresses))
        print(f"[FOUND] {host} -> {', '.join(unique_addresses)}")

    if not results:
        print("[i] No subdomains resolved from the selected wordlist.")
    return results


def resolve_dns(domain: str) -> dict[str, object]:
    domain = validate_host(domain).strip(".")
    print(f"\n[+] DNS lookup for {domain}")

    records: dict[str, object] = {"host": domain, "addresses": []}
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError(f"DNS resolution failed for {domain}: {error}") from None

    addresses = sorted({info[4][0] for info in infos})
    records["addresses"] = addresses
    for address in addresses:
        print(f"[A/AAAA] {address}")

    nslookup = find_tool("nslookup")
    if nslookup:
        result = run_external([nslookup, domain], timeout=10)
        records["nslookup"] = result.stdout
        if result.stdout.strip():
            print("\n[nslookup]")
            print(result.stdout.strip())
    else:
        print("\n[i] nslookup is not installed; showing Python resolver results only.")

    return records


def whois_lookup(
    domain: str,
    timeout: float,
    install_missing: bool = False,
    package_manager: str | None = None,
) -> dict[str, object]:
    domain = validate_host(domain).strip(".")
    whois_path = ensure_tool("whois", auto_install=install_missing, manager=package_manager)
    if not whois_path:
        raise ValueError("whois is not installed. Rerun with --install-missing or install it first.")

    print(f"\n[+] WHOIS lookup for {domain}")
    result = run_external([whois_path, domain], timeout=timeout)
    output = result.stdout.strip()
    if output:
        print(output)
    if result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)
    return {
        "domain": domain,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def http_request(url: str, method: str = "GET", timeout: float = 5.0) -> tuple[int, dict[str, str], bytes]:
    context = ssl.create_default_context()
    request = Request(url, method=method, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(1024 * 128)
            return response.status, dict(response.headers.items()), body
    except HTTPError as error:
        body = error.read(1024 * 128)
        return error.code, dict(error.headers.items()), body
    except URLError as error:
        reason = getattr(error, "reason", error)
        raise ConnectionError(str(reason)) from error


def header_analyzer(url: str, timeout: float) -> HeaderResult:
    normalized = normalize_url(url)
    print(f"\n[+] Analyzing HTTP headers for {normalized}")

    try:
        status, headers, _ = http_request(normalized, method="GET", timeout=timeout)
    except ConnectionError as error:
        print(f"[ERROR] {error}")
        return HeaderResult(
            url=normalized,
            status=None,
            headers={},
            missing_security_headers=[],
            error=str(error),
        )

    normalized_headers = {key.lower(): value for key, value in headers.items()}
    missing = [
        header
        for header in SECURITY_HEADERS
        if header.lower() not in normalized_headers
    ]

    print(f"[STATUS] HTTP {status}")
    for key, value in sorted(headers.items()):
        print(f"{key}: {value}")

    if missing:
        print("\n[!] Missing common security headers:")
        for header in missing:
            print(f"    - {header}: {SECURITY_HEADERS[header]}")
    else:
        print("\n[OK] Common security headers are present.")

    return HeaderResult(
        url=normalized,
        status=status,
        headers=headers,
        missing_security_headers=missing,
    )


def directory_scanner(
    url: str,
    paths: list[str],
    timeout: float,
    delay: float,
    show_all: bool,
) -> list[DirectoryResult]:
    base_url = normalize_url(url)
    print(f"\n[+] Checking common paths on {base_url}")

    results: list[DirectoryResult] = []
    for raw_path in paths:
        path = raw_path.strip().lstrip("/")
        if not path:
            continue
        full_url = f"{base_url}/{path}"
        try:
            status, _, body = http_request(full_url, method="GET", timeout=timeout)
            result = DirectoryResult(url=full_url, status=status, length=len(body))
        except ConnectionError as error:
            result = DirectoryResult(url=full_url, status=None, error=str(error))

        if show_all or (result.status is not None and result.status < 400):
            if result.status is None:
                print(f"[ERROR] {full_url} -> {result.error}")
            else:
                print(f"[{result.status}] {full_url} ({result.length} bytes sampled)")
        results.append(result)

        if delay:
            time.sleep(delay)

    interesting = [item for item in results if item.status is not None and item.status < 400]
    if not interesting:
        print("[i] No accessible paths found from the selected wordlist.")
    return results


def web_baseline(url: str, timeout: float, delay: float) -> dict[str, object]:
    print("\n[+] Running safe web baseline checks")
    headers = header_analyzer(url, timeout=timeout)
    paths = directory_scanner(
        url,
        paths=DEFAULT_PATHS,
        timeout=timeout,
        delay=delay,
        show_all=False,
    )
    return {"headers": asdict(headers), "paths": [asdict(path) for path in paths]}


def extract_web_technologies(headers: dict[str, str], body: bytes) -> list[str]:
    technologies: set[str] = set()
    for header_name in ("Server", "X-Powered-By", "X-Generator"):
        value = headers.get(header_name)
        if value:
            technologies.add(value.strip())

    text = body.decode("utf-8", errors="ignore")[:50000]
    generator_match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        text,
        re.IGNORECASE,
    )
    if generator_match:
        technologies.add(generator_match.group(1).strip())

    known_markers = {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "Drupal.settings": "Drupal",
        "Joomla!": "Joomla",
        "content=\"Wix": "Wix",
        "Shopify.theme": "Shopify",
        "laravel_session": "Laravel",
        "Django": "Django",
    }
    lower_text = text.lower()
    for marker, technology in known_markers.items():
        if marker.lower() in lower_text:
            technologies.add(technology)

    return sorted(technologies)


def analyze_cookie_flags(headers: dict[str, str], scheme: str) -> list[dict[str, object]]:
    issues: list[dict[str, object]] = []
    cookie_headers = [
        value
        for key, value in headers.items()
        if key.lower() == "set-cookie"
    ]
    for cookie_header in cookie_headers:
        cookie_name = cookie_header.split("=", 1)[0].strip()
        lower_cookie = cookie_header.lower()
        missing: list[str] = []
        if scheme == "https" and "secure" not in lower_cookie:
            missing.append("Secure")
        if "httponly" not in lower_cookie:
            missing.append("HttpOnly")
        if "samesite" not in lower_cookie:
            missing.append("SameSite")
        if missing:
            issues.append({"cookie": cookie_name, "missing_flags": missing})
    return issues


def check_http_methods(url: str, timeout: float) -> dict[str, object]:
    try:
        status, headers, _ = http_request(url, method="OPTIONS", timeout=timeout)
    except ConnectionError as error:
        return {"status": None, "allow": [], "risky": [], "error": str(error)}

    allow_header = headers.get("Allow", "")
    allowed = sorted({method.strip().upper() for method in allow_header.split(",") if method.strip()})
    risky = sorted(set(allowed) & {"DELETE", "PUT", "TRACE", "CONNECT"})
    return {"status": status, "allow": allowed, "risky": risky}


def searchsploit_metadata(queries: list[str], timeout: float) -> list[dict[str, object]]:
    searchsploit_path = find_tool("searchsploit")
    if not searchsploit_path:
        print("[i] searchsploit is not installed; skipping Exploit-DB metadata search.")
        print(install_hint_text("searchsploit"))
        return []

    results: list[dict[str, object]] = []
    for query in queries:
        command = [searchsploit_path, "--colour", "never", query]
        result = run_external(command, timeout=timeout)
        output_lines = result.stdout.strip().splitlines()
        preview = "\n".join(output_lines[:30])
        print(f"\n[searchsploit] {query}")
        print(preview if preview else "No local Exploit-DB metadata matches.")
        if len(output_lines) > 30:
            print(f"[i] Output truncated, {len(output_lines) - 30} more lines in JSON report.")
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        results.append(
            {
                "query": query,
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
    return results


def run_nikto(url: str, timeout: float) -> dict[str, object]:
    nikto_path = find_tool("nikto")
    if not nikto_path:
        print("[i] nikto is not installed; skipping Nikto scan.")
        print(install_hint_text("nikto"))
        return {"installed": False}

    command = [nikto_path, "-host", url, "-nointeractive"]
    print(f"\n[+] Running Nikto: {' '.join(command)}")
    print("[i] Nikto is an active web scanner. Use it only on authorized targets.")
    result = run_external(command, timeout=timeout)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)
    return {
        "installed": True,
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def web_vulnerability_search(
    url: str,
    timeout: float,
    delay: float,
    use_searchsploit: bool,
    use_nikto: bool,
    nikto_timeout: float,
) -> dict[str, object]:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    print(f"\n[+] Web vulnerability search for {normalized}")
    print("[i] This checks metadata and common misconfigurations; it does not exploit vulnerabilities.")

    status, headers, body = http_request(normalized, method="GET", timeout=timeout)
    missing_headers = [
        header
        for header in SECURITY_HEADERS
        if header.lower() not in {key.lower() for key in headers}
    ]
    technologies = extract_web_technologies(headers, body)
    cookie_issues = analyze_cookie_flags(headers, parsed.scheme)
    method_result = check_http_methods(normalized, timeout=timeout)
    exposure_results = directory_scanner(
        normalized,
        paths=WEB_EXPOSURE_PATHS,
        timeout=timeout,
        delay=delay,
        show_all=False,
    )
    exposed_paths = [
        asdict(result)
        for result in exposure_results
        if result.status is not None and result.status < 400
    ]

    findings: list[dict[str, object]] = []
    for header in missing_headers:
        findings.append({"severity": "medium", "type": "missing_security_header", "detail": header})
    for issue in cookie_issues:
        findings.append({"severity": "medium", "type": "cookie_flags", "detail": issue})
    for method in method_result.get("risky", []):
        findings.append({"severity": "high", "type": "risky_http_method", "detail": method})
    for exposed in exposed_paths:
        findings.append({"severity": "high", "type": "exposed_sensitive_path", "detail": exposed["url"]})

    print(f"\n[STATUS] HTTP {status}")
    if technologies:
        print("[TECH] " + ", ".join(technologies))
    else:
        print("[TECH] No obvious framework/server fingerprint beyond headers.")

    if findings:
        print("\n[Potential issues]")
        for finding in findings:
            print(f"[{finding['severity'].upper()}] {finding['type']}: {finding['detail']}")
    else:
        print("\n[OK] No obvious baseline web issues found.")

    exploitdb_results: list[dict[str, object]] = []
    if use_searchsploit and technologies:
        queries = technologies[:5]
        exploitdb_results = searchsploit_metadata(queries, timeout=timeout)
    elif use_searchsploit:
        print("[i] No technologies found for searchsploit queries.")

    nikto_result: dict[str, object] | None = None
    if use_nikto:
        nikto_result = run_nikto(normalized, timeout=nikto_timeout)

    return {
        "url": normalized,
        "status": status,
        "headers": headers,
        "technologies": technologies,
        "missing_security_headers": missing_headers,
        "cookie_issues": cookie_issues,
        "http_methods": method_result,
        "exposed_paths": exposed_paths,
        "findings": findings,
        "searchsploit": exploitdb_results,
        "nikto": nikto_result,
    }


def find_tool(tool: str) -> str | None:
    candidates = TOOL_ALIASES.get(tool, [tool])
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def install_hint_text(tool: str) -> str:
    hints = INSTALL_HINTS.get(tool)
    if not hints:
        return f"No install hint is available for {tool}."

    lines = [f"{tool} install hints:"]
    for distro, command in hints.items():
        lines.append(f"  {distro}: {command}")
    return "\n".join(lines)


def print_install_hints(tool: str | None = None) -> dict[str, object]:
    selected = [tool] if tool else sorted(INSTALL_HINTS)
    unknown = [name for name in selected if name not in INSTALL_HINTS]
    if unknown:
        raise ValueError(f"No install hint available for: {', '.join(unknown)}")

    payload: dict[str, object] = {}
    print("\n[+] Install hints")
    for name in selected:
        payload[name] = INSTALL_HINTS[name]
        print()
        print(install_hint_text(name))
    return payload


def run_external(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(f"Command timed out after {timeout}s: {' '.join(command)}") from error
    except OSError as error:
        return subprocess.CompletedProcess(
            args=command,
            returncode=126,
            stdout="",
            stderr=str(error),
        )


def detect_package_manager() -> str | None:
    for manager in ("apt", "dnf", "pacman", "brew"):
        if shutil.which(manager):
            return manager
    return None


def install_command_for(tool: str, manager: str | None = None) -> list[str]:
    selected_manager = manager or detect_package_manager()
    if not selected_manager:
        raise ValueError("No supported package manager found. Supported: apt, dnf, pacman, brew.")

    package = PACKAGE_NAMES.get(tool, {}).get(selected_manager)
    if not package:
        raise ValueError(f"No package mapping for {tool!r} with {selected_manager}.")

    if selected_manager == "apt":
        return ["sudo", "apt", "install", "-y", package]
    if selected_manager == "dnf":
        return ["sudo", "dnf", "install", "-y", package]
    if selected_manager == "pacman":
        return ["sudo", "pacman", "-S", "--noconfirm", package]
    if selected_manager == "brew":
        return ["brew", "install", package]
    raise ValueError(f"Unsupported package manager: {selected_manager}")


def install_system_tool(tool: str, manager: str | None, execute: bool) -> dict[str, object]:
    command = install_command_for(tool, manager=manager)
    print_section("Installer")
    cyber_line("tool", tool)
    cyber_line("package manager", manager or detect_package_manager() or "unknown")
    cyber_line("command", " ".join(command))

    if not execute:
        print("[i] Dry run only. Add --execute to run the installer.")
        return {"tool": tool, "command": command, "executed": False}

    print("[i] Installing missing dependency. You may be asked for your sudo password.")
    result = run_external(command, timeout=900)
    output = result.stdout.strip() or result.stderr.strip()
    if output:
        print(output)
    return {
        "tool": tool,
        "command": command,
        "executed": True,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "path_after_install": find_tool(tool),
    }


def ensure_tool(tool: str, auto_install: bool = False, manager: str | None = None) -> str | None:
    path = find_tool(tool)
    if path:
        return path

    if not auto_install:
        return None

    install_system_tool(tool, manager=manager, execute=True)
    return find_tool(tool)


def ensure_python_package(module: str, auto_install: bool = False) -> bool:
    if importlib.util.find_spec(module):
        return True

    package = PYTHON_PACKAGES.get(module, module)
    print(f"[missing] Python package {module}")
    if not auto_install:
        print(install_hint_text(module))
        return False

    command = [sys.executable, "-m", "pip", "install", "--user", package]
    print(f"[+] Installing Python package: {' '.join(command)}")
    result = run_external(command, timeout=900)
    output = result.stdout.strip() or result.stderr.strip()
    if output:
        print(output)
    return importlib.util.find_spec(module) is not None


def nmap_scan(
    target: str,
    top_ports: int,
    timeout: float,
    scripts: bool,
    os_detect: bool,
    install_missing: bool = False,
    package_manager: str | None = None,
) -> dict[str, object]:
    target = validate_host(target)
    nmap_path = ensure_tool("nmap", auto_install=install_missing, manager=package_manager)
    if not nmap_path:
        raise ValueError("nmap is not installed. Rerun with --install-missing or install it first.")
    if top_ports < 1 or top_ports > 1000:
        raise ValueError("--top-ports must be between 1 and 1000.")

    command = [
        nmap_path,
        "-sV",
        "-T3",
        "--top-ports",
        str(top_ports),
        target,
    ]
    if scripts:
        command.insert(1, "-sC")
    if os_detect:
        command.insert(1, "-O")

    print(f"\n[+] Running nmap: {' '.join(command)}")
    print("[i] Use this only on authorized targets. OS detection may require root privileges.")
    result = run_external(command, timeout=timeout)

    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)
        print_permission_hint_if_needed(result.stderr, "tcpdump packet capture")

    return {
        "target": target,
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def password_audit(
    path: str,
    min_length: int,
    require_upper: bool,
    require_lower: bool,
    require_digit: bool,
    require_symbol: bool,
    show_values: bool,
) -> dict[str, object]:
    wordlist = Path(path)
    if not wordlist.exists():
        raise ValueError(f"Password file not found: {path}")
    if min_length < 1:
        raise ValueError("--min-length must be at least 1.")

    print(f"\n[+] Auditing password candidates in {wordlist}")
    print("[i] This checks policy strength only; it does not attempt logins or crack hashes.")

    total = 0
    weak: list[dict[str, object]] = []
    common_values = {
        "password",
        "password1",
        "admin",
        "admin123",
        "qwerty",
        "letmein",
        "welcome",
        "123456",
        "12345678",
        "changeme",
    }

    for line_number, raw_line in enumerate(wordlist.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        password = raw_line.strip()
        if not password or password.startswith("#"):
            continue

        total += 1
        reasons: list[str] = []
        if len(password) < min_length:
            reasons.append(f"shorter than {min_length}")
        if require_upper and not any(char.isupper() for char in password):
            reasons.append("missing uppercase")
        if require_lower and not any(char.islower() for char in password):
            reasons.append("missing lowercase")
        if require_digit and not any(char.isdigit() for char in password):
            reasons.append("missing digit")
        if require_symbol and not any(not char.isalnum() for char in password):
            reasons.append("missing symbol")
        if password.lower() in common_values:
            reasons.append("common password")
        if len(set(password)) <= 2 and len(password) >= 4:
            reasons.append("low character variety")

        if reasons:
            entry: dict[str, object] = {"line": line_number, "reasons": reasons}
            if show_values:
                entry["value"] = password
            weak.append(entry)

    print(f"[SUMMARY] Checked {total} password candidates.")
    print(f"[SUMMARY] Weak candidates: {len(weak)}")
    for entry in weak[:25]:
        label = f"line {entry['line']}"
        if show_values and "value" in entry:
            label += f" ({entry['value']})"
        print(f"[WEAK] {label}: {', '.join(entry['reasons'])}")
    if len(weak) > 25:
        print(f"[i] Showing first 25 weak candidates out of {len(weak)}.")

    return {
        "file": str(wordlist),
        "checked": total,
        "weak_count": len(weak),
        "weak": weak,
        "policy": {
            "min_length": min_length,
            "require_upper": require_upper,
            "require_lower": require_lower,
            "require_digit": require_digit,
            "require_symbol": require_symbol,
        },
    }


def password_strength(password: str, show_value: bool = False) -> dict[str, object]:
    if not password:
        raise ValueError("Password cannot be empty.")

    charsets = 0
    if any(char.islower() for char in password):
        charsets += 26
    if any(char.isupper() for char in password):
        charsets += 26
    if any(char.isdigit() for char in password):
        charsets += 10
    if any(char in string.punctuation for char in password):
        charsets += len(string.punctuation)
    if any(not char.isascii() for char in password):
        charsets += 64

    entropy = len(password) * math.log2(max(charsets, 1))
    lowered = password.lower()
    reasons: list[str] = []
    common_values = {
        "password",
        "password1",
        "admin",
        "admin123",
        "qwerty",
        "letmein",
        "welcome",
        "123456",
        "12345678",
        "changeme",
    }

    if len(password) < 12:
        reasons.append("shorter than 12 characters")
    if lowered in common_values:
        reasons.append("common password")
    if re.search(r"(.)\1{2,}", password):
        reasons.append("repeated characters")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)", lowered):
        reasons.append("keyboard or sequential pattern")
    if not any(char.isupper() for char in password):
        reasons.append("missing uppercase")
    if not any(char.islower() for char in password):
        reasons.append("missing lowercase")
    if not any(char.isdigit() for char in password):
        reasons.append("missing digit")
    if not any(not char.isalnum() for char in password):
        reasons.append("missing symbol")

    if entropy >= 90 and len(reasons) <= 1:
        rating = "strong"
    elif entropy >= 65 and len(reasons) <= 2:
        rating = "good"
    elif entropy >= 45:
        rating = "fair"
    else:
        rating = "weak"

    print_section("Password Strength")
    cyber_line("rating", rating.upper())
    cyber_line("estimated entropy", f"{entropy:.1f} bits")
    cyber_line("length", str(len(password)))
    if reasons:
        print("[findings]")
        for reason in reasons:
            print(f"  - {reason}")
    else:
        print("[OK] No obvious local policy issues found.")

    result: dict[str, object] = {
        "rating": rating,
        "entropy_bits": round(entropy, 1),
        "length": len(password),
        "findings": reasons,
    }
    if show_value:
        result["value"] = password
    return result


def generate_password_values(
    length: int,
    count: int,
    no_symbols: bool,
    no_ambiguous: bool,
) -> list[str]:
    if length < 8 or length > 256:
        raise ValueError("--length must be between 8 and 256.")
    if count < 1 or count > 50:
        raise ValueError("--count must be between 1 and 50.")

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.?/"
    if no_ambiguous:
        ambiguous = set("O0oIl1|`'\"")
        lowercase = "".join(char for char in lowercase if char not in ambiguous)
        uppercase = "".join(char for char in uppercase if char not in ambiguous)
        digits = "".join(char for char in digits if char not in ambiguous)
        symbols = "".join(char for char in symbols if char not in ambiguous)

    groups = [lowercase, uppercase, digits]
    if not no_symbols:
        groups.append(symbols)
    alphabet = "".join(groups)
    if length < len(groups):
        raise ValueError("--length is too short for the selected character groups.")

    generated: list[str] = []
    for _ in range(count):
        required = [secrets.choice(group) for group in groups]
        remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
        chars = required + remaining
        secrets.SystemRandom().shuffle(chars)
        generated.append("".join(chars))
    return generated


def generate_password(
    length: int,
    count: int,
    no_symbols: bool,
    no_ambiguous: bool,
) -> dict[str, object]:
    generated = generate_password_values(
        length=length,
        count=count,
        no_symbols=no_symbols,
        no_ambiguous=no_ambiguous,
    )

    print_section("Password Generator")
    for value in generated:
        print(value)
    return {
        "length": length,
        "count": count,
        "symbols": not no_symbols,
        "ambiguous_removed": no_ambiguous,
        "passwords": generated,
    }


def write_secret_file(path: str, content: str) -> str:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(output_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    output_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return str(output_path)


def admin_password(
    username: str,
    length: int,
    rotate_after_days: int,
    output: str | None,
    no_symbols: bool,
    no_ambiguous: bool,
) -> dict[str, object]:
    username = username.strip() or "admin"
    if rotate_after_days < 1 or rotate_after_days > 365:
        raise ValueError("--rotate-after-days must be between 1 and 365.")

    generated = generate_password_values(
        length=length,
        count=1,
        no_symbols=no_symbols,
        no_ambiguous=no_ambiguous,
    )[0]

    result: dict[str, object] = {
        "username": username,
        "password": generated,
        "length": length,
        "rotate_after_days": rotate_after_days,
        "storage": "not_saved",
        "notes": [
            "Store this in an approved password manager.",
            "Use a unique password per admin account.",
            "Enable MFA for admin access where supported.",
        ],
    }

    print_section("Admin Password")
    cyber_line("username", username)
    cyber_line("password", generated)
    cyber_line("rotation", f"{rotate_after_days} days")
    print("[i] Store this in your approved password manager. Do not reuse it.")

    if output:
        body = (
            f"username={username}\n"
            f"password={generated}\n"
            f"rotate_after_days={rotate_after_days}\n"
            f"generated_at={datetime.now(timezone.utc).isoformat()}\n"
        )
        saved_path = write_secret_file(output, body)
        result["storage"] = saved_path
        print(f"[+] Saved secret file with mode 0600: {saved_path}")

    return result


def permission_guide(tool: str | None = None) -> dict[str, object]:
    selected = tool or "all"
    guides: dict[str, list[str]] = {
        "sudo-su": [
            "Use ktool sudo-su -- <command args> to relaunch one Ktool command through sudo.",
            "Use ktool sudo-su with no command args to open the interactive menu as root.",
            "This uses the operating system's sudo policy; it does not bypass authentication or permissions.",
        ],
        "capture": [
            "Run packet capture from an approved admin shell: sudo ktool capture <interface> --yes-i-am-authorized",
            "Or use: ktool sudo-su -- capture <interface> --yes-i-am-authorized",
            "Linux alternative for tcpdump: sudo setcap cap_net_raw,cap_net_admin=eip $(command -v tcpdump)",
            "macOS alternative: install Wireshark's ChmodBPF package or run from an approved sudo session.",
        ],
        "scapy-sniff": [
            "Run Scapy sniffing from an approved admin shell: sudo ktool scapy-sniff --interface <iface> --yes-i-am-authorized",
            "Or use: ktool sudo-su -- scapy-sniff --interface <iface> --yes-i-am-authorized",
            "Linux raw socket access generally requires root or CAP_NET_RAW/CAP_NET_ADMIN.",
            "macOS raw packet access often requires sudo and Terminal/iTerm network permissions.",
        ],
        "lan-scan": [
            "Use --no-scapy for an unprivileged ping sweep when ARP scan permissions are unavailable.",
            "For Scapy ARP discovery, run from an approved admin shell or use an authorized network scanner host.",
        ],
        "nmap": [
            "Most connect scans run unprivileged; OS detection and SYN scans usually require sudo.",
            "Use ktool nmap <target> without --os-detect if admin rights are not approved.",
        ],
        "ncat-chat": [
            "Use ports above 1024 for unprivileged listen mode.",
            "Ports below 1024 require approved admin privileges or a service manager binding the port.",
        ],
    }
    if selected != "all" and selected not in guides:
        raise ValueError(f"Unknown permission guide: {selected}. Choices: {', '.join(sorted(guides))}, all")

    shown = guides if selected == "all" else {selected: guides[selected]}
    print_section("Permission Guide")
    print("[i] Ktool will not bypass operating-system controls. Use approved admin privileges or capabilities.")
    for name, lines in shown.items():
        print(f"\n[{name}]")
        for line in lines:
            print(f"  - {line}")
    return {"tool": selected, "guides": shown}


def permission_error_message(operation: str, error: object | str) -> str:
    return (
        f"{operation} needs approved OS privileges: {error}\n"
        "Ktool will not bypass permission controls. Run `ktool permission-guide` "
        "for safe work-environment fixes."
    )


def print_permission_hint_if_needed(stderr: str, operation: str) -> None:
    lowered = stderr.lower()
    markers = (
        "operation not permitted",
        "permission denied",
        "you don't have permission",
        "socket: operation not permitted",
    )
    if any(marker in lowered for marker in markers):
        print(f"\n[i] {permission_error_message(operation, stderr.strip())}", file=sys.stderr)


def is_root_user() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def sudo_su(ktool_args: list[str], dry_run: bool = False) -> dict[str, object]:
    if os.name == "nt":
        raise ValueError("sudo-su is only supported on Unix-like systems.")

    args = list(ktool_args)
    if args and args[0] == "--":
        args = args[1:]

    script_path = str(Path(__file__).resolve())
    target = args or ["<interactive-menu>"]

    if is_root_user():
        print_section("Root Access")
        cyber_line("status", "already running as root")
        cyber_line("target", " ".join(target))
        if dry_run or not args:
            return {"already_root": True, "target": target, "executed": False}
        command = [sys.executable, script_path, *args]
    else:
        sudo_path = find_tool("sudo")
        if not sudo_path:
            raise ValueError("sudo is not installed or not in PATH. Ask your administrator to provision sudo access.")
        command = [sudo_path, sys.executable, script_path, *args]

    print_section("Root Relaunch")
    cyber_line("command", " ".join(shlex.quote(part) for part in command))
    print("[i] This uses approved sudo policy. Ktool does not bypass authentication or OS permissions.")

    if dry_run:
        return {
            "command": command,
            "target": target,
            "already_root": is_root_user(),
            "executed": False,
        }

    result = subprocess.run(command, check=False)
    return {
        "command": command,
        "target": target,
        "already_root": is_root_user(),
        "executed": True,
        "returncode": result.returncode,
    }


def resolve_name(address: str) -> str | None:
    try:
        return socket.gethostbyaddr(address)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def ping_host(address: str, timeout: float) -> bool:
    ping_path = find_tool("ping")
    if not ping_path:
        return False
    wait_value = "1000" if platform.system() == "Darwin" else str(max(1, int(timeout)))
    command = [ping_path, "-c", "1", "-W", wait_value, address]
    result = run_external(command, timeout=timeout + 2)
    return result.returncode == 0


def arp_lookup(address: str) -> str | None:
    arp_path = find_tool("arp")
    if not arp_path:
        return None
    result = run_external([arp_path, "-n", address], timeout=5)
    text = result.stdout + result.stderr
    match = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", text, re.IGNORECASE)
    return match.group(1).lower() if match else None


def scapy_arp_scan(
    network: ipaddress.IPv4Network,
    interface: str | None,
    timeout: float,
    install_missing: bool,
) -> list[dict[str, object]]:
    if not ensure_python_package("scapy", auto_install=install_missing):
        return []

    try:
        from scapy.all import ARP, Ether, conf, srp  # type: ignore[import-not-found]
    except ImportError:
        return []

    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(packet, timeout=timeout, iface=interface)
    devices: list[dict[str, object]] = []
    for _, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc.lower(), "method": "arp"})
    return sorted(devices, key=lambda item: ipaddress.ip_address(str(item["ip"])))


def lan_scan(
    cidr: str,
    interface: str | None,
    timeout: float,
    workers: int,
    resolve_names: bool,
    use_scapy: bool,
    install_missing: bool,
) -> list[dict[str, object]]:
    network = ipaddress.ip_network(cidr, strict=False)
    if network.version != 4:
        raise ValueError("lan-scan currently supports IPv4 networks only.")
    if network.num_addresses > 1024:
        raise ValueError("Refusing to scan more than 1024 addresses. Use a smaller CIDR such as /24.")

    print_section("LAN Device Scanner")
    cyber_line("network", str(network))
    cyber_line("mode", "Scapy ARP" if use_scapy else "ICMP ping sweep")

    devices: list[dict[str, object]] = []
    if use_scapy:
        try:
            devices = scapy_arp_scan(network, interface, timeout, install_missing)
        except PermissionError as error:
            print(f"[i] {permission_error_message('Scapy ARP scan', error)}")
        except OSError as error:
            print(f"[i] Scapy ARP failed, falling back to ping sweep: {error}")

    if not devices:
        hosts = [str(host) for host in network.hosts()]
        found: list[dict[str, object]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, 128))) as executor:
            future_map = {executor.submit(ping_host, host, timeout): host for host in hosts}
            for future in concurrent.futures.as_completed(future_map):
                host = future_map[future]
                if future.result():
                    found.append({"ip": host, "mac": arp_lookup(host), "method": "icmp"})
        devices = sorted(found, key=lambda item: ipaddress.ip_address(str(item["ip"])))

    if resolve_names:
        for device in devices:
            name = resolve_name(str(device["ip"]))
            if name:
                device["hostname"] = name

    if devices:
        rows = []
        for device in devices:
            name = f" {device.get('hostname', '')}" if device.get("hostname") else ""
            rows.append((str(device["ip"]), f"{device.get('mac') or 'unknown-mac'} {device['method']}{name}"))
        print_key_value_table(rows)
    else:
        print("[i] No live devices responded. Some hosts block ping/ARP replies.")
    return devices


def combine_bpf_filters(traffic: str, bpf_filter: str | None) -> str | None:
    traffic_filters = {
        "all": None,
        "http": "tcp port 80 or tcp port 8000 or tcp port 8080 or tcp port 8081 or tcp port 8888",
        "dns": "port 53",
        "http-dns": "(port 53) or (tcp port 80 or tcp port 8000 or tcp port 8080 or tcp port 8081 or tcp port 8888)",
    }
    selected = traffic_filters[traffic]
    if selected and bpf_filter:
        return f"({selected}) and ({bpf_filter})"
    return selected or bpf_filter


def decode_packet_text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="ignore").replace("\r", "")


def header_value(http_text: str, header_name: str) -> str | None:
    prefix = f"{header_name.lower()}:"
    for line in http_text.splitlines()[1:30]:
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def normalize_domain(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="ignore")
    else:
        text = str(value)
    text = text.strip().strip(".").lower()
    return text or None


def endpoint(packet: object, layer_name: str, attr: str) -> str:
    try:
        layer = packet.getlayer(layer_name)
        return str(getattr(layer, attr))
    except Exception:
        return "?"


def packet_ports(packet: object) -> tuple[int | None, int | None, str]:
    for layer_name, proto in (("TCP", "TCP"), ("UDP", "UDP")):
        try:
            if packet.haslayer(layer_name):
                layer = packet.getlayer(layer_name)
                return int(layer.sport), int(layer.dport), proto
        except Exception:
            continue
    return None, None, "IP"


def suspicious_reasons(domain: str | None, info: str, sport: int | None, dport: int | None, proto: str) -> list[str]:
    reasons: list[str] = []
    lowered_info = info.lower()
    if domain:
        lowered_domain = domain.lower()
        if len(lowered_domain) > 60 or lowered_domain.count(".") >= 5:
            reasons.append("long/suspicious domain")
        if lowered_domain.startswith("xn--") or ".xn--" in lowered_domain:
            reasons.append("punycode domain")
        if any(lowered_domain.endswith(tld) for tld in SUSPICIOUS_DNS_TLDS):
            reasons.append("watchlist TLD")
        if any(marker in lowered_domain for marker in DYNAMIC_DNS_MARKERS):
            reasons.append("dynamic DNS domain")
        marker_hits = [marker for marker in SUSPICIOUS_DOMAIN_MARKERS if marker in lowered_domain]
        if len(marker_hits) >= 2:
            reasons.append("phishing-like domain words")
    if proto == "HTTP" and any(token in lowered_info for token in ("password=", "passwd=", "token=", "apikey=", "api_key=")):
        reasons.append("sensitive value in cleartext HTTP")
    if proto == "HTTP" and any(token in lowered_info for token in ("login", "signin", "auth")):
        reasons.append("login over cleartext HTTP")
    if dport in {21, 23, 2323} or sport in {21, 23, 2323}:
        reasons.append("cleartext admin protocol")
    if dport in {445, 3389, 5900}:
        reasons.append("sensitive management/service port")
    return reasons


def analyze_packet(packet: object) -> dict[str, object]:
    src = endpoint(packet, "IP", "src")
    dst = endpoint(packet, "IP", "dst")
    if src == "?" and dst == "?":
        src = endpoint(packet, "IPv6", "src")
        dst = endpoint(packet, "IPv6", "dst")

    sport, dport, transport = packet_ports(packet)
    proto = transport
    domain: str | None = None
    info = ""

    try:
        if packet.haslayer("DNSQR"):
            proto = "DNS"
            query = packet.getlayer("DNSQR")
            domain = normalize_domain(getattr(query, "qname", None))
            qtype = getattr(query, "qtype", "?")
            info = f"query type={qtype}"
    except Exception:
        pass

    try:
        if packet.haslayer("Raw") and (sport in HTTP_PORTS or dport in HTTP_PORTS):
            raw = bytes(packet.getlayer("Raw").load)
            text = decode_packet_text(raw)
            first_line = text.splitlines()[0].strip() if text.splitlines() else ""
            host = header_value(text, "Host")
            if first_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
                proto = "HTTP"
                domain = normalize_domain(host) or domain
                info = first_line[:120]
    except Exception:
        pass

    if not info:
        try:
            info = packet.summary()
        except Exception:
            info = "packet"

    reasons = suspicious_reasons(domain, info, sport, dport, proto)
    return {
        "time": datetime.now().strftime("%H:%M:%S"),
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "proto": proto,
        "domain": domain,
        "info": info,
        "suspicious": bool(reasons),
        "reasons": reasons,
    }


def format_packet_event(event: dict[str, object]) -> str:
    proto = str(event["proto"])
    suspicious = bool(event["suspicious"])
    tag = "ALERT" if suspicious else proto
    tag_color = "1;31" if suspicious else ("1;35" if proto == "DNS" else "1;36" if proto == "HTTP" else "90")
    src = str(event["src"])
    dst = str(event["dst"])
    sport = event.get("sport")
    dport = event.get("dport")
    left = f"{src}{':' + str(sport) if sport else ''}"
    right = f"{dst}{':' + str(dport) if dport else ''}"
    domain = str(event["domain"] or "-")
    info = str(event["info"])
    if len(info) > 110:
        info = info[:107] + "..."
    reason_text = ""
    if suspicious:
        reason_text = " " + color("[" + "; ".join(str(reason) for reason in event["reasons"]) + "]", "1;31")
    return (
        f"{color(str(event['time']), '90')} "
        f"{color(tag.rjust(5), tag_color)} "
        f"{left} {color('->', '32')} {right} "
        f"{color(domain, '1;33' if domain != '-' else '90')} "
        f"{info}{reason_text}"
    )


def scapy_sniff(
    interface: str | None,
    duration: int,
    count: int,
    bpf_filter: str | None,
    output: str | None,
    install_missing: bool,
    traffic: str,
    suspicious_only: bool,
) -> dict[str, object]:
    if duration < 1 or duration > 300:
        raise ValueError("--duration must be between 1 and 300 seconds.")
    if count < 1 or count > 5000:
        raise ValueError("--count must be between 1 and 5000 packets.")
    if not ensure_python_package("scapy", auto_install=install_missing):
        raise ValueError("Scapy is not installed. Rerun with --install-missing or install scapy first.")
    if traffic not in {"all", "http", "dns", "http-dns"}:
        raise ValueError("--traffic must be one of: all, http, dns, http-dns.")

    from scapy.all import conf, sniff, wrpcap  # type: ignore[import-not-found]

    conf.verb = 0
    events: list[dict[str, object]] = []
    packets = []
    active_filter = combine_bpf_filters(traffic, bpf_filter)
    counters = {"total": 0, "shown": 0, "suspicious": 0, "dns": 0, "http": 0}

    def on_packet(packet: object) -> None:
        counters["total"] += 1
        event = analyze_packet(packet)
        proto = str(event["proto"]).lower()
        if proto in counters:
            counters[proto] += 1
        if event["suspicious"]:
            counters["suspicious"] += 1
        if suspicious_only and not event["suspicious"]:
            return
        counters["shown"] += 1
        events.append(event)
        print(format_packet_event(event))

    print_section("Scapy Packet Sniffer")
    cyber_line("interface", interface or "default")
    cyber_line("duration", f"{duration}s")
    cyber_line("count", str(count))
    cyber_line("traffic", traffic)
    if active_filter:
        cyber_line("filter", active_filter)
    if suspicious_only:
        cyber_line("display", "suspicious traffic only")
    print("[i] Readable DNS/HTTP view. Use only on networks you administer.")
    print(color(" TIME   TYPE  FLOW                                DOMAIN / DETAIL", "90"))

    try:
        packets = sniff(
            iface=interface,
            timeout=duration,
            count=count,
            filter=active_filter,
            prn=on_packet,
            store=bool(output),
        )
    except PermissionError as error:
        raise ValueError(permission_error_message("Scapy packet sniffing", error)) from error
    except OSError as error:
        message = str(error)
        if "operation not permitted" in message.lower() or "permission denied" in message.lower():
            raise ValueError(permission_error_message("Scapy packet sniffing", error)) from error
        raise ValueError(f"Scapy sniff failed: {error}") from error

    if output:
        wrpcap(output, packets)
        print(f"[+] Wrote pcap: {output}")

    print_section("Sniffer Summary")
    print_key_value_table(
        [
            ("captured", str(counters["total"])),
            ("displayed", str(counters["shown"])),
            ("dns", str(counters["dns"])),
            ("http", str(counters["http"])),
            ("suspicious", str(counters["suspicious"])),
        ]
    )

    return {
        "interface": interface,
        "duration": duration,
        "count_limit": count,
        "captured": counters["total"],
        "displayed": counters["shown"],
        "traffic": traffic,
        "filter": active_filter,
        "suspicious_only": suspicious_only,
        "output": output,
        "counters": counters,
        "events": events,
    }


def build_ncat_command(path: str, mode: str, host: str | None, port: int, bind: str | None) -> list[str]:
    binary = Path(path).name
    if mode == "listen":
        if binary == "ncat":
            command = [path, "--listen", "--keep-open", "--recv-only", "-p", str(port)]
            if bind:
                command.extend(["-s", bind])
            return command
        command = [path, "-l", "-p", str(port)]
        if bind:
            command.extend(["-s", bind])
        return command

    if not host:
        raise ValueError("Connect/send mode requires a host.")
    return [path, host, str(port)]


def ncat_chat(
    mode: str,
    host: str | None,
    port: int,
    bind: str | None,
    message: str | None,
    timeout: float | None,
    install_missing: bool,
    package_manager: str | None,
) -> dict[str, object]:
    if port < 1 or port > 65535:
        raise ValueError("--port must be between 1 and 65535.")

    ncat_path = ensure_tool("ncat", auto_install=install_missing, manager=package_manager)
    if not ncat_path:
        raise ValueError("ncat/nc is not installed. Rerun with --install-missing or install ncat first.")

    command = build_ncat_command(ncat_path, mode, host, port, bind)
    print_section("ncat Messenger")
    cyber_line("mode", mode)
    cyber_line("command", " ".join(command))
    print("[i] Plain text transport. Use only on trusted networks or wrap it with SSH/VPN.")

    if mode == "send":
        payload = (message if message is not None else sys.stdin.read()).rstrip("\n") + "\n"
        result = subprocess.run(
            command,
            input=payload,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
            print_permission_hint_if_needed(result.stderr, "ncat messaging")
        return {
            "mode": mode,
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    try:
        result = subprocess.run(command, check=False, timeout=timeout)
        if result.returncode != 0:
            print_permission_hint_if_needed("", "ncat messaging")
        return {"mode": mode, "command": command, "returncode": result.returncode}
    except subprocess.TimeoutExpired:
        print(f"[i] ncat session timed out after {timeout}s.")
        return {"mode": mode, "command": command, "timed_out_after_seconds": timeout}


def packet_capture(
    interface: str,
    duration: int,
    count: int,
    output: str,
    install_missing: bool = False,
    package_manager: str | None = None,
) -> dict[str, object]:
    tcpdump_path = ensure_tool("tcpdump", auto_install=install_missing, manager=package_manager)
    if not tcpdump_path:
        raise ValueError("tcpdump is not installed. Rerun with --install-missing or use Wireshark manually.")
    if duration < 1 or duration > 300:
        raise ValueError("--duration must be between 1 and 300 seconds.")
    if count < 1 or count > 10000:
        raise ValueError("--count must be between 1 and 10000 packets.")

    output_path = Path(output)
    command = [
        tcpdump_path,
        "-i",
        interface,
        "-c",
        str(count),
        "-w",
        str(output_path),
    ]

    print(f"\n[+] Capturing packets on {interface}")
    print("[i] This may require root privileges. Capture only networks you own or administer.")
    print(f"[i] Output: {output_path}")

    try:
        result = run_external(command, timeout=duration)
    except TimeoutError:
        return {
            "interface": interface,
            "output": str(output_path),
            "timed_out_after_seconds": duration,
            "note": "tcpdump was stopped by the timeout; output may still contain captured packets.",
        }

    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)

    return {
        "interface": interface,
        "output": str(output_path),
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def is_private_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def parse_lsof_connections(output: str) -> list[dict[str, object]]:
    connections: list[dict[str, object]] = []
    for line in output.splitlines()[1:]:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        command, pid, user, _, _, _, _, node, name = parts
        local = name
        remote = ""
        state = ""
        if "->" in name:
            local, rest = name.split("->", 1)
            remote = rest
        state_match = re.search(r"\(([^)]+)\)", name)
        if state_match:
            state = state_match.group(1)
            local = local.replace(f"({state})", "").strip()
            remote = remote.replace(f"({state})", "").strip()
        connections.append(
            {
                "command": command,
                "pid": pid,
                "user": user,
                "proto": node,
                "local": local.strip(),
                "remote": remote.strip(),
                "state": state,
                "raw": name,
            }
        )
    return connections


def parse_endpoint_port(endpoint_text: str) -> int | None:
    match = re.search(r":(\d+)(?:\s|$)", endpoint_text)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def parse_endpoint_host(endpoint_text: str) -> str | None:
    endpoint_text = endpoint_text.strip()
    if not endpoint_text or endpoint_text == "*":
        return None
    if endpoint_text.startswith("[") and "]" in endpoint_text:
        return endpoint_text[1:endpoint_text.index("]")]
    if ":" in endpoint_text:
        return endpoint_text.rsplit(":", 1)[0]
    return endpoint_text


def connection_reasons(connection: dict[str, object]) -> list[str]:
    reasons: list[str] = []
    local = str(connection.get("local") or "")
    remote = str(connection.get("remote") or "")
    state = str(connection.get("state") or "")
    local_port = parse_endpoint_port(local)
    remote_port = parse_endpoint_port(remote)
    remote_host = parse_endpoint_host(remote)

    for port in (local_port, remote_port):
        if port in SUSPICIOUS_PORTS:
            reasons.append(SUSPICIOUS_PORTS[port])
    if state.upper() == "LISTEN" and local_port in HIGH_RISK_LISTEN_PORTS:
        reasons.append("high-risk service listening")
    if state.upper() == "LISTEN" and (local.startswith("*:") or local.startswith("0.0.0.0:") or local.startswith("[::]:")):
        reasons.append("listening on all interfaces")
    if remote_host and not is_private_address(remote_host):
        reasons.append("external remote endpoint")
    return sorted(set(reasons))


def connection_snapshot(show_all: bool) -> list[dict[str, object]]:
    lsof_path = find_tool("lsof")
    if not lsof_path:
        raise ValueError("lsof is not installed. Install lsof or use platform network tools manually.")
    result = run_external([lsof_path, "-nP", "-iTCP", "-iUDP"], timeout=15)
    if result.returncode not in {0, 1} and result.stderr.strip():
        raise ValueError(result.stderr.strip())
    connections = parse_lsof_connections(result.stdout)
    enriched: list[dict[str, object]] = []
    for connection in connections:
        reasons = connection_reasons(connection)
        connection["suspicious"] = bool(reasons)
        connection["reasons"] = reasons
        if show_all or reasons:
            enriched.append(connection)
    return enriched


def format_connection(connection: dict[str, object]) -> str:
    suspicious = bool(connection.get("suspicious"))
    tag = color("ALERT", "1;31") if suspicious else color("CONN ", "1;36")
    command = f"{connection.get('command')}[{connection.get('pid')}]"
    flow = f"{connection.get('local') or '-'}"
    if connection.get("remote"):
        flow += f" -> {connection.get('remote')}"
    state = str(connection.get("state") or "-")
    reasons = connection.get("reasons") or []
    reason_text = ""
    if reasons:
        reason_text = " " + color("[" + "; ".join(str(reason) for reason in reasons) + "]", "1;31")
    return f"{tag} {color(command.ljust(24), '36')} {state.ljust(13)} {flow}{reason_text}"


def connection_watch(iterations: int, interval: float, show_all: bool) -> dict[str, object]:
    if iterations < 1 or iterations > 100:
        raise ValueError("--iterations must be between 1 and 100.")
    if interval < 0.5 or interval > 300:
        raise ValueError("--interval must be between 0.5 and 300 seconds.")

    print_section("Live Connection Watch")
    cyber_line("iterations", str(iterations))
    cyber_line("interval", f"{interval}s")
    cyber_line("display", "all connections" if show_all else "alerts only")

    snapshots: list[dict[str, object]] = []
    for index in range(iterations):
        if iterations > 1:
            print(color(f"\n[cycle {index + 1}/{iterations}]", "90"))
        connections = connection_snapshot(show_all=show_all)
        alerts = [connection for connection in connections if connection.get("suspicious")]
        print_key_value_table([("shown", str(len(connections))), ("alerts", str(len(alerts)))])
        for connection in connections[:80]:
            print(format_connection(connection))
        if len(connections) > 80:
            print(f"[i] Showing first 80 rows out of {len(connections)}.")
        snapshots.append({"shown": len(connections), "alerts": len(alerts), "connections": connections})
        if index < iterations - 1:
            time.sleep(interval)
    return {"iterations": iterations, "interval": interval, "show_all": show_all, "snapshots": snapshots}


def classify_log_line(line: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for severity, label, pattern in LOG_PATTERNS:
        if pattern.search(line):
            findings.append({"severity": severity, "type": label})
    return findings


def read_last_lines(path: Path, limit: int) -> list[str]:
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]


def print_log_event(line: str, findings: list[dict[str, str]]) -> None:
    if not findings:
        print(color(" INFO ", "90") + " " + line)
        return
    severity = "high" if any(finding["severity"] == "high" for finding in findings) else "medium"
    tag = color("ALERT", "1;31" if severity == "high" else "1;33")
    labels = ", ".join(finding["type"] for finding in findings)
    print(f"{tag} {line} {color('[' + labels + ']', '1;31' if severity == 'high' else '1;33')}")


def log_watch(path: str, lines: int, follow: bool, duration: int, alerts_only: bool) -> dict[str, object]:
    log_path = Path(path).expanduser()
    if not log_path.exists():
        raise ValueError(f"Log file not found: {log_path}")
    if lines < 1 or lines > 5000:
        raise ValueError("--lines must be between 1 and 5000.")
    if duration < 1 or duration > 3600:
        raise ValueError("--duration must be between 1 and 3600 seconds.")

    print_section("Log Watch")
    cyber_line("file", str(log_path))
    cyber_line("mode", "follow" if follow else "snapshot")
    cyber_line("display", "alerts only" if alerts_only else "all")

    events: list[dict[str, object]] = []
    for line in read_last_lines(log_path, lines):
        findings = classify_log_line(line)
        if alerts_only and not findings:
            continue
        print_log_event(line, findings)
        events.append({"line": line, "findings": findings})

    if follow:
        end_at = time.time() + duration
        with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
            handle.seek(0, os.SEEK_END)
            while time.time() < end_at:
                line = handle.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                line = line.rstrip("\n")
                findings = classify_log_line(line)
                if alerts_only and not findings:
                    continue
                print_log_event(line, findings)
                events.append({"line": line, "findings": findings})
    return {"file": str(log_path), "events": events, "alerts": [event for event in events if event["findings"]]}


def classify_ioc(value: str) -> dict[str, object]:
    raw = value.strip()
    if not raw:
        raise ValueError("IOC value cannot be empty.")
    parsed_url = urlparse(raw if "://" in raw else f"//{raw}")
    reasons: list[str] = []
    kind = "unknown"
    normalized = raw

    try:
        address = ipaddress.ip_address(raw)
        kind = "ip"
        normalized = str(address)
        if address.is_private:
            reasons.append("private address")
        elif address.is_global:
            reasons.append("public routable address")
        if address.is_multicast or address.is_reserved:
            reasons.append("reserved/special address")
    except ValueError:
        host = parsed_url.hostname
        if re.fullmatch(r"[a-fA-F0-9]{32}", raw):
            kind = "md5"
        elif re.fullmatch(r"[a-fA-F0-9]{40}", raw):
            kind = "sha1"
        elif re.fullmatch(r"[a-fA-F0-9]{64}", raw):
            kind = "sha256"
        elif host:
            kind = "url" if parsed_url.scheme else "domain"
            normalized = host.lower()
            reasons.extend(suspicious_reasons(normalized, raw, None, None, "IOC"))
            if parsed_url.scheme == "http":
                reasons.append("cleartext URL")
        else:
            reasons.append("unrecognized indicator format")

    severity = "info"
    if any("phishing" in reason or "watchlist" in reason or "dynamic DNS" in reason for reason in reasons):
        severity = "medium"
    if any("cleartext" in reason for reason in reasons):
        severity = "medium"

    return {"value": raw, "normalized": normalized, "kind": kind, "severity": severity, "reasons": sorted(set(reasons))}


def ioc_triage(values: list[str]) -> list[dict[str, object]]:
    if not values:
        raise ValueError("Provide at least one IOC value.")
    print_section("IOC Triage")
    results = [classify_ioc(value) for value in values]
    for result in results:
        severity = str(result["severity"])
        tag = color(severity.upper().rjust(6), "1;33" if severity == "medium" else "90")
        reasons = "; ".join(str(reason) for reason in result["reasons"]) or "no local flags"
        print(f"{tag} {str(result['kind']).ljust(8)} {result['normalized']} {color('[' + reasons + ']', '90')}")
    return results


def live_workflow(target: str, url: str | None, ports: str, timeout: float) -> dict[str, object]:
    require_target = validate_host(target)
    print_section("Authorized Live Workflow")
    cyber_line("target", require_target)
    results: dict[str, object] = {}
    results["dns"] = resolve_dns(require_target)
    results["ports"] = [asdict(item) for item in port_scanner(require_target, parse_ports(ports), timeout=timeout, workers=32, delay=0.0)]
    if url:
        results["web"] = web_baseline(url, timeout=5.0, delay=0.1)
    return results


def wireless_info() -> dict[str, object]:
    print("\n[+] Wireless interface inventory")
    print("[i] This is read-only. It does not enable monitor mode, deauthenticate clients, or capture handshakes.")

    commands = [
        ("iw", ["dev"]),
        ("nmcli", ["device", "status"]),
        ("ip", ["link", "show"]),
    ]
    results: dict[str, object] = {}

    for tool, args in commands:
        tool_path = find_tool(tool)
        if not tool_path:
            print(f"[missing] {tool}")
            results[tool] = {"installed": False}
            continue

        command = [tool_path, *args]
        result = run_external(command, timeout=10)
        results[tool] = {
            "installed": True,
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        print(f"\n[{tool}]")
        output = result.stdout.strip() or result.stderr.strip()
        print(output if output else "No output.")

    return results


def vuln_lookup(query: str, timeout: float) -> dict[str, object]:
    if not query.strip():
        raise ValueError("Search query cannot be empty.")

    searchsploit_path = find_tool("searchsploit")
    if not searchsploit_path:
        raise ValueError(
            "searchsploit is not installed.\n"
            + install_hint_text("searchsploit")
        )

    command = [searchsploit_path, "--colour", "never", query]
    print(f"\n[+] Searching Exploit-DB metadata for: {query}")
    print("[i] This performs vulnerability research only; it does not run exploit code.")
    result = run_external(command, timeout=timeout)

    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)

    return {
        "query": query,
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def awareness_plan(company_name: str, audience: str) -> dict[str, object]:
    company_name = company_name.strip() or "the organization"
    audience = audience.strip() or "employees"
    plan = {
        "company": company_name,
        "audience": audience,
        "objectives": [
            "Teach staff how to identify suspicious messages.",
            "Explain how to report suspected phishing safely.",
            "Measure awareness using quizzes or tabletop exercises, not credential harvesting.",
        ],
        "activities": [
            "Review real-world phishing indicators using sanitized examples.",
            "Run a reporting drill with a dedicated internal mailbox or ticket form.",
            "Publish a one-page checklist for links, attachments, urgency, and sender verification.",
        ],
        "do_not_do": [
            "Do not collect real passwords.",
            "Do not clone live login pages.",
            "Do not target people without management approval and clear scope.",
        ],
    }

    print(f"\n[+] Awareness plan for {company_name} ({audience})")
    for section, items in plan.items():
        if isinstance(items, list):
            print(f"\n{section}:")
            for item in items:
                print(f"  - {item}")
    return plan


def local_posture() -> dict[str, object]:
    print("\n[+] Local privilege-risk posture review")
    print("[i] This is defensive inventory for your own Linux host; it does not attempt privilege escalation.")

    checks: dict[str, object] = {}
    for name, command in {
        "id": ["id"],
        "kernel": ["uname", "-a"],
        "sudo_non_interactive": ["sudo", "-n", "-l"],
    }.items():
        tool = find_tool(command[0])
        if not tool:
            checks[name] = {"installed": False}
            continue
        result = run_external([tool, *command[1:]], timeout=10)
        checks[name] = {
            "command": [tool, *command[1:]],
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        print(f"\n[{name}]")
        output = result.stdout.strip() or result.stderr.strip()
        print(output if output else "No output.")

    suid_paths = find_suid_files(["/usr/bin", "/usr/sbin", "/bin", "/sbin"])
    checks["suid_files"] = suid_paths
    print("\n[SUID files in common binary directories]")
    if suid_paths:
        for path in suid_paths[:50]:
            print(f"  - {path}")
        if len(suid_paths) > 50:
            print(f"  ... {len(suid_paths) - 50} more")
    else:
        print("  None found or directories unavailable.")

    writable_paths = find_world_writable_paths(["/tmp", "/var/tmp", os.getcwd()])
    checks["world_writable_paths"] = writable_paths
    print("\n[World-writable paths sampled]")
    for path in writable_paths[:50]:
        print(f"  - {path}")
    if len(writable_paths) > 50:
        print(f"  ... {len(writable_paths) - 50} more")

    return checks


def find_suid_files(roots: list[str]) -> list[str]:
    found: list[str] = []
    for root in roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        for path in root_path.rglob("*"):
            try:
                if path.is_file() and path.stat().st_mode & 0o4000:
                    found.append(str(path))
            except OSError:
                continue
    return sorted(found)


def find_world_writable_paths(roots: list[str]) -> list[str]:
    found: list[str] = []
    for root in roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        for path in root_path.rglob("*"):
            try:
                if path.stat().st_mode & 0o002:
                    found.append(str(path))
            except OSError:
                continue
            if len(found) >= 200:
                return sorted(found)
    return sorted(found)


def check_tools(categories: list[str] | None = None) -> dict[str, list[dict[str, str | bool | None]]]:
    selected = categories or list(TOOL_CATEGORIES)
    report: dict[str, list[dict[str, str | bool | None]]] = {}

    print("\n[+] Tool availability")
    for category in selected:
        if category not in TOOL_CATEGORIES:
            raise ValueError(f"Unknown category: {category}")

        details = TOOL_CATEGORIES[category]
        print(f"\n{category}: {details['title']}")
        report[category] = []
        for tool in details["tools"]:
            if tool in PYTHON_PACKAGES:
                installed = importlib.util.find_spec(tool) is not None
                path = "python package" if installed else None
            else:
                path = find_tool(tool)
                installed = path is not None
            status = "installed" if installed else "missing"
            print(f"  [{status}] {tool}{f' -> {path}' if path else ''}")
            report[category].append(
                {"tool": tool, "installed": installed, "path": path}
            )

    return report


def print_roadmap(category: str | None = None) -> dict[str, object]:
    selected_keys = [category] if category else list(TOOL_CATEGORIES)
    unknown = [key for key in selected_keys if key not in TOOL_CATEGORIES]
    if unknown:
        raise ValueError(f"Unknown category: {', '.join(unknown)}")

    print("\n=== Ktool Learning Roadmap ===")
    print("Use every active test only on owned systems, written-scope targets, or labs.")
    print("Ktool does not automate brute force, phishing, persistence, or exploitation.")

    payload: dict[str, object] = {}
    for key in selected_keys:
        details = TOOL_CATEGORIES[key]
        payload[key] = details
        print(f"\n[{key}] {details['title']}")
        print("  Skills:")
        for skill in details["skills"]:
            print(f"    - {skill}")
        print("  Tools to learn:")
        for tool in details["tools"]:
            print(f"    - {tool}")
        print("  Implemented here:")
        for item in details["implemented"]:
            print(f"    - {item}")

        if key in {"passwords", "exploitation", "awareness", "post", "wireless"}:
            print("  Safety boundary: use dedicated labs and do not target real users or third-party systems.")

    return payload


def save_report(path: str | None, command: str, data: Iterable[object] | object) -> None:
    if not path:
        return

    if isinstance(data, list):
        payload_data = [asdict(item) if hasattr(item, "__dataclass_fields__") else item for item in data]
    elif hasattr(data, "__dataclass_fields__"):
        payload_data = asdict(data)
    else:
        payload_data = data

    payload = {
        "tool": TOOL_NAME,
        "owner": TOOL_OWNER,
        "command": command,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": payload_data,
    }
    report_path = Path(path)
    report_content = json.dumps(payload, indent=2)
    if command in SENSITIVE_REPORT_COMMANDS:
        saved_path = write_secret_file(str(report_path), report_content + "\n")
        print(f"\n[+] Sensitive report saved with mode 0600 to {saved_path}")
    else:
        report_path.write_text(report_content, encoding="utf-8")
        print(f"\n[+] Report saved to {report_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ktool ethical security assessment tool for Linux.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--yes-i-am-authorized",
        action="store_true",
        help="Confirm you have permission to test the target.",
    )
    parser.add_argument("--report", help="Write JSON report to this path.")

    subparsers = parser.add_subparsers(dest="command")

    roadmap_parser = subparsers.add_parser("roadmap", help="Show Ktool learning coverage.")
    roadmap_parser.add_argument(
        "--category",
        choices=sorted(TOOL_CATEGORIES),
        help="Show one category only.",
    )
    roadmap_parser.add_argument(
        "--report",
        default=argparse.SUPPRESS,
        help="Write JSON report to this path.",
    )

    tools_parser = subparsers.add_parser("tools", help="Check whether common Linux tools are installed.")
    tools_parser.add_argument(
        "--category",
        action="append",
        choices=sorted(TOOL_CATEGORIES),
        help="Limit checks to one category. Can be used more than once.",
    )
    tools_parser.add_argument(
        "--report",
        default=argparse.SUPPRESS,
        help="Write JSON report to this path.",
    )

    hints_parser = subparsers.add_parser("install-hints", help="Show package install commands for missing tools.")
    hints_parser.add_argument(
        "tool",
        nargs="?",
        choices=sorted(INSTALL_HINTS),
        help="Specific tool to show. Omit to show all supported hints.",
    )
    hints_parser.add_argument(
        "--report",
        default=argparse.SUPPRESS,
        help="Write JSON report to this path.",
    )

    install_parser = subparsers.add_parser("install-tool", help="Install a supported external tool.")
    install_parser.add_argument("tool", choices=sorted(PACKAGE_NAMES), help="Tool to install.")
    install_parser.add_argument("--manager", choices=["apt", "dnf", "pacman", "brew"], help="Package manager to use.")
    install_parser.add_argument("--execute", action="store_true", help="Run the install command.")
    install_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    sudo_parser = subparsers.add_parser("sudo-su", help="Relaunch Ktool through sudo for approved root access.")
    sudo_parser.add_argument("--dry-run", action="store_true", help="Print the sudo command without running it.")
    sudo_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")
    sudo_parser.add_argument(
        "ktool_args",
        nargs=argparse.REMAINDER,
        help="Ktool command args to run as root. Use -- before the command, or omit for the root menu.",
    )

    dns_parser = subparsers.add_parser("dns", help="Resolve DNS information for a host.")
    add_common_run_options(dns_parser)
    dns_parser.add_argument("domain", help="Domain or hostname to resolve.")

    whois_parser = subparsers.add_parser("whois", help="Run a WHOIS lookup using the system whois tool.")
    add_common_run_options(whois_parser)
    add_install_options(whois_parser)
    whois_parser.add_argument("domain", help="Domain or IP address to query.")
    whois_parser.add_argument("--timeout", type=float, default=15.0, help="Command timeout in seconds.")

    port_parser = subparsers.add_parser("ports", help="Scan selected TCP ports.")
    add_common_run_options(port_parser)
    port_parser.add_argument("target", help="Hostname or IP address.")
    port_parser.add_argument(
        "--ports",
        default="common",
        help="Port list, range, or 'common'. Example: 22,80,443 or 1-1024.",
    )
    port_parser.add_argument("--timeout", type=float, default=0.7, help="Socket timeout in seconds.")
    port_parser.add_argument("--workers", type=int, default=32, help="Concurrent socket workers.")
    port_parser.add_argument("--delay", type=float, default=0.0, help="Delay between scheduling checks.")

    sub_parser = subparsers.add_parser("subs", help="Resolve common subdomains.")
    add_common_run_options(sub_parser)
    sub_parser.add_argument("domain", help="Base domain, for example example.com.")
    sub_parser.add_argument("--wordlist", help="Optional subdomain wordlist path.")

    headers_parser = subparsers.add_parser("headers", help="Review HTTP headers.")
    add_common_run_options(headers_parser)
    headers_parser.add_argument("url", help="URL to check.")
    headers_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds.")

    dirs_parser = subparsers.add_parser("dirs", help="Check common web paths.")
    add_common_run_options(dirs_parser)
    dirs_parser.add_argument("url", help="Base URL to check.")
    dirs_parser.add_argument("--wordlist", help="Optional path wordlist.")
    dirs_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds.")
    dirs_parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests.")
    dirs_parser.add_argument("--show-all", action="store_true", help="Print all statuses, including 404s.")

    web_parser = subparsers.add_parser("web", help="Run safe baseline web checks.")
    add_common_run_options(web_parser)
    web_parser.add_argument("url", help="Base URL to check.")
    web_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds.")
    web_parser.add_argument("--delay", type=float, default=0.2, help="Delay between path requests.")

    web_vuln_parser = subparsers.add_parser("web-vuln-search", help="Search for safe web vulnerability indicators.")
    add_common_run_options(web_vuln_parser)
    web_vuln_parser.add_argument("url", help="Base URL to check.")
    web_vuln_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds.")
    web_vuln_parser.add_argument("--delay", type=float, default=0.2, help="Delay between exposure checks.")
    web_vuln_parser.add_argument(
        "--no-searchsploit",
        action="store_true",
        help="Skip local Exploit-DB metadata lookup.",
    )
    web_vuln_parser.add_argument(
        "--nikto",
        action="store_true",
        help="Run Nikto if installed. This is an active scanner.",
    )
    web_vuln_parser.add_argument("--nikto-timeout", type=float, default=180.0, help="Nikto timeout in seconds.")

    nmap_parser = subparsers.add_parser("nmap", help="Run a conservative nmap service scan.")
    add_common_run_options(nmap_parser)
    nmap_parser.add_argument("target", help="Hostname or IP address.")
    nmap_parser.add_argument("--top-ports", type=int, default=100, help="Number of top ports to scan.")
    nmap_parser.add_argument("--timeout", type=float, default=120.0, help="Command timeout in seconds.")
    nmap_parser.add_argument("--scripts", action="store_true", help="Include nmap default scripts (-sC).")
    nmap_parser.add_argument("--os-detect", action="store_true", help="Include OS detection (-O).")
    add_install_options(nmap_parser)

    lan_parser = subparsers.add_parser("lan-scan", help="Show live devices on an authorized local IPv4 network.")
    add_common_run_options(lan_parser)
    lan_parser.add_argument("cidr", help="Local network CIDR, for example 192.168.1.0/24.")
    lan_parser.add_argument("--interface", help="Network interface for Scapy ARP scans.")
    lan_parser.add_argument("--timeout", type=float, default=2.0, help="Per-host or ARP response timeout.")
    lan_parser.add_argument("--workers", type=int, default=64, help="Ping sweep workers when Scapy is unavailable.")
    lan_parser.add_argument("--resolve-names", action="store_true", help="Try reverse DNS for discovered devices.")
    lan_parser.add_argument("--no-scapy", action="store_true", help="Skip Scapy ARP and use ping sweep.")
    lan_parser.add_argument("--install-missing", action="store_true", help="Install Scapy automatically if it is missing.")

    password_parser = subparsers.add_parser("password-audit", help="Audit a local password candidate file for weak values.")
    password_parser.add_argument("file", help="Path to a local password candidate file.")
    password_parser.add_argument("--min-length", type=int, default=12, help="Minimum acceptable length.")
    password_parser.add_argument("--no-upper", action="store_true", help="Do not require uppercase characters.")
    password_parser.add_argument("--no-lower", action="store_true", help="Do not require lowercase characters.")
    password_parser.add_argument("--no-digit", action="store_true", help="Do not require digits.")
    password_parser.add_argument("--no-symbol", action="store_true", help="Do not require symbols.")
    password_parser.add_argument("--show-values", action="store_true", help="Print weak password values in output.")
    password_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    password_check_parser = subparsers.add_parser("password-check", help="Check one password for local strength indicators.")
    password_check_parser.add_argument("password", nargs="?", help="Password to check. Omit to enter hidden input.")
    password_check_parser.add_argument("--show-value", action="store_true", help="Include the password in JSON report output.")
    password_check_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    password_gen_parser = subparsers.add_parser("password-generate", help="Generate strong random passwords.")
    password_gen_parser.add_argument("--length", type=int, default=20, help="Password length.")
    password_gen_parser.add_argument("--count", type=int, default=5, help="Number of passwords.")
    password_gen_parser.add_argument("--no-symbols", action="store_true", help="Exclude symbols.")
    password_gen_parser.add_argument("--no-ambiguous", action="store_true", help="Remove visually ambiguous characters.")
    password_gen_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    admin_password_parser = subparsers.add_parser("admin-password", help="Generate a secure randomized admin password.")
    admin_password_parser.add_argument("--username", default="admin", help="Admin username label.")
    admin_password_parser.add_argument("--length", type=int, default=28, help="Password length.")
    admin_password_parser.add_argument("--rotate-after-days", type=int, default=90, help="Recommended rotation interval.")
    admin_password_parser.add_argument("--output", help="Optional local secret file saved with mode 0600.")
    admin_password_parser.add_argument("--no-symbols", action="store_true", help="Exclude symbols.")
    admin_password_parser.add_argument("--no-ambiguous", action="store_true", default=True, help="Remove visually ambiguous characters.")
    admin_password_parser.add_argument("--allow-ambiguous", action="store_false", dest="no_ambiguous", help="Allow visually ambiguous characters.")
    admin_password_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    capture_parser = subparsers.add_parser("capture", help="Capture packets with tcpdump for a short defensive sample.")
    add_common_run_options(capture_parser)
    add_install_options(capture_parser)
    capture_parser.add_argument("interface", help="Network interface, for example eth0 or wlan0.")
    capture_parser.add_argument("--duration", type=int, default=20, help="Maximum capture duration in seconds.")
    capture_parser.add_argument("--count", type=int, default=100, help="Maximum packet count.")
    capture_parser.add_argument("--output", default="capture.pcap", help="Output pcap file path.")

    sniff_parser = subparsers.add_parser("scapy-sniff", help="Show a bounded live packet summary using Scapy.")
    add_common_run_options(sniff_parser)
    sniff_parser.add_argument("--interface", help="Network interface. Omit for Scapy default.")
    sniff_parser.add_argument("--duration", type=int, default=20, help="Maximum sniff duration in seconds.")
    sniff_parser.add_argument("--count", type=int, default=100, help="Maximum packet count.")
    sniff_parser.add_argument("--filter", help="Optional BPF filter, for example 'tcp port 443'.")
    sniff_parser.add_argument(
        "--traffic",
        choices=["all", "http", "dns", "http-dns"],
        default="http-dns",
        help="Built-in traffic view/filter.",
    )
    sniff_parser.add_argument("--suspicious-only", action="store_true", help="Only print traffic with suspicious indicators.")
    sniff_parser.add_argument("--output", help="Optional pcap output path.")
    sniff_parser.add_argument("--install-missing", action="store_true", help="Install Scapy automatically if it is missing.")

    ncat_parser = subparsers.add_parser("ncat-chat", help="Use ncat/nc for simple port messaging.")
    add_common_run_options(ncat_parser)
    add_install_options(ncat_parser)
    ncat_parser.add_argument("mode", choices=["listen", "connect", "send"], help="Listen, connect interactively, or send one message.")
    ncat_parser.add_argument("--host", help="Remote host for connect/send mode.")
    ncat_parser.add_argument("--port", type=int, required=True, help="Port to listen on or connect to.")
    ncat_parser.add_argument("--bind", help="Local bind address for listen mode.")
    ncat_parser.add_argument("--message", help="Message for send mode. If omitted, stdin is used.")
    ncat_parser.add_argument("--timeout", type=float, help="Optional session timeout in seconds.")

    conn_parser = subparsers.add_parser("conn-watch", help="Watch active local network connections and highlight risky ones.")
    conn_parser.add_argument("--iterations", type=int, default=1, help="Number of snapshots to collect.")
    conn_parser.add_argument("--interval", type=float, default=3.0, help="Delay between snapshots.")
    conn_parser.add_argument("--show-all", action="store_true", help="Show all connections, not only suspicious rows.")
    conn_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    log_parser = subparsers.add_parser("log-watch", help="Watch a log file and highlight suspicious security events.")
    log_parser.add_argument("file", help="Log file to inspect.")
    log_parser.add_argument("--lines", type=int, default=80, help="Initial trailing lines to inspect.")
    log_parser.add_argument("--follow", action="store_true", help="Follow the file for new lines.")
    log_parser.add_argument("--duration", type=int, default=60, help="Follow duration in seconds.")
    log_parser.add_argument("--alerts-only", action="store_true", help="Only print lines with suspicious/security matches.")
    log_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    ioc_parser = subparsers.add_parser("ioc-triage", help="Classify IPs, domains, URLs, and hashes with local heuristics.")
    ioc_parser.add_argument("values", nargs="+", help="IOC values to inspect.")
    ioc_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    live_parser = subparsers.add_parser("live-workflow", help="Run an authorized live DNS, port, and optional web baseline.")
    add_common_run_options(live_parser)
    live_parser.add_argument("target", help="Authorized host or IP target.")
    live_parser.add_argument("--url", help="Optional URL for web baseline checks.")
    live_parser.add_argument("--ports", default="common", help="Ports for TCP scan, for example common, 22,80,443, or 1-1024.")
    live_parser.add_argument("--timeout", type=float, default=0.7, help="Socket timeout for port checks.")

    wireless_parser = subparsers.add_parser("wireless-info", help="Show read-only wireless/network interface information.")
    add_common_run_options(wireless_parser)

    vuln_parser = subparsers.add_parser("vuln-lookup", help="Search local Exploit-DB metadata with searchsploit.")
    add_common_run_options(vuln_parser)
    vuln_parser.add_argument("query", help="Product, CVE, or service/version query.")
    vuln_parser.add_argument("--timeout", type=float, default=30.0, help="Command timeout in seconds.")

    awareness_parser = subparsers.add_parser("awareness-plan", help="Generate a social-engineering awareness plan.")
    awareness_parser.add_argument("--company", default="the organization", help="Organization name.")
    awareness_parser.add_argument("--audience", default="employees", help="Audience name.")
    awareness_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    posture_parser = subparsers.add_parser("local-posture", help="Run local defensive privilege-risk checks.")
    posture_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    permission_parser = subparsers.add_parser("permission-guide", help="Show safe fixes for Operation not permitted errors.")
    permission_parser.add_argument(
        "tool",
        nargs="?",
        choices=["sudo-su", "capture", "scapy-sniff", "lan-scan", "nmap", "ncat-chat", "all"],
        default="all",
        help="Tool to show guidance for.",
    )
    permission_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    return parser


def add_common_run_options(command_parser: argparse.ArgumentParser) -> None:
    command_parser.add_argument(
        "--yes-i-am-authorized",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Confirm you have permission to test the target.",
    )
    command_parser.add_argument(
        "--report",
        default=argparse.SUPPRESS,
        help="Write JSON report to this path.",
    )


def add_install_options(command_parser: argparse.ArgumentParser) -> None:
    command_parser.add_argument(
        "--install-missing",
        action="store_true",
        help="Install a required external tool/package automatically if it is missing.",
    )
    command_parser.add_argument(
        "--package-manager",
        choices=["apt", "dnf", "pacman", "brew"],
        help="Package manager to use with --install-missing.",
    )


def interactive_menu() -> None:
    print_startup_banner()
    require_authorization(False)

    while True:
        print_menu_panel()

        choice = input(color("ktool> ", "1;32")).strip()

        try:
            if choice == "1":
                print_roadmap()
            elif choice == "2":
                check_tools()
            elif choice == "3":
                domain = input("Domain/host: ").strip()
                resolve_dns(domain)
            elif choice == "4":
                domain = input("Domain/IP: ").strip()
                whois_lookup(domain, timeout=15.0)
            elif choice == "5":
                target = input("Target host/IP: ").strip()
                port_text = input("Ports (common, 22,80,443, or 1-1024) [common]: ").strip() or "common"
                port_scanner(target, parse_ports(port_text), timeout=0.7, workers=32, delay=0.0)
            elif choice == "6":
                domain = input("Domain (example.com): ").strip()
                subdomain_finder(domain, DEFAULT_SUBDOMAINS)
            elif choice == "7":
                url = input("URL (https://example.com): ").strip()
                header_analyzer(url, timeout=5.0)
            elif choice == "8":
                url = input("Base URL (https://example.com): ").strip()
                directory_scanner(url, DEFAULT_PATHS, timeout=5.0, delay=0.2, show_all=False)
            elif choice == "9":
                url = input("Base URL (https://example.com): ").strip()
                web_baseline(url, timeout=5.0, delay=0.2)
            elif choice == "10":
                target = input("Target host/IP: ").strip()
                nmap_scan(target, top_ports=100, timeout=120.0, scripts=False, os_detect=False)
            elif choice == "11":
                cidr = input("Local CIDR (192.168.1.0/24): ").strip()
                lan_scan(
                    cidr,
                    interface=None,
                    timeout=2.0,
                    workers=64,
                    resolve_names=True,
                    use_scapy=True,
                    install_missing=False,
                )
            elif choice == "12":
                interface = input("Interface [default]: ").strip() or None
                traffic = input("Traffic (http/dns/http-dns/all) [http-dns]: ").strip() or "http-dns"
                bpf = input("BPF filter [none]: ").strip() or None
                suspicious_only = input("Show suspicious only? [y/N]: ").strip().lower() in {"y", "yes"}
                scapy_sniff(
                    interface=interface,
                    duration=20,
                    count=100,
                    bpf_filter=bpf,
                    output=None,
                    install_missing=False,
                    traffic=traffic,
                    suspicious_only=suspicious_only,
                )
            elif choice == "13":
                password = getpass.getpass("Password: ")
                password_strength(password, show_value=False)
            elif choice == "14":
                length = int(input("Length [20]: ").strip() or "20")
                count = int(input("Count [5]: ").strip() or "5")
                generate_password(length=length, count=count, no_symbols=False, no_ambiguous=True)
            elif choice == "15":
                mode = input("Mode (listen/connect/send): ").strip().lower()
                host = None
                if mode in {"connect", "send"}:
                    host = input("Remote host: ").strip()
                port = int(input("Port: ").strip())
                message = None
                if mode == "send":
                    message = input("Message: ")
                ncat_chat(
                    mode=mode,
                    host=host,
                    port=port,
                    bind=None,
                    message=message,
                    timeout=None,
                    install_missing=False,
                    package_manager=None,
                )
            elif choice == "16":
                username = input("Admin username [admin]: ").strip() or "admin"
                length = int(input("Length [28]: ").strip() or "28")
                output = input("Save to 0600 file [optional]: ").strip() or None
                admin_password(
                    username=username,
                    length=length,
                    rotate_after_days=90,
                    output=output,
                    no_symbols=False,
                    no_ambiguous=True,
                )
            elif choice == "17":
                command_text = input("Ktool args to run as root [blank for root menu]: ").strip()
                sudo_su(shlex.split(command_text), dry_run=False)
            elif choice == "18":
                tool = input("Tool (all/sudo-su/capture/scapy-sniff/lan-scan/nmap/ncat-chat) [all]: ").strip() or "all"
                permission_guide(tool)
            elif choice == "19":
                path = input("Password candidate file: ").strip()
                password_audit(
                    path,
                    min_length=12,
                    require_upper=True,
                    require_lower=True,
                    require_digit=True,
                    require_symbol=True,
                    show_values=False,
                )
            elif choice == "20":
                interface = input("Interface (eth0/wlan0): ").strip()
                output = input("Output pcap [capture.pcap]: ").strip() or "capture.pcap"
                packet_capture(interface, duration=20, count=100, output=output)
            elif choice == "21":
                wireless_info()
            elif choice == "22":
                query = input("Searchsploit query (product/CVE/service): ").strip()
                vuln_lookup(query, timeout=30.0)
            elif choice == "23":
                company = input("Company name [the organization]: ").strip() or "the organization"
                audience = input("Audience [employees]: ").strip() or "employees"
                awareness_plan(company, audience)
            elif choice == "24":
                local_posture()
            elif choice == "25":
                tool = input("Tool name [all]: ").strip() or None
                print_install_hints(tool)
            elif choice == "26":
                tool = input(f"Tool ({', '.join(sorted(PACKAGE_NAMES))}): ").strip()
                execute = input("Run installer now? [y/N]: ").strip().lower() in {"y", "yes"}
                install_system_tool(tool, manager=None, execute=execute)
            elif choice == "27":
                url = input("Base URL (https://example.com): ").strip()
                use_nikto = input("Run Nikto if installed? [y/N]: ").strip().lower() in {"y", "yes"}
                web_vulnerability_search(
                    url,
                    timeout=5.0,
                    delay=0.2,
                    use_searchsploit=True,
                    use_nikto=use_nikto,
                    nikto_timeout=180.0,
                )
            elif choice == "28":
                show_all = input("Show all connections? [y/N]: ").strip().lower() in {"y", "yes"}
                connection_watch(iterations=1, interval=3.0, show_all=show_all)
            elif choice == "29":
                path = input("Log file path: ").strip()
                alerts_only = input("Alerts only? [Y/n]: ").strip().lower() not in {"n", "no"}
                log_watch(path, lines=80, follow=False, duration=60, alerts_only=alerts_only)
            elif choice == "30":
                values = shlex.split(input("IOC values: ").strip())
                ioc_triage(values)
            elif choice == "31":
                target = input("Target host/IP: ").strip()
                url = input("Optional URL [blank]: ").strip() or None
                ports = input("Ports [common]: ").strip() or "common"
                live_workflow(target=target, url=url, ports=ports, timeout=0.7)
            elif choice == "32":
                print_exit_screen("Session closed from the interactive menu.", 0)
                break
            else:
                print("Invalid choice.")
        except (ValueError, OSError, ConnectionError, TimeoutError) as error:
            print(f"[ERROR] {error}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if not args.command:
            interactive_menu()
            return 0

        if args.command == "roadmap":
            results = print_roadmap(args.category)
        elif args.command == "tools":
            results = check_tools(args.category)
        elif args.command == "install-hints":
            results = print_install_hints(args.tool)
        elif args.command == "install-tool":
            results = install_system_tool(args.tool, manager=args.manager, execute=args.execute)
        elif args.command == "sudo-su":
            results = sudo_su(args.ktool_args, dry_run=args.dry_run)
        elif args.command == "password-audit":
            results = password_audit(
                args.file,
                min_length=args.min_length,
                require_upper=not args.no_upper,
                require_lower=not args.no_lower,
                require_digit=not args.no_digit,
                require_symbol=not args.no_symbol,
                show_values=args.show_values,
            )
        elif args.command == "password-check":
            password = args.password if args.password is not None else getpass.getpass("Password: ")
            results = password_strength(password, show_value=args.show_value)
        elif args.command == "password-generate":
            results = generate_password(
                length=args.length,
                count=args.count,
                no_symbols=args.no_symbols,
                no_ambiguous=args.no_ambiguous,
            )
        elif args.command == "admin-password":
            results = admin_password(
                username=args.username,
                length=args.length,
                rotate_after_days=args.rotate_after_days,
                output=args.output,
                no_symbols=args.no_symbols,
                no_ambiguous=args.no_ambiguous,
            )
        elif args.command == "awareness-plan":
            results = awareness_plan(args.company, args.audience)
        elif args.command == "local-posture":
            results = local_posture()
        elif args.command == "permission-guide":
            results = permission_guide(args.tool)
        elif args.command == "conn-watch":
            results = connection_watch(args.iterations, interval=args.interval, show_all=args.show_all)
        elif args.command == "log-watch":
            results = log_watch(args.file, lines=args.lines, follow=args.follow, duration=args.duration, alerts_only=args.alerts_only)
        elif args.command == "ioc-triage":
            results = ioc_triage(args.values)
        else:
            require_authorization(args.yes_i_am_authorized)

        if args.command == "dns":
            results = resolve_dns(args.domain)
        elif args.command == "whois":
            results = whois_lookup(
                args.domain,
                timeout=args.timeout,
                install_missing=args.install_missing,
                package_manager=args.package_manager,
            )
        elif args.command == "ports":
            workers = max(1, min(args.workers, 128))
            results = port_scanner(
                target=args.target,
                ports=parse_ports(args.ports),
                timeout=args.timeout,
                workers=workers,
                delay=args.delay,
            )
        elif args.command == "subs":
            results = subdomain_finder(args.domain, load_words(args.wordlist, DEFAULT_SUBDOMAINS))
        elif args.command == "headers":
            results = header_analyzer(args.url, timeout=args.timeout)
        elif args.command == "dirs":
            results = directory_scanner(
                args.url,
                paths=load_words(args.wordlist, DEFAULT_PATHS),
                timeout=args.timeout,
                delay=args.delay,
                show_all=args.show_all,
            )
        elif args.command == "web":
            results = web_baseline(args.url, timeout=args.timeout, delay=args.delay)
        elif args.command == "web-vuln-search":
            results = web_vulnerability_search(
                args.url,
                timeout=args.timeout,
                delay=args.delay,
                use_searchsploit=not args.no_searchsploit,
                use_nikto=args.nikto,
                nikto_timeout=args.nikto_timeout,
            )
        elif args.command == "nmap":
            results = nmap_scan(
                args.target,
                top_ports=args.top_ports,
                timeout=args.timeout,
                scripts=args.scripts,
                os_detect=args.os_detect,
                install_missing=args.install_missing,
                package_manager=args.package_manager,
            )
        elif args.command == "lan-scan":
            results = lan_scan(
                cidr=args.cidr,
                interface=args.interface,
                timeout=args.timeout,
                workers=args.workers,
                resolve_names=args.resolve_names,
                use_scapy=not args.no_scapy,
                install_missing=args.install_missing,
            )
        elif args.command == "capture":
            results = packet_capture(
                args.interface,
                duration=args.duration,
                count=args.count,
                output=args.output,
                install_missing=args.install_missing,
                package_manager=args.package_manager,
            )
        elif args.command == "scapy-sniff":
            results = scapy_sniff(
                interface=args.interface,
                duration=args.duration,
                count=args.count,
                bpf_filter=args.filter,
                output=args.output,
                install_missing=args.install_missing,
                traffic=args.traffic,
                suspicious_only=args.suspicious_only,
            )
        elif args.command == "ncat-chat":
            results = ncat_chat(
                mode=args.mode,
                host=args.host,
                port=args.port,
                bind=args.bind,
                message=args.message,
                timeout=args.timeout,
                install_missing=args.install_missing,
                package_manager=args.package_manager,
            )
        elif args.command == "live-workflow":
            results = live_workflow(
                target=args.target,
                url=args.url,
                ports=args.ports,
                timeout=args.timeout,
            )
        elif args.command == "wireless-info":
            results = wireless_info()
        elif args.command == "vuln-lookup":
            results = vuln_lookup(args.query, timeout=args.timeout)
        elif args.command in {
            "roadmap",
            "tools",
            "install-hints",
            "install-tool",
            "sudo-su",
            "password-audit",
            "password-check",
            "password-generate",
            "admin-password",
            "awareness-plan",
            "local-posture",
            "permission-guide",
            "conn-watch",
            "log-watch",
            "ioc-triage",
        }:
            pass
        else:
            parser.error(f"Unknown command: {args.command}")
            return 2

        save_report(args.report, args.command, results)
        return 0
    except KeyboardInterrupt:
        print_exit_screen("Interrupted with Ctrl+C.", 130)
        return 130
    except (ValueError, OSError, ConnectionError, TimeoutError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
