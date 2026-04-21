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
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
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


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def color(text: str, code: str) -> str:
    if not supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def clear_screen() -> None:
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "cls"], check=False)
    elif sys.stdout.isatty():
        print("\033[2J\033[H", end="")
    else:
        print()


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
    __ __ __              __
   / //_// /_____  ____  / /
  / ,<  / __/ __ \/ __ \/ / 
 / /| |/ /_/ /_/ / /_/ / /  
/_/ |_|\__/\____/\____/_/   
"""
    print(color(banner.rstrip(), "1;32"))
    print(color("        Ktool built for Linux ethical security assessment", "36"))
    print(color(f"        Built by: {TOOL_OWNER}", "36"))
    print(color("        Authorized testing only | Defensive by design", "90"))


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
        ("11", "Password Policy Audit"),
        ("12", "Packet Capture Sample"),
        ("13", "Wireless Interface Info"),
        ("14", "Vulnerability Lookup"),
        ("15", "Awareness Plan"),
        ("16", "Local Posture Review"),
        ("17", "Install Hints"),
        ("18", "Web Vulnerability Search"),
        ("19", "SEToolkit Info"),
        ("20", "Clear Screen"),
        ("21", "Restart Console"),
        ("22", "External Tool Examples"),
        ("23", "Exit"),
    ]
    width = 45
    border = "+" + "-" * width + "+"
    print()
    print(color(border, "32"))
    print(color("|", "32") + color(" Ktool Console ".center(width), "1;32") + color("|", "32"))
    print(color(border, "32"))
    for number, label in menu_items:
        line = f" [{number.rjust(2)}] {label}"
        print(color("|", "32") + line.ljust(width) + color("|", "32"))
    print(color(border, "32"))


TOOL_CATEGORIES = {
    "recon": {
        "title": "Reconnaissance",
        "skills": ["DNS lookup", "WHOIS lookup", "Subdomain discovery"],
        "tools": [
            "whois",
            "nslookup",
            "theHarvester",
            "amass",
            "sublist3r",
            "subfinder",
            "assetfinder",
            "dnsrecon",
            "dnsenum",
        ],
        "implemented": ["dns", "whois", "subs", "dns-enum", "passive-assets"],
    },
    "scan": {
        "title": "Scanning and Enumeration",
        "skills": ["TCP scanning", "Service detection", "Basic web exposure checks"],
        "tools": ["nmap", "masscan", "nc", "nikto", "rustscan", "enum4linux-ng", "smbclient", "snmpwalk"],
        "implemented": ["ports", "nmap", "fast-scan", "smb-enum", "snmp-enum"],
    },
    "web": {
        "title": "Web Application Testing",
        "skills": ["Security headers", "Common path discovery", "Proxy-based manual testing"],
        "tools": [
            "burpsuite",
            "zaproxy",
            "sqlmap",
            "ffuf",
            "gobuster",
            "feroxbuster",
            "nikto",
            "searchsploit",
            "whatweb",
            "httpx",
            "nuclei",
            "wapiti",
            "testssl.sh",
            "sslscan",
            "wafw00f",
            "waybackurls",
            "gau",
            "katana",
            "hakrawler",
            "dalfox",
            "xsstrike",
            "gowitness",
            "aquatone",
        ],
        "implemented": [
            "headers",
            "dirs",
            "web",
            "web-vuln-search",
            "fingerprint",
            "tls-audit",
            "content-discovery",
            "url-discovery",
            "web-scan",
            "screenshot-audit",
        ],
    },
    "passwords": {
        "title": "Password Security Testing",
        "skills": ["Password audit policy", "Weak password review", "Hash cracking in labs only"],
        "tools": ["hydra", "john", "hashcat"],
        "implemented": ["password-audit"],
    },
    "network": {
        "title": "Network Security Testing",
        "skills": ["TCP/IP", "Ports", "Firewalls", "VPNs", "Packet capture"],
        "tools": ["wireshark", "tcpdump", "ettercap", "traceroute", "mtr", "arp-scan"],
        "implemented": ["capture", "network-diagnostics", "local-network-discovery", "tools"],
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
        "tools": ["linpeas", "winpeas", "lynis", "chkrootkit", "rkhunter"],
        "implemented": ["local-posture", "linux-audit"],
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
    "testssl.sh": ["testssl.sh", "testssl"],
    "httpx": ["httpx", "httpx-toolkit"],
    "xsstrike": ["xsstrike", "XSStrike"],
    "gowitness": ["gowitness"],
    "enum4linux-ng": ["enum4linux-ng", "enum4linux-ng.py"],
    "arp-scan": ["arp-scan"],
}

INSTALL_HINTS = {
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
    "setoolkit": {
        "Kali": "sudo apt update && sudo apt install set",
        "GitHub": "git clone https://github.com/trustedsec/social-engineer-toolkit",
        "Manual setup": "cd social-engineer-toolkit && sudo pip3 install -r requirements.txt && sudo python3 setup.py",
        "Safety": "Use only for approved awareness training in isolated labs. Ktool does not run SET attack modules.",
    },
    "masscan": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install masscan",
        "Arch": "sudo pacman -S masscan",
        "Fedora": "sudo dnf install masscan",
    },
    "nc": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install netcat-openbsd",
        "Arch": "sudo pacman -S openbsd-netcat",
        "Fedora": "sudo dnf install nmap-ncat",
    },
    "theHarvester": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install theharvester",
        "Python": "python3 -m pip install theHarvester",
    },
    "sublist3r": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install sublist3r",
        "Python": "python3 -m pip install sublist3r",
    },
    "burpsuite": {
        "Kali": "sudo apt update && sudo apt install burpsuite",
        "Download": "https://portswigger.net/burp/communitydownload",
    },
    "zaproxy": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install zaproxy",
        "Download": "https://www.zaproxy.org/download/",
    },
    "sqlmap": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install sqlmap",
        "Python": "python3 -m pip install sqlmap",
        "Safety": "Use only for authorized validation. Ktool does not automate SQL injection exploitation.",
    },
    "hydra": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install hydra",
        "Arch": "sudo pacman -S hydra",
        "Safety": "Use only in labs. Ktool does not run password attacks.",
    },
    "john": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install john",
        "Arch": "sudo pacman -S john",
    },
    "hashcat": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install hashcat",
        "Arch": "sudo pacman -S hashcat",
    },
    "wireshark": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install wireshark",
        "Arch": "sudo pacman -S wireshark-qt",
    },
    "ettercap": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install ettercap-graphical",
        "Arch": "sudo pacman -S ettercap",
        "Safety": "Use only on owned lab networks. Ktool does not run MITM attacks.",
    },
    "aircrack-ng": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install aircrack-ng",
        "Arch": "sudo pacman -S aircrack-ng",
    },
    "airodump-ng": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install aircrack-ng",
        "Arch": "sudo pacman -S aircrack-ng",
    },
    "kismet": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install kismet",
        "Arch": "sudo pacman -S kismet",
    },
    "msfconsole": {
        "Kali": "sudo apt update && sudo apt install metasploit-framework",
        "Download": "https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html",
        "Safety": "Use only in controlled labs. Ktool does not run Metasploit modules.",
    },
    "linpeas": {
        "GitHub": "Download from https://github.com/peass-ng/PEASS-ng/releases",
        "Safety": "Use on your own hosts or authorized assessments only.",
    },
    "winpeas": {
        "GitHub": "Download from https://github.com/peass-ng/PEASS-ng/releases",
        "Safety": "Use on your own hosts or authorized assessments only.",
    },
    "whatweb": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install whatweb",
        "Arch": "sudo pacman -S whatweb",
        "Fedora": "sudo dnf install whatweb",
    },
    "httpx": {
        "Go install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "Kali": "sudo apt update && sudo apt install httpx-toolkit",
    },
    "nuclei": {
        "Go install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "Templates": "nuclei -update-templates",
    },
    "wapiti": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install wapiti",
        "Python": "python3 -m pip install wapiti3",
    },
    "testssl.sh": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install testssl.sh",
        "GitHub": "git clone https://github.com/drwetter/testssl.sh",
    },
    "sslscan": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install sslscan",
        "Arch": "sudo pacman -S sslscan",
        "Fedora": "sudo dnf install sslscan",
    },
    "gobuster": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install gobuster",
        "Go install": "go install github.com/OJ/gobuster/v3@latest",
    },
    "ffuf": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install ffuf",
        "Go install": "go install github.com/ffuf/ffuf/v2@latest",
    },
    "feroxbuster": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install feroxbuster",
        "Cargo": "cargo install feroxbuster",
    },
    "dnsrecon": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install dnsrecon",
        "Python": "python3 -m pip install dnsrecon",
    },
    "dnsenum": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install dnsenum",
    },
    "amass": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install amass",
        "Go install": "go install github.com/owasp-amass/amass/v4/...@master",
    },
    "subfinder": {
        "Go install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "assetfinder": {
        "Go install": "go install github.com/tomnomnom/assetfinder@latest",
    },
    "waybackurls": {
        "Go install": "go install github.com/tomnomnom/waybackurls@latest",
    },
    "gau": {
        "Go install": "go install github.com/lc/gau/v2/cmd/gau@latest",
    },
    "katana": {
        "Go install": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    },
    "hakrawler": {
        "Go install": "go install github.com/hakluke/hakrawler@latest",
    },
    "rustscan": {
        "Debian package": "Download a release from https://github.com/RustScan/RustScan/releases",
        "Cargo": "cargo install rustscan",
    },
    "enum4linux-ng": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install enum4linux-ng",
        "GitHub": "git clone https://github.com/cddmp/enum4linux-ng",
    },
    "smbclient": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install smbclient",
        "Arch": "sudo pacman -S smbclient",
        "Fedora": "sudo dnf install samba-client",
    },
    "snmpwalk": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install snmp",
        "Arch": "sudo pacman -S net-snmp",
        "Fedora": "sudo dnf install net-snmp-utils",
    },
    "traceroute": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install traceroute",
        "Arch": "sudo pacman -S traceroute",
        "Fedora": "sudo dnf install traceroute",
    },
    "mtr": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install mtr",
        "Arch": "sudo pacman -S mtr",
        "Fedora": "sudo dnf install mtr",
    },
    "arp-scan": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install arp-scan",
        "Arch": "sudo pacman -S arp-scan",
        "Fedora": "sudo dnf install arp-scan",
    },
    "lynis": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install lynis",
        "Arch": "sudo pacman -S lynis",
        "Fedora": "sudo dnf install lynis",
    },
    "chkrootkit": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install chkrootkit",
        "Arch": "sudo pacman -S chkrootkit",
    },
    "rkhunter": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install rkhunter",
        "Arch": "sudo pacman -S rkhunter",
        "Fedora": "sudo dnf install rkhunter",
    },
    "wafw00f": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install wafw00f",
        "Python": "python3 -m pip install wafw00f",
    },
    "xsstrike": {
        "GitHub": "git clone https://github.com/s0md3v/XSStrike",
        "Setup": "cd XSStrike && python3 -m pip install -r requirements.txt",
        "Safety": "Use only on authorized web apps and labs.",
    },
    "dalfox": {
        "Go install": "go install github.com/hahwul/dalfox/v2@latest",
    },
    "gowitness": {
        "Go install": "go install github.com/sensepost/gowitness@latest",
    },
    "aquatone": {
        "GitHub releases": "Download from https://github.com/michenriksen/aquatone/releases",
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


def whois_lookup(domain: str, timeout: float) -> dict[str, object]:
    domain = validate_host(domain).strip(".")
    whois_path = find_tool("whois")
    if not whois_path:
        raise ValueError("whois is not installed. Install it with your Linux package manager.")

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


def run_nikto_with_timeout(url: str, timeout: float) -> dict[str, object]:
    try:
        return run_nikto(url, timeout=timeout)
    except TimeoutError as error:
        message = str(error)
        print(f"[WARN] {message}")
        print("[i] Increase --nikto-timeout for deeper scans, or run without --nikto for faster checks.")
        return {
            "installed": True,
            "timed_out": True,
            "timeout_seconds": timeout,
            "error": message,
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
        nikto_result = run_nikto_with_timeout(normalized, timeout=nikto_timeout)

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


def print_external_tool_examples() -> dict[str, object]:
    examples = {
        "fingerprint": "ktool fingerprint https://example.com --tools whatweb,wafw00f,httpx --yes-i-am-authorized",
        "tls-audit": "ktool tls-audit https://example.com --tools testssl.sh,sslscan --yes-i-am-authorized",
        "content-discovery": "ktool content-discovery https://example.com --tool ffuf --wordlist /usr/share/wordlists/dirb/common.txt --yes-i-am-authorized",
        "dns-enum": "ktool dns-enum example.com --tools dnsrecon,subfinder,amass --yes-i-am-authorized",
        "url-discovery": "ktool url-discovery https://example.com --tools waybackurls,gau,katana --yes-i-am-authorized",
        "web-scan": "ktool web-scan https://example.com --tool nuclei --rate 20 --yes-i-am-authorized",
        "fast-scan": "ktool fast-scan 192.168.1.10 --tool rustscan --ports 1-1000 --yes-i-am-authorized",
        "smb-enum": "ktool smb-enum 192.168.1.10 --tool enum4linux-ng --yes-i-am-authorized",
        "snmp-enum": "ktool snmp-enum 192.168.1.10 --community public --yes-i-am-authorized",
        "network-diagnostics": "ktool network-diagnostics example.com --tools traceroute,mtr --yes-i-am-authorized",
        "local-network-discovery": "ktool local-network-discovery --interface eth0 --yes-i-am-authorized",
        "linux-audit": "ktool linux-audit --tools lynis,chkrootkit,rkhunter",
        "screenshot-audit": "ktool screenshot-audit https://example.com --tool gowitness --output screenshots --yes-i-am-authorized",
    }
    print("\n[+] External tool wrapper examples")
    print("[i] Install the underlying Linux tools first with: ktool install-hints <tool>")
    for name, command in examples.items():
        print(f"\n{name}:")
        print(f"  {command}")
    return examples


def run_external(command: list[str], timeout: float, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
            input=input_text,
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


def run_tool_command(
    tool: str,
    args: list[str],
    timeout: float,
    input_text: str | None = None,
    active: bool = False,
) -> dict[str, object]:
    tool_path = find_tool(tool)
    if not tool_path:
        print(f"[missing] {tool}")
        print(install_hint_text(tool))
        return {"tool": tool, "installed": False}

    command = [tool_path, *args]
    print(f"\n[+] Running {tool}: {' '.join(command)}")
    if active:
        print("[i] Active scanner. Use only on authorized targets and keep rate limits conservative.")

    try:
        result = run_external(command, timeout=timeout, input_text=input_text)
    except TimeoutError as error:
        message = str(error)
        print(f"[WARN] {message}")
        return {
            "tool": tool,
            "installed": True,
            "timed_out": True,
            "timeout_seconds": timeout,
            "error": message,
            "command": command,
        }

    output = result.stdout.strip()
    if output:
        print(output)
    if result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)

    return {
        "tool": tool,
        "installed": True,
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def split_tool_list(value: str | None, defaults: list[str]) -> list[str]:
    if not value:
        return defaults
    return [item.strip() for item in value.split(",") if item.strip()]


def host_from_url_or_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return parsed.hostname or value


def run_fingerprint(url: str, tools: list[str], timeout: float) -> dict[str, object]:
    normalized = normalize_url(url)
    results: dict[str, object] = {"url": normalized, "results": []}
    for tool in tools:
        if tool == "whatweb":
            result = run_tool_command("whatweb", ["--no-errors", normalized], timeout)
        elif tool == "wafw00f":
            result = run_tool_command("wafw00f", [normalized], timeout)
        elif tool == "httpx":
            result = run_tool_command("httpx", ["-silent", "-title", "-tech-detect", "-status-code"], timeout, input_text=normalized + "\n")
        else:
            print(f"[skip] Unsupported fingerprint tool: {tool}")
            result = {"tool": tool, "supported": False}
        results["results"].append(result)
    return results


def run_tls_audit(target: str, tools: list[str], timeout: float) -> dict[str, object]:
    normalized = normalize_url(target) if "://" in target else target
    host = host_from_url_or_host(normalized)
    results: dict[str, object] = {"target": normalized, "host": host, "results": []}
    for tool in tools:
        if tool == "testssl.sh":
            result = run_tool_command("testssl.sh", ["--quiet", "--fast", normalized], timeout, active=True)
        elif tool == "sslscan":
            result = run_tool_command("sslscan", [host], timeout, active=True)
        else:
            print(f"[skip] Unsupported TLS tool: {tool}")
            result = {"tool": tool, "supported": False}
        results["results"].append(result)
    return results


def run_content_discovery(
    url: str,
    tool: str,
    wordlist: str,
    timeout: float,
    rate: int,
    extensions: str | None,
) -> dict[str, object]:
    normalized = normalize_url(url)
    if not Path(wordlist).exists():
        raise ValueError(f"Wordlist not found: {wordlist}")

    if tool == "ffuf":
        target = normalized.rstrip("/") + "/FUZZ"
        args = ["-u", target, "-w", wordlist, "-rate", str(rate)]
        if extensions:
            args.extend(["-e", extensions])
    elif tool == "gobuster":
        args = ["dir", "-u", normalized, "-w", wordlist, "--delay", "100ms"]
        if extensions:
            args.extend(["-x", extensions])
    elif tool == "feroxbuster":
        args = ["-u", normalized, "-w", wordlist, "--rate-limit", str(rate)]
        if extensions:
            args.extend(["-x", extensions])
    else:
        raise ValueError(f"Unsupported content discovery tool: {tool}")

    return run_tool_command(tool, args, timeout, active=True)


def run_dns_enum(domain: str, tools: list[str], timeout: float) -> dict[str, object]:
    domain = validate_host(domain).strip(".")
    results: dict[str, object] = {"domain": domain, "results": []}
    for tool in tools:
        if tool == "dnsrecon":
            result = run_tool_command("dnsrecon", ["-d", domain], timeout, active=True)
        elif tool == "dnsenum":
            result = run_tool_command("dnsenum", [domain], timeout, active=True)
        elif tool == "amass":
            result = run_tool_command("amass", ["enum", "-passive", "-d", domain], timeout)
        elif tool == "subfinder":
            result = run_tool_command("subfinder", ["-silent", "-d", domain], timeout)
        elif tool == "assetfinder":
            result = run_tool_command("assetfinder", ["--subs-only", domain], timeout)
        else:
            print(f"[skip] Unsupported DNS enum tool: {tool}")
            result = {"tool": tool, "supported": False}
        results["results"].append(result)
    return results


def run_passive_assets(domain: str, tools: list[str], timeout: float) -> dict[str, object]:
    domain = validate_host(domain).strip(".")
    selected = tools or ["subfinder", "assetfinder", "amass"]
    return run_dns_enum(domain, selected, timeout)


def run_url_discovery(target: str, tools: list[str], timeout: float) -> dict[str, object]:
    normalized = normalize_url(target)
    host = host_from_url_or_host(normalized)
    results: dict[str, object] = {"target": normalized, "host": host, "results": []}
    for tool in tools:
        if tool == "waybackurls":
            result = run_tool_command("waybackurls", [], timeout, input_text=host + "\n")
        elif tool == "gau":
            result = run_tool_command("gau", [host], timeout)
        elif tool == "katana":
            result = run_tool_command("katana", ["-silent", "-u", normalized, "-d", "2"], timeout, active=True)
        elif tool == "hakrawler":
            result = run_tool_command("hakrawler", ["-plain"], timeout, input_text=normalized + "\n", active=True)
        else:
            print(f"[skip] Unsupported URL discovery tool: {tool}")
            result = {"tool": tool, "supported": False}
        results["results"].append(result)
    return results


def run_web_scan(url: str, tool: str, timeout: float, rate: int) -> dict[str, object]:
    normalized = normalize_url(url)
    if tool == "nuclei":
        args = ["-u", normalized, "-rl", str(rate), "-silent"]
    elif tool == "wapiti":
        args = ["-u", normalized, "--scope", "page", "--flush-session"]
    elif tool == "nikto":
        return run_nikto_with_timeout(normalized, timeout=timeout)
    elif tool == "dalfox":
        args = ["url", normalized, "--silence", "--worker", "5"]
    elif tool == "xsstrike":
        args = ["-u", normalized, "--crawl"]
    else:
        raise ValueError(f"Unsupported web scanner: {tool}")
    return run_tool_command(tool, args, timeout, active=True)


def run_fast_scan(target: str, tool: str, ports: str, timeout: float) -> dict[str, object]:
    target = validate_host(target)
    if tool == "rustscan":
        args = ["-a", target, "-p", ports, "--ulimit", "5000"]
    elif tool == "masscan":
        args = [target, "-p", ports, "--rate", "1000"]
    else:
        raise ValueError(f"Unsupported fast scan tool: {tool}")
    return run_tool_command(tool, args, timeout, active=True)


def run_smb_enum(target: str, tool: str, timeout: float) -> dict[str, object]:
    target = validate_host(target)
    if tool == "enum4linux-ng":
        args = ["-A", target]
    elif tool == "smbclient":
        args = ["-L", f"//{target}/", "-N"]
    else:
        raise ValueError(f"Unsupported SMB tool: {tool}")
    return run_tool_command(tool, args, timeout, active=True)


def run_snmp_enum(target: str, community: str, timeout: float) -> dict[str, object]:
    target = validate_host(target)
    return run_tool_command("snmpwalk", ["-v2c", "-c", community, target], timeout, active=True)


def run_network_diagnostics(target: str, tools: list[str], timeout: float) -> dict[str, object]:
    target = validate_host(target)
    results: dict[str, object] = {"target": target, "results": []}
    for tool in tools:
        if tool == "traceroute":
            result = run_tool_command("traceroute", [target], timeout)
        elif tool == "mtr":
            result = run_tool_command("mtr", ["-r", "-c", "10", target], timeout)
        else:
            print(f"[skip] Unsupported network diagnostic tool: {tool}")
            result = {"tool": tool, "supported": False}
        results["results"].append(result)
    return results


def run_local_network_discovery(interface: str | None, timeout: float) -> dict[str, object]:
    args = ["--localnet"]
    if interface:
        args.extend(["--interface", interface])
    return run_tool_command("arp-scan", args, timeout, active=True)


def run_linux_audit(tools: list[str], timeout: float) -> dict[str, object]:
    results: dict[str, object] = {"results": []}
    for tool in tools:
        if tool == "lynis":
            result = run_tool_command("lynis", ["audit", "system", "--quick"], timeout)
        elif tool == "chkrootkit":
            result = run_tool_command("chkrootkit", [], timeout)
        elif tool == "rkhunter":
            result = run_tool_command("rkhunter", ["--check", "--sk"], timeout)
        else:
            print(f"[skip] Unsupported Linux audit tool: {tool}")
            result = {"tool": tool, "supported": False}
        results["results"].append(result)
    return results


def run_screenshot_audit(url: str, tool: str, timeout: float, output: str) -> dict[str, object]:
    normalized = normalize_url(url)
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    if tool == "gowitness":
        args = ["scan", "single", "--url", normalized, "--screenshot-path", str(output_path)]
    elif tool == "aquatone":
        args = ["-out", str(output_path)]
        return run_tool_command("aquatone", args, timeout, input_text=normalized + "\n", active=True)
    else:
        raise ValueError(f"Unsupported screenshot tool: {tool}")
    return run_tool_command(tool, args, timeout, active=True)


def nmap_scan(
    target: str,
    top_ports: int,
    timeout: float,
    scripts: bool,
    os_detect: bool,
) -> dict[str, object]:
    target = validate_host(target)
    nmap_path = find_tool("nmap")
    if not nmap_path:
        raise ValueError("nmap is not installed. Install it first, then rerun this command.")
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


def packet_capture(interface: str, duration: int, count: int, output: str) -> dict[str, object]:
    tcpdump_path = find_tool("tcpdump")
    if not tcpdump_path:
        raise ValueError("tcpdump is not installed. Install tcpdump or use Wireshark manually.")
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


def setoolkit_info() -> dict[str, object]:
    path = find_tool("setoolkit")
    installed = path is not None
    print("\n[+] SEToolkit awareness support")
    print("[i] Ktool does not launch SET attack modules, credential harvesters, or phishing pages.")
    print("[i] Use SET only in approved training labs with written authorization.")
    if installed:
        print(f"[installed] setoolkit -> {path}")
    else:
        print("[missing] setoolkit")
        print()
        print(install_hint_text("setoolkit"))

    workflow = [
        "Define written training scope and audience.",
        "Use sanitized examples and controlled lab infrastructure.",
        "Do not collect real credentials.",
        "Measure training with reporting drills, quizzes, and debriefs.",
        "Document authorization, schedule, and success criteria.",
    ]
    print("\nSafe awareness workflow:")
    for item in workflow:
        print(f"  - {item}")

    return {
        "tool": "setoolkit",
        "installed": installed,
        "path": path,
        "github": "https://github.com/trustedsec/social-engineer-toolkit",
        "install_hints": INSTALL_HINTS["setoolkit"],
        "safe_workflow": workflow,
    }


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
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
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

    dns_parser = subparsers.add_parser("dns", help="Resolve DNS information for a host.")
    add_common_run_options(dns_parser)
    dns_parser.add_argument("domain", help="Domain or hostname to resolve.")

    whois_parser = subparsers.add_parser("whois", help="Run a WHOIS lookup using the system whois tool.")
    add_common_run_options(whois_parser)
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
    web_vuln_parser.add_argument("--nikto-timeout", type=float, default=900.0, help="Nikto timeout in seconds.")

    fingerprint_parser = subparsers.add_parser("fingerprint", help="Run web fingerprinting wrappers.")
    add_common_run_options(fingerprint_parser)
    fingerprint_parser.add_argument("url", help="URL to fingerprint.")
    fingerprint_parser.add_argument("--tools", default="whatweb,wafw00f,httpx", help="Comma-separated tools.")
    fingerprint_parser.add_argument("--timeout", type=float, default=60.0, help="Per-tool timeout in seconds.")

    tls_parser = subparsers.add_parser("tls-audit", help="Run TLS/SSL audit wrappers.")
    add_common_run_options(tls_parser)
    tls_parser.add_argument("target", help="HTTPS URL or host.")
    tls_parser.add_argument("--tools", default="testssl.sh,sslscan", help="Comma-separated tools.")
    tls_parser.add_argument("--timeout", type=float, default=300.0, help="Per-tool timeout in seconds.")

    content_parser = subparsers.add_parser("content-discovery", help="Run content/directory discovery wrappers.")
    add_common_run_options(content_parser)
    content_parser.add_argument("url", help="Base URL.")
    content_parser.add_argument("--tool", choices=["ffuf", "gobuster", "feroxbuster"], default="ffuf")
    content_parser.add_argument("--wordlist", required=True, help="Wordlist path.")
    content_parser.add_argument("--extensions", help="Optional extensions, for example php,txt,bak.")
    content_parser.add_argument("--rate", type=int, default=50, help="Conservative request rate.")
    content_parser.add_argument("--timeout", type=float, default=300.0, help="Command timeout in seconds.")

    dns_enum_parser = subparsers.add_parser("dns-enum", help="Run DNS/subdomain enumeration wrappers.")
    add_common_run_options(dns_enum_parser)
    dns_enum_parser.add_argument("domain", help="Domain to enumerate.")
    dns_enum_parser.add_argument("--tools", default="dnsrecon,subfinder,assetfinder,amass", help="Comma-separated tools.")
    dns_enum_parser.add_argument("--timeout", type=float, default=300.0, help="Per-tool timeout in seconds.")

    passive_parser = subparsers.add_parser("passive-assets", help="Run passive asset discovery wrappers.")
    add_common_run_options(passive_parser)
    passive_parser.add_argument("domain", help="Domain to enumerate.")
    passive_parser.add_argument("--tools", default="subfinder,assetfinder,amass", help="Comma-separated tools.")
    passive_parser.add_argument("--timeout", type=float, default=240.0, help="Per-tool timeout in seconds.")

    url_discovery_parser = subparsers.add_parser("url-discovery", help="Run URL discovery and crawler wrappers.")
    add_common_run_options(url_discovery_parser)
    url_discovery_parser.add_argument("url", help="Base URL or domain.")
    url_discovery_parser.add_argument("--tools", default="waybackurls,gau,katana,hakrawler", help="Comma-separated tools.")
    url_discovery_parser.add_argument("--timeout", type=float, default=240.0, help="Per-tool timeout in seconds.")

    web_scan_parser = subparsers.add_parser("web-scan", help="Run optional web scanner wrappers.")
    add_common_run_options(web_scan_parser)
    web_scan_parser.add_argument("url", help="Target URL.")
    web_scan_parser.add_argument("--tool", choices=["nuclei", "wapiti", "nikto", "dalfox", "xsstrike"], default="nuclei")
    web_scan_parser.add_argument("--rate", type=int, default=20, help="Conservative rate limit where supported.")
    web_scan_parser.add_argument("--timeout", type=float, default=900.0, help="Command timeout in seconds.")

    fast_scan_parser = subparsers.add_parser("fast-scan", help="Run fast port scanner wrappers.")
    add_common_run_options(fast_scan_parser)
    fast_scan_parser.add_argument("target", help="Target host/IP.")
    fast_scan_parser.add_argument("--tool", choices=["rustscan", "masscan"], default="rustscan")
    fast_scan_parser.add_argument("--ports", default="1-1000", help="Ports or ranges, for example 1-1000.")
    fast_scan_parser.add_argument("--timeout", type=float, default=240.0, help="Command timeout in seconds.")

    smb_parser = subparsers.add_parser("smb-enum", help="Run SMB enumeration wrappers.")
    add_common_run_options(smb_parser)
    smb_parser.add_argument("target", help="Target host/IP.")
    smb_parser.add_argument("--tool", choices=["enum4linux-ng", "smbclient"], default="enum4linux-ng")
    smb_parser.add_argument("--timeout", type=float, default=180.0, help="Command timeout in seconds.")

    snmp_parser = subparsers.add_parser("snmp-enum", help="Run SNMP enumeration with snmpwalk.")
    add_common_run_options(snmp_parser)
    snmp_parser.add_argument("target", help="Target host/IP.")
    snmp_parser.add_argument("--community", default="public", help="SNMP community string.")
    snmp_parser.add_argument("--timeout", type=float, default=120.0, help="Command timeout in seconds.")

    netdiag_parser = subparsers.add_parser("network-diagnostics", help="Run traceroute/mtr diagnostics.")
    add_common_run_options(netdiag_parser)
    netdiag_parser.add_argument("target", help="Target host/IP.")
    netdiag_parser.add_argument("--tools", default="traceroute,mtr", help="Comma-separated tools.")
    netdiag_parser.add_argument("--timeout", type=float, default=120.0, help="Per-tool timeout in seconds.")

    localnet_parser = subparsers.add_parser("local-network-discovery", help="Run local network discovery with arp-scan.")
    add_common_run_options(localnet_parser)
    localnet_parser.add_argument("--interface", help="Optional interface, for example eth0.")
    localnet_parser.add_argument("--timeout", type=float, default=120.0, help="Command timeout in seconds.")

    linux_audit_parser = subparsers.add_parser("linux-audit", help="Run defensive Linux audit wrappers.")
    linux_audit_parser.add_argument("--tools", default="lynis,chkrootkit,rkhunter", help="Comma-separated tools.")
    linux_audit_parser.add_argument("--timeout", type=float, default=600.0, help="Per-tool timeout in seconds.")
    linux_audit_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    screenshot_parser = subparsers.add_parser("screenshot-audit", help="Run screenshot capture wrappers.")
    add_common_run_options(screenshot_parser)
    screenshot_parser.add_argument("url", help="Target URL.")
    screenshot_parser.add_argument("--tool", choices=["gowitness", "aquatone"], default="gowitness")
    screenshot_parser.add_argument("--output", default="screenshots", help="Output directory.")
    screenshot_parser.add_argument("--timeout", type=float, default=240.0, help="Command timeout in seconds.")

    subparsers.add_parser("external-examples", help="Show external tool wrapper examples.")

    nmap_parser = subparsers.add_parser("nmap", help="Run a conservative nmap service scan.")
    add_common_run_options(nmap_parser)
    nmap_parser.add_argument("target", help="Hostname or IP address.")
    nmap_parser.add_argument("--top-ports", type=int, default=100, help="Number of top ports to scan.")
    nmap_parser.add_argument("--timeout", type=float, default=120.0, help="Command timeout in seconds.")
    nmap_parser.add_argument("--scripts", action="store_true", help="Include nmap default scripts (-sC).")
    nmap_parser.add_argument("--os-detect", action="store_true", help="Include OS detection (-O).")

    password_parser = subparsers.add_parser("password-audit", help="Audit a local password candidate file for weak values.")
    password_parser.add_argument("file", help="Path to a local password candidate file.")
    password_parser.add_argument("--min-length", type=int, default=12, help="Minimum acceptable length.")
    password_parser.add_argument("--no-upper", action="store_true", help="Do not require uppercase characters.")
    password_parser.add_argument("--no-lower", action="store_true", help="Do not require lowercase characters.")
    password_parser.add_argument("--no-digit", action="store_true", help="Do not require digits.")
    password_parser.add_argument("--no-symbol", action="store_true", help="Do not require symbols.")
    password_parser.add_argument("--show-values", action="store_true", help="Print weak password values in output.")
    password_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    capture_parser = subparsers.add_parser("capture", help="Capture packets with tcpdump for a short defensive sample.")
    add_common_run_options(capture_parser)
    capture_parser.add_argument("interface", help="Network interface, for example eth0 or wlan0.")
    capture_parser.add_argument("--duration", type=int, default=20, help="Maximum capture duration in seconds.")
    capture_parser.add_argument("--count", type=int, default=100, help="Maximum packet count.")
    capture_parser.add_argument("--output", default="capture.pcap", help="Output pcap file path.")

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

    setoolkit_parser = subparsers.add_parser("setoolkit-info", help="Show safe SEToolkit GitHub/install guidance.")
    setoolkit_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    posture_parser = subparsers.add_parser("local-posture", help="Run local defensive privilege-risk checks.")
    posture_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    subparsers.add_parser("clear", help="Clear the terminal screen.")
    subparsers.add_parser("restart", help="Start the interactive Ktool console.")
    subparsers.add_parser("Ktool", help="Start the interactive Ktool console.")

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
            elif choice == "12":
                interface = input("Interface (eth0/wlan0): ").strip()
                output = input("Output pcap [capture.pcap]: ").strip() or "capture.pcap"
                packet_capture(interface, duration=20, count=100, output=output)
            elif choice == "13":
                wireless_info()
            elif choice == "14":
                query = input("Searchsploit query (product/CVE/service): ").strip()
                vuln_lookup(query, timeout=30.0)
            elif choice == "15":
                company = input("Company name [the organization]: ").strip() or "the organization"
                audience = input("Audience [employees]: ").strip() or "employees"
                awareness_plan(company, audience)
            elif choice == "16":
                local_posture()
            elif choice == "17":
                tool = input("Tool name [all]: ").strip() or None
                print_install_hints(tool)
            elif choice == "18":
                url = input("Base URL (https://example.com): ").strip()
                use_nikto = input("Run Nikto if installed? [y/N]: ").strip().lower() in {"y", "yes"}
                web_vulnerability_search(
                    url,
                    timeout=5.0,
                    delay=0.2,
                    use_searchsploit=True,
                    use_nikto=use_nikto,
                    nikto_timeout=900.0,
                )
            elif choice == "19":
                setoolkit_info()
            elif choice == "20":
                clear_screen()
                print_startup_banner()
            elif choice == "21":
                clear_screen()
                print_startup_banner()
                print(color("[restarted] Ktool console restarted.", "1;32"))
            elif choice == "22":
                print_external_tool_examples()
            elif choice == "23":
                print_exit_screen("Session closed from the interactive menu.", 0)
                break
            else:
                command = choice.lower()
                if command == "clear":
                    clear_screen()
                    print_startup_banner()
                elif command in {"restart", "ktool"}:
                    clear_screen()
                    print_startup_banner()
                    print(color("[restarted] Ktool console restarted.", "1;32"))
                elif command in {"exit", "quit"}:
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
        if not args.command or args.command in {"restart", "Ktool"}:
            interactive_menu()
            return 0
        if args.command == "clear":
            clear_screen()
            return 0

        if args.command == "roadmap":
            results = print_roadmap(args.category)
        elif args.command == "tools":
            results = check_tools(args.category)
        elif args.command == "install-hints":
            results = print_install_hints(args.tool)
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
        elif args.command == "awareness-plan":
            results = awareness_plan(args.company, args.audience)
        elif args.command == "setoolkit-info":
            results = setoolkit_info()
        elif args.command == "local-posture":
            results = local_posture()
        elif args.command == "linux-audit":
            results = run_linux_audit(split_tool_list(args.tools, ["lynis", "chkrootkit", "rkhunter"]), timeout=args.timeout)
        elif args.command == "external-examples":
            results = print_external_tool_examples()
        else:
            require_authorization(args.yes_i_am_authorized)

        if args.command == "dns":
            results = resolve_dns(args.domain)
        elif args.command == "whois":
            results = whois_lookup(args.domain, timeout=args.timeout)
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
        elif args.command == "fingerprint":
            results = run_fingerprint(
                args.url,
                tools=split_tool_list(args.tools, ["whatweb", "wafw00f", "httpx"]),
                timeout=args.timeout,
            )
        elif args.command == "tls-audit":
            results = run_tls_audit(
                args.target,
                tools=split_tool_list(args.tools, ["testssl.sh", "sslscan"]),
                timeout=args.timeout,
            )
        elif args.command == "content-discovery":
            results = run_content_discovery(
                args.url,
                tool=args.tool,
                wordlist=args.wordlist,
                timeout=args.timeout,
                rate=args.rate,
                extensions=args.extensions,
            )
        elif args.command == "dns-enum":
            results = run_dns_enum(
                args.domain,
                tools=split_tool_list(args.tools, ["dnsrecon", "subfinder", "assetfinder", "amass"]),
                timeout=args.timeout,
            )
        elif args.command == "passive-assets":
            results = run_passive_assets(
                args.domain,
                tools=split_tool_list(args.tools, ["subfinder", "assetfinder", "amass"]),
                timeout=args.timeout,
            )
        elif args.command == "url-discovery":
            results = run_url_discovery(
                args.url,
                tools=split_tool_list(args.tools, ["waybackurls", "gau", "katana", "hakrawler"]),
                timeout=args.timeout,
            )
        elif args.command == "web-scan":
            results = run_web_scan(args.url, tool=args.tool, timeout=args.timeout, rate=args.rate)
        elif args.command == "fast-scan":
            results = run_fast_scan(args.target, tool=args.tool, ports=args.ports, timeout=args.timeout)
        elif args.command == "smb-enum":
            results = run_smb_enum(args.target, tool=args.tool, timeout=args.timeout)
        elif args.command == "snmp-enum":
            results = run_snmp_enum(args.target, community=args.community, timeout=args.timeout)
        elif args.command == "network-diagnostics":
            results = run_network_diagnostics(
                args.target,
                tools=split_tool_list(args.tools, ["traceroute", "mtr"]),
                timeout=args.timeout,
            )
        elif args.command == "local-network-discovery":
            results = run_local_network_discovery(args.interface, timeout=args.timeout)
        elif args.command == "screenshot-audit":
            results = run_screenshot_audit(args.url, tool=args.tool, timeout=args.timeout, output=args.output)
        elif args.command == "nmap":
            results = nmap_scan(
                args.target,
                top_ports=args.top_ports,
                timeout=args.timeout,
                scripts=args.scripts,
                os_detect=args.os_detect,
            )
        elif args.command == "capture":
            results = packet_capture(
                args.interface,
                duration=args.duration,
                count=args.count,
                output=args.output,
            )
        elif args.command == "wireless-info":
            results = wireless_info()
        elif args.command == "vuln-lookup":
            results = vuln_lookup(args.query, timeout=args.timeout)
        elif args.command in {
            "roadmap",
            "tools",
            "install-hints",
            "password-audit",
            "awareness-plan",
            "setoolkit-info",
            "local-posture",
            "linux-audit",
            "external-examples",
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
