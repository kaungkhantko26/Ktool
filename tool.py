#!/usr/bin/env python3
"""
KTOOL LabOps - Linux-friendly lab and assessment console.

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
import pty
import re
import select
import secrets
import signal
import shlex
import shutil
import socket
import ssl
import stat
import string
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
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

TOOL_NAME = "KTOOL LabOps"
TOOL_VERSION = "3.1.0"
TOOL_OWNER = "LabOps user"
TOOL_TAGLINE = "authorized lab and web assessment console"
TOOL_COMMAND = "ktool"
MYANMAR_FLAG = "🇲🇲"
USER_AGENT = "KTOOL-LabOps/3.0 (+authorized-security-testing)"
TERMINAL_WIDTH = 78
SHODAN_API_KEY_ENV = "SHODAN_API_KEY"
NVD_API_KEY_ENV = "NVD_API_KEY"
VIRUSTOTAL_API_KEY_ENV = "VIRUSTOTAL_API_KEY"
HTTP_RETRY_ATTEMPTS = 2

PACKAGE_NAMES = {
    "hatch": {"brew": "hatch"},
    "amass": {"apt": "amass", "dnf": "amass", "pacman": "amass", "brew": "amass"},
    "dirb": {"apt": "dirb"},
    "docker": {"apt": "docker.io", "dnf": "docker", "pacman": "docker", "brew": "docker"},
    "dnsrecon": {"apt": "dnsrecon", "brew": "dnsrecon"},
    "ffuf": {"apt": "ffuf", "pacman": "ffuf", "brew": "ffuf"},
    "gobuster": {"apt": "gobuster", "pacman": "gobuster", "brew": "gobuster"},
    "nmap": {"apt": "nmap", "dnf": "nmap", "pacman": "nmap", "brew": "nmap"},
    "ncat": {"apt": "ncat", "dnf": "nmap-ncat", "pacman": "nmap", "brew": "nmap"},
    "nc": {"apt": "netcat-openbsd", "dnf": "nmap-ncat", "pacman": "openbsd-netcat", "brew": "netcat"},
    "seclists": {"apt": "seclists", "pacman": "seclists", "brew": "seclists"},
    "searchsploit": {"apt": "exploitdb", "dnf": "exploitdb", "pacman": "exploitdb"},
    "ssh": {"apt": "openssh-client", "dnf": "openssh-clients", "pacman": "openssh", "brew": "openssh"},
    "sslscan": {"apt": "sslscan", "dnf": "sslscan", "pacman": "sslscan", "brew": "sslscan"},
    "whois": {"apt": "whois", "dnf": "whois", "pacman": "whois", "brew": "whois"},
    "tcpdump": {"apt": "tcpdump", "dnf": "tcpdump", "pacman": "tcpdump", "brew": "tcpdump"},
    "nikto": {"apt": "nikto", "dnf": "nikto", "pacman": "nikto", "brew": "nikto"},
    "wafw00f": {"apt": "wafw00f", "pacman": "wafw00f", "brew": "wafw00f"},
    "whatweb": {"apt": "whatweb", "pacman": "whatweb", "brew": "whatweb"},
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
PHISHING_BRAND_MARKERS = {
    "apple",
    "icloud",
    "google",
    "microsoft",
    "office",
    "paypal",
    "binance",
    "coinbase",
    "facebook",
    "telegram",
    "whatsapp",
    "bank",
}
IOC_REGEXES = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,24})\b"),
    "url": re.compile(r"https?://[^\s'\"<>]+", re.I),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}
ANDROID_DANGEROUS_PERMISSIONS = {
    "android.permission.ACCEPT_HANDOVER",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BODY_SENSORS",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.GET_ACCOUNTS",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.USE_SIP",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}
ANDROID_SENSITIVE_PERMISSIONS = ANDROID_DANGEROUS_PERMISSIONS | {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_LOGS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.USE_FULL_SCREEN_INTENT",
    "android.permission.VPN_SERVICE",
    "android.permission.WRITE_SETTINGS",
}
MOBILE_AUDIT_EXTENSIONS = {
    ".xml",
    ".json",
    ".txt",
    ".properties",
    ".gradle",
    ".smali",
    ".java",
    ".kt",
    ".js",
    ".ts",
    ".html",
    ".md",
    ".yml",
    ".yaml",
}
MOBILE_SUSPICIOUS_PATTERNS = [
    ("high", "cleartext_url", re.compile(r"http://[^\s'\"<>]+", re.I)),
    ("high", "hardcoded_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I)),
    ("high", "hardcoded_secret", re.compile(r"(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"][^'\"]{8,}", re.I)),
    ("medium", "dynamic_code_loading", re.compile(r"\b(DexClassLoader|PathClassLoader|loadDex|loadClass)\b", re.I)),
    ("medium", "native_library_loading", re.compile(r"\b(System\.loadLibrary|System\.load)\b", re.I)),
    ("medium", "reflection_usage", re.compile(r"\b(Class\.forName|getDeclaredMethod|invoke\()\b", re.I)),
    ("medium", "crypto_marker", re.compile(r"\b(AES|DESede|RSA/ECB|XOR|Base64\.decode|javax\.crypto)\b", re.I)),
    ("medium", "root_or_debug_marker", re.compile(r"\b(su\b|magisk|xposed|frida|isDebuggerConnected|ro\.debuggable)\b", re.I)),
    ("medium", "accessibility_marker", re.compile(r"\bAccessibilityService\b|BIND_ACCESSIBILITY_SERVICE", re.I)),
    ("medium", "boot_persistence_marker", re.compile(r"\bBOOT_COMPLETED\b|RECEIVE_BOOT_COMPLETED", re.I)),
    ("low", "webview_javascript", re.compile(r"\bsetJavaScriptEnabled\s*\(\s*true\s*\)", re.I)),
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
    title = f"{MYANMAR_FLAG} {TOOL_NAME} Console"
    lines = [
        title,
        TOOL_TAGLINE,
        f"Profile: {TOOL_OWNER}",
        "",
        reason,
        "No tasks are still running.",
        "Session complete. Keep authorization and notes with the workspace.",
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
██╗  ██╗████████╗ ██████╗  ██████╗ ██╗      ██╗      █████╗ ██████╗  ██████╗ ██████╗ ███████╗
██║ ██╔╝╚══██╔══╝██╔═══██╗██╔═══██╗██║      ██║     ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
█████╔╝    ██║   ██║   ██║██║   ██║██║      ██║     ███████║██████╔╝██║   ██║██████╔╝███████╗
██╔═██╗    ██║   ██║   ██║██║   ██║██║      ██║     ██╔══██║██╔══██╗██║   ██║██╔═══╝ ╚════██║
██║  ██╗   ██║   ╚██████╔╝╚██████╔╝███████╗ ███████╗██║  ██║██████╔╝╚██████╔╝██║     ███████║
╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝
"""
    print(color(banner.rstrip(), "1;32"))
    print(color(f"        {MYANMAR_FLAG} {TOOL_NAME}", "1;33"))
    print(color(f"        {TOOL_TAGLINE}", "36"))
    print(color(f"        profile: {TOOL_OWNER}", "36"))
    print(color(f"        version: {TOOL_VERSION}", "36"))
    print(color("        workflow: doctor | target-brief | recon | web | tryhackme | local defense", "90"))
    print(color("        active checks require explicit permission or a lab target", "90"))


def print_menu_panel() -> None:
    menu_groups = [
        (
            "START",
            [
                ("1", "Skill Roadmap"),
                ("2", "Tool Availability Check"),
                ("46", "Operator Doctor"),
                ("25", "Install Hints"),
                ("26", "Install Tool"),
                ("39", "Workflow Examples"),
                ("40", "SecLists Finder"),
            ],
        ),
        (
            "RECON",
            [
                ("3", "DNS Lookup"),
                ("4", "WHOIS Lookup"),
                ("5", "TCP Port Check"),
                ("6", "Subdomain Resolver"),
                ("10", "nmap First Pass"),
                ("22", "Vulnerability Lookup"),
                ("35", "Shodan Host Intelligence"),
                ("36", "NVD CVE Lookup"),
            ],
        ),
        (
            "WEB",
            [
                ("7", "HTTP Header Analyzer"),
                ("8", "Common Path Probe"),
                ("9", "Safe Web Baseline"),
                ("27", "Web Risk Baseline"),
                ("41", "Content Discovery: Gobuster / FFUF / Dirb"),
            ],
        ),
        (
            "LABS",
            [
                ("31", "Live Target Workflow"),
                ("47", "Target Brief Workflow"),
                ("42", "Lab Workspace Setup"),
                ("43", "TryHackMe Room Workflow"),
            ],
        ),
        (
            "LOCAL DEFENSE",
            [
                ("11", "LAN Device Inventory"),
                ("12", "Scapy Packet Sniffer"),
                ("20", "Packet Capture"),
                ("21", "Wireless Interface Info"),
                ("24", "Local Posture Review"),
                ("44", "VPS Health Check"),
                ("28", "Live Connection Watch"),
                ("29", "Log Watch"),
                ("30", "IOC Triage"),
                ("33", "Threat Site Triage"),
                ("34", "Defang / Refang IOC"),
                ("37", "VirusTotal IOC Lookup"),
                ("38", "Mobile Artifact Audit"),
            ],
        ),
        (
            "UTILITIES",
            [
                ("13", "Password Strength Check"),
                ("14", "Password Generator"),
                ("15", "ncat Port Messenger"),
                ("16", "Admin Password Generator"),
                ("17", "Run LabOps as Root"),
                ("18", "Permission Guide"),
                ("19", "Password Policy Audit"),
                ("23", "Awareness Plan Builder"),
                ("32", "Hatch Runner"),
                ("45", "Exit"),
            ],
        ),
    ]
    width = 70
    border = "+" + "-" * width + "+"
    print()
    print(color(border, "32"))
    print(color("|", "32") + color(f" {MYANMAR_FLAG} {TOOL_NAME.upper()} ".center(width), "1;32") + color("|", "32"))
    print(color("|", "32") + color(" pick a workflow, then follow the prompts ".center(width), "90") + color("|", "32"))
    print(color("|", "32") + color(" shortcuts: ? help | q quit | 45 exit ".center(width), "90") + color("|", "32"))
    print(color(border, "32"))
    for title, items in menu_groups:
        print(color("|", "32") + color(f" {title} ".ljust(width), "1;36") + color("|", "32"))
        for number, label in items:
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
        "skills": ["Security headers", "Common path discovery", "Fingerprinting", "Proxy-based manual testing"],
        "tools": ["burpsuite", "zaproxy", "gobuster", "ffuf", "dirb", "seclists", "whatweb", "wafw00f", "nikto", "searchsploit"],
        "implemented": ["headers", "dirs", "web", "web-vuln-search", "content-discovery", "fingerprint", "web-scan", "js-audit"],
    },
    "threat": {
        "title": "Threat Site Investigation",
        "skills": ["Phishing triage", "IOC extraction", "Evidence collection", "Threat intelligence enrichment", "Takedown support"],
        "tools": ["whois", "nslookup", "hatch", "VirusTotal"],
        "implemented": ["threat-site-triage", "defang", "virustotal"],
    },
    "intel": {
        "title": "Exposure and Vulnerability Intelligence",
        "skills": ["Passive internet exposure review", "CVE research", "Service-to-risk mapping", "TLS review", "Mobile artifact triage"],
        "tools": ["Shodan", "NVD", "VirusTotal", "searchsploit", "apktool", "testssl.sh", "sslscan", "nuclei"],
        "implemented": ["shodan", "cve-lookup", "virustotal", "vuln-lookup", "tls-audit", "mobile-artifact-audit"],
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
    "tooling": {
        "title": "Developer Tooling",
        "skills": ["Python project environments", "Build automation", "Task runner integration", "Lab workspace setup"],
        "tools": ["hatch"],
        "implemented": ["hatch", "lab-init", "external-examples", "seclists-find"],
    },
    "vps": {
        "title": "VPS Operations",
        "skills": ["Storage checks", "PM2 process review", "Service status", "Read-only SSH health checks", "Deployment directory inventory"],
        "tools": ["ssh", "pm2", "docker", "systemctl", "journalctl", "df", "du", "ls", "ss"],
        "implemented": ["vps-check"],
    },
}

TOOL_ALIASES = {
    "burpsuite": ["burpsuite", "burp-suite", "BurpSuiteCommunity"],
    "zaproxy": ["zaproxy", "owasp-zap", "zap"],
    "sublist3r": ["sublist3r", "Sublist3r"],
    "amass": ["amass"],
    "dirb": ["dirb"],
    "docker": ["docker"],
    "aircrack-ng": ["aircrack-ng"],
    "airodump-ng": ["airodump-ng"],
    "dnsrecon": ["dnsrecon"],
    "ffuf": ["ffuf"],
    "gau": ["gau"],
    "gobuster": ["gobuster"],
    "httpx": ["httpx", "httpx-toolkit"],
    "katana": ["katana"],
    "msfconsole": ["msfconsole"],
    "nuclei": ["nuclei"],
    "retire": ["retire", "retirejs"],
    "semgrep": ["semgrep"],
    "setoolkit": ["setoolkit", "setoolkit-launcher"],
    "sslscan": ["sslscan"],
    "subfinder": ["subfinder"],
    "testssl.sh": ["testssl.sh", "testssl"],
    "theHarvester": ["theHarvester", "theharvester"],
    "linpeas": ["linpeas", "linpeas.sh"],
    "nikto": ["nikto", "nikto.pl"],
    "ncat": ["ncat", "nc"],
    "nc": ["nc", "ncat", "netcat"],
    "hatch": ["hatch"],
    "pm2": ["pm2"],
    "ssh": ["ssh"],
    "trufflehog": ["trufflehog"],
    "wafw00f": ["wafw00f"],
    "waybackurls": ["waybackurls"],
    "whatweb": ["whatweb"],
}

SECLISTS_ROOT_CANDIDATES = [
    "/usr/share/seclists",
    "/usr/share/SecLists",
    "/opt/SecLists",
    "/usr/local/share/seclists",
    "/usr/local/opt/seclists/share/seclists",
    str(Path.home() / "SecLists"),
]

SECLISTS_WORDLISTS = {
    "directory-small": [
        "Discovery/Web-Content/directory-list-2.3-small.txt",
        "Discovery/Web-Content/common.txt",
    ],
    "directory-medium": [
        "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "Discovery/Web-Content/raft-medium-directories.txt",
    ],
    "web-common": [
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/quickhits.txt",
    ],
    "api": [
        "Discovery/Web-Content/api/api-endpoints.txt",
        "Discovery/Web-Content/api/objects.txt",
    ],
    "subdomains": [
        "Discovery/DNS/subdomains-top1million-5000.txt",
        "Discovery/DNS/namelist.txt",
    ],
}

EXTERNAL_WRAPPER_TOOLS = {
    "fingerprint": ["whatweb", "wafw00f", "httpx"],
    "tls-audit": ["testssl.sh", "sslscan", "nmap"],
    "dns-enum": ["dnsrecon", "subfinder", "amass"],
    "url-discovery": ["waybackurls", "gau", "katana"],
    "web-scan": ["nuclei", "nikto"],
    "js-audit": ["retire", "semgrep", "trufflehog"],
}

INSTALL_HINTS = {
    "hatch": {
        "Python user install": "python3 -m pip install --user hatch",
        "pipx": "pipx install hatch",
        "macOS": "brew install hatch",
        "LabOps": "ktool hatch --install-missing -- --version",
    },
    "gobuster": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install gobuster",
        "Arch": "sudo pacman -S gobuster",
        "macOS": "brew install gobuster",
        "LabOps": "ktool install-tool gobuster --execute",
    },
    "dirb": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install dirb",
        "Kali": "dirb is usually available from the Kali repositories.",
        "Manual": "Use Gobuster or FFUF if your platform does not package Dirb.",
        "LabOps": "ktool install-tool dirb --execute",
    },
    "ssh": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install openssh-client",
        "Fedora": "sudo dnf install openssh-clients",
        "Arch": "sudo pacman -S openssh",
        "macOS": "brew install openssh",
    },
    "pm2": {
        "npm": "npm install -g pm2",
        "Check": "pm2 list",
        "Docs": "https://pm2.keymetrics.io/",
    },
    "docker": {
        "Debian/Ubuntu": "sudo apt update && sudo apt install docker.io",
        "Fedora": "sudo dnf install docker",
        "Arch": "sudo pacman -S docker",
        "macOS": "brew install --cask docker",
    },
    "ffuf": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install ffuf",
        "Arch": "sudo pacman -S ffuf",
        "macOS": "brew install ffuf",
        "Go": "go install github.com/ffuf/ffuf/v2@latest",
    },
    "seclists": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install seclists",
        "Arch": "sudo pacman -S seclists",
        "macOS": "brew install seclists",
        "Git": "git clone https://github.com/danielmiessler/SecLists.git ~/SecLists",
    },
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
    "whatweb": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install whatweb",
        "Arch": "sudo pacman -S whatweb",
        "macOS": "brew install whatweb",
    },
    "wafw00f": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install wafw00f",
        "Arch": "sudo pacman -S wafw00f",
        "Python": "python3 -m pip install --user wafw00f",
    },
    "httpx": {
        "Go": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "ProjectDiscovery": "https://github.com/projectdiscovery/httpx",
    },
    "testssl.sh": {
        "Git": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/tools/testssl.sh",
        "Run": "~/tools/testssl.sh/testssl.sh --fast https://example.com",
    },
    "sslscan": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install sslscan",
        "Arch": "sudo pacman -S sslscan",
        "Fedora": "sudo dnf install sslscan",
        "macOS": "brew install sslscan",
    },
    "dnsrecon": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install dnsrecon",
        "Python": "python3 -m pip install --user dnsrecon",
    },
    "subfinder": {
        "Go": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "ProjectDiscovery": "https://github.com/projectdiscovery/subfinder",
    },
    "amass": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install amass",
        "Arch": "sudo pacman -S amass",
        "macOS": "brew install amass",
    },
    "waybackurls": {
        "Go": "go install github.com/tomnomnom/waybackurls@latest",
    },
    "gau": {
        "Go": "go install github.com/lc/gau/v2/cmd/gau@latest",
    },
    "katana": {
        "Go": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    },
    "nuclei": {
        "Go": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "Templates": "nuclei -update-templates",
    },
    "retire": {
        "npm": "npm install -g retire",
    },
    "semgrep": {
        "Python": "python3 -m pip install --user semgrep",
        "pipx": "pipx install semgrep",
    },
    "trufflehog": {
        "GitHub release": "https://github.com/trufflesecurity/trufflehog/releases",
        "macOS": "brew install trufflehog",
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
    print(color("[scope check]", "1;33"))
    print("Continue only for your own systems, a lab target, or written-scope work.")
    answer = input("Confirm authorization for this activity? [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        print_exit_screen("Scope confirmation was not provided.", 1)
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


def json_ready(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_ready(item) for item in value]
    return value


def write_json_output(path: str | Path, payload: object) -> Path:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(json_ready(payload), indent=2) + "\n", encoding="utf-8")
    return output_path


def should_retry_url_error(error: URLError) -> bool:
    reason = getattr(error, "reason", error)
    return isinstance(reason, (TimeoutError, socket.timeout, ConnectionResetError, ssl.SSLError, OSError))


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
    for attempt in range(HTTP_RETRY_ATTEMPTS):
        try:
            with urlopen(request, timeout=timeout, context=context) as response:
                body = response.read(1024 * 128)
                return response.status, dict(response.headers.items()), body
        except HTTPError as error:
            body = error.read(1024 * 128)
            return error.code, dict(error.headers.items()), body
        except URLError as error:
            if attempt + 1 < HTTP_RETRY_ATTEMPTS and should_retry_url_error(error):
                time.sleep(0.25 * (attempt + 1))
                continue
            reason = getattr(error, "reason", error)
            raise ConnectionError(str(reason)) from error
    raise ConnectionError(f"HTTP request failed for {url}")


def api_key_value(provided: str | None, env_name: str, service_name: str) -> str:
    api_key = (provided or os.environ.get(env_name) or "").strip()
    if not api_key:
        raise ValueError(f"{service_name} API key required. Pass --api-key or set {env_name}.")
    return api_key


def http_json_request(
    url: str,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    if headers:
        request_headers.update(headers)

    request = Request(url, headers=request_headers)
    for attempt in range(HTTP_RETRY_ATTEMPTS):
        try:
            with urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
                body = response.read(1024 * 1024)
                return json.loads(body.decode("utf-8", errors="replace"))
        except HTTPError as error:
            body = error.read(64 * 1024).decode("utf-8", errors="replace")
            message = body
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    message = str(parsed.get("message") or parsed.get("error") or parsed)
            except json.JSONDecodeError:
                pass
            raise ConnectionError(f"HTTP {error.code}: {message}") from error
        except URLError as error:
            if attempt + 1 < HTTP_RETRY_ATTEMPTS and should_retry_url_error(error):
                time.sleep(0.25 * (attempt + 1))
                continue
            reason = getattr(error, "reason", error)
            raise ConnectionError(str(reason)) from error
        except json.JSONDecodeError as error:
            raise ConnectionError(f"API response was not valid JSON: {error}") from error
    raise ConnectionError(f"API request failed for {url}")


def first_public_ip(target: str) -> tuple[str, str | None]:
    target = validate_host(target)
    try:
        address = ipaddress.ip_address(target)
        return str(address), None
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError(f"Could not resolve target for API lookup: {target}: {error}") from None
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise ValueError(f"No addresses resolved for {target}.")
    return addresses[0], target


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


def summarize_shodan_service(banner: dict[str, object]) -> dict[str, object]:
    ssl_info = banner.get("ssl") if isinstance(banner.get("ssl"), dict) else {}
    vulns = banner.get("vulns") if isinstance(banner.get("vulns"), dict) else {}
    return {
        "ip": banner.get("ip_str"),
        "port": banner.get("port"),
        "transport": banner.get("transport", "tcp"),
        "product": banner.get("product"),
        "version": banner.get("version"),
        "hostnames": banner.get("hostnames", []),
        "domains": banner.get("domains", []),
        "org": banner.get("org"),
        "isp": banner.get("isp"),
        "asn": banner.get("asn"),
        "timestamp": banner.get("timestamp"),
        "ssl_versions": sorted(ssl_info.get("versions", [])) if isinstance(ssl_info.get("versions"), list) else [],
        "cves": sorted(vulns)[:25],
        "banner_sample": str(banner.get("data") or "").strip()[:500],
    }


def shodan_lookup(
    target: str,
    api_key: str | None,
    timeout: float,
    history: bool,
    minify: bool,
) -> dict[str, object]:
    key = api_key_value(api_key, SHODAN_API_KEY_ENV, "Shodan")
    ip, resolved_from = first_public_ip(target)
    params = {"key": key, "history": str(history).lower(), "minify": str(minify).lower()}
    url = f"https://api.shodan.io/shodan/host/{ip}?{urlencode(params)}"

    print_section("Shodan Host Intelligence")
    cyber_line("target", target)
    if resolved_from:
        cyber_line("resolved ip", ip)
    print("[i] Passive Shodan lookup only. This does not request a new internet scan.")

    data = http_json_request(url, timeout=timeout)
    banners = data.get("data") if isinstance(data.get("data"), list) else []
    services = [
        summarize_shodan_service(banner)
        for banner in banners
        if isinstance(banner, dict)
    ]

    summary = {
        "ip": data.get("ip_str", ip),
        "hostnames": data.get("hostnames", []),
        "domains": data.get("domains", []),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "country": data.get("country_name") or data.get("country_code"),
        "os": data.get("os"),
        "last_update": data.get("last_update"),
        "ports": sorted(data.get("ports", [])) if isinstance(data.get("ports"), list) else [],
    }

    print_key_value_table(
        [
            ("ip", str(summary["ip"])),
            ("org", str(summary.get("org") or "unknown")),
            ("asn", str(summary.get("asn") or "unknown")),
            ("country", str(summary.get("country") or "unknown")),
            ("last update", str(summary.get("last_update") or "unknown")),
            ("ports", ", ".join(str(port) for port in summary["ports"]) or "none"),
        ]
    )

    if services:
        print("\n[Services]")
        for service in services[:25]:
            product = " ".join(
                str(value)
                for value in (service.get("product"), service.get("version"))
                if value
            ) or "unknown service"
            cves = service.get("cves") or []
            cve_text = f" CVEs={','.join(str(cve) for cve in cves[:5])}" if cves else ""
            print(f"  - {service.get('port')}/{service.get('transport')} {product}{cve_text}")
        if len(services) > 25:
            print(f"[i] Showing first 25 services out of {len(services)}.")
    elif minify and summary["ports"]:
        print("[i] Minified response returned host metadata and ports only.")
    else:
        print("[i] Shodan returned no service banners for this host.")

    return {
        "target": target,
        "resolved_from": resolved_from,
        "ip": ip,
        "history": history,
        "minify": minify,
        "summary": summary,
        "services": services,
        "source": "https://api.shodan.io/shodan/host/{ip}",
    }


def cve_metric_summary(metrics: dict[str, object]) -> dict[str, object]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not isinstance(values, list) or not values:
            continue
        metric = values[0] if isinstance(values[0], dict) else {}
        cvss_data = metric.get("cvssData") if isinstance(metric.get("cvssData"), dict) else {}
        return {
            "source": metric.get("source"),
            "version": cvss_data.get("version") or key.replace("cvssMetric", "CVSS "),
            "base_score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity") or metric.get("baseSeverity"),
            "vector": cvss_data.get("vectorString"),
        }
    return {}


def summarize_nvd_vulnerability(vulnerability: dict[str, object]) -> dict[str, object]:
    cve = vulnerability.get("cve") if isinstance(vulnerability.get("cve"), dict) else {}
    descriptions = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
    english_description = ""
    for description in descriptions:
        if isinstance(description, dict) and description.get("lang") == "en":
            english_description = str(description.get("value") or "")
            break

    references = cve.get("references") if isinstance(cve.get("references"), list) else []
    reference_urls = [
        str(item.get("url"))
        for item in references
        if isinstance(item, dict) and item.get("url")
    ][:8]

    weaknesses = cve.get("weaknesses") if isinstance(cve.get("weaknesses"), list) else []
    weakness_ids: list[str] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for description in weakness.get("description", []):
            if isinstance(description, dict) and description.get("value"):
                weakness_ids.append(str(description["value"]))

    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": english_description[:700],
        "metric": cve_metric_summary(cve.get("metrics", {}) if isinstance(cve.get("metrics"), dict) else {}),
        "weaknesses": sorted(set(weakness_ids)),
        "references": reference_urls,
        "kev": {
            "listed": bool(cve.get("cisaExploitAdd")),
            "added": cve.get("cisaExploitAdd"),
            "due": cve.get("cisaActionDue"),
            "required_action": cve.get("cisaRequiredAction"),
            "name": cve.get("cisaVulnerabilityName"),
        },
    }


def cve_database_lookup(
    query: str,
    api_key: str | None,
    timeout: float,
    limit: int,
    exact: bool,
    severity: str | None,
    kev_only: bool,
) -> dict[str, object]:
    query = query.strip()
    if not query:
        raise ValueError("CVE lookup query cannot be empty.")
    if limit < 1 or limit > 50:
        raise ValueError("--limit must be between 1 and 50.")
    if severity and severity.upper() not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValueError("--severity must be one of LOW, MEDIUM, HIGH, CRITICAL.")

    params: dict[str, object] = {"resultsPerPage": limit, "noRejected": ""}
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", query, re.IGNORECASE):
        params["cveId"] = query.upper()
    else:
        params["keywordSearch"] = query
        if exact:
            params["keywordExactMatch"] = ""
    if severity:
        params["cvssV3Severity"] = severity.upper()

    query_parts = urlencode({key: value for key, value in params.items() if value != ""})
    if "noRejected" in params:
        query_parts += ("&" if query_parts else "") + "noRejected"
    if "keywordExactMatch" in params:
        query_parts += "&keywordExactMatch"
    if kev_only:
        query_parts += "&hasKev"

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query_parts}"
    headers = {}
    key = (api_key or os.environ.get(NVD_API_KEY_ENV) or "").strip()
    if key:
        headers["apiKey"] = key

    print_section("CVE Database Lookup")
    cyber_line("source", "NVD CVE API 2.0")
    cyber_line("query", query)
    if severity:
        cyber_line("severity", severity.upper())
    if kev_only:
        cyber_line("filter", "CISA KEV listed")

    data = http_json_request(url, timeout=timeout, headers=headers or None)
    vulnerabilities = data.get("vulnerabilities") if isinstance(data.get("vulnerabilities"), list) else []
    summaries = [
        summarize_nvd_vulnerability(item)
        for item in vulnerabilities
        if isinstance(item, dict)
    ]

    cyber_line("total matches", str(data.get("totalResults", len(summaries))))
    if summaries:
        print("\n[CVEs]")
        for item in summaries:
            metric = item.get("metric") if isinstance(item.get("metric"), dict) else {}
            sev = str(metric.get("severity") or "UNKNOWN")
            score = metric.get("base_score")
            kev = " KEV" if isinstance(item.get("kev"), dict) and item["kev"].get("listed") else ""
            print(f"  - {item.get('id')} {sev} {score if score is not None else '-'}{kev}")
            description = str(item.get("description") or "")
            if description:
                print(f"    {description[:180]}{'...' if len(description) > 180 else ''}")
    else:
        print("[i] No NVD CVE records matched the query.")

    return {
        "query": query,
        "limit": limit,
        "exact": exact,
        "severity": severity.upper() if severity else None,
        "kev_only": kev_only,
        "total_results": data.get("totalResults"),
        "results": summaries,
        "source": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    }


def virustotal_lookup(indicator: str, api_key: str | None, timeout: float) -> dict[str, object]:
    indicator = indicator.strip()
    if not indicator:
        raise ValueError("VirusTotal indicator cannot be empty.")
    key = api_key_value(api_key, VIRUSTOTAL_API_KEY_ENV, "VirusTotal")
    url = f"https://www.virustotal.com/api/v3/search?{urlencode({'query': indicator, 'limit': 1})}"

    print_section("VirusTotal Intelligence")
    cyber_line("indicator", defang_value(indicator))
    print(f"[i] Reputation lookup only. {TOOL_NAME} does not upload files or submit URL scans.")

    data = http_json_request(url, timeout=timeout, headers={"x-apikey": key})
    matches = data.get("data") if isinstance(data.get("data"), list) else []
    result: dict[str, object] = {
        "indicator": indicator,
        "matched": False,
        "summary": {},
        "source": "https://www.virustotal.com/api/v3/search",
    }
    if not matches:
        print("[i] VirusTotal returned no matching objects.")
        return result

    first = matches[0] if isinstance(matches[0], dict) else {}
    attributes = first.get("attributes") if isinstance(first.get("attributes"), dict) else {}
    stats = attributes.get("last_analysis_stats") if isinstance(attributes.get("last_analysis_stats"), dict) else {}
    summary = {
        "id": first.get("id"),
        "type": first.get("type"),
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": stats,
        "tags": attributes.get("tags", []),
        "categories": attributes.get("categories", {}),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "meaningful_name": attributes.get("meaningful_name"),
    }
    result["matched"] = True
    result["summary"] = summary

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    print_key_value_table(
        [
            ("type", str(summary.get("type") or "unknown")),
            ("id", str(summary.get("id") or "unknown")),
            ("reputation", str(summary.get("reputation") if summary.get("reputation") is not None else "unknown")),
            ("malicious", str(malicious)),
            ("suspicious", str(suspicious)),
        ]
    )
    tags = summary.get("tags")
    if isinstance(tags, list) and tags:
        print(f"[tags] {', '.join(str(tag) for tag in tags[:15])}")
    return result


def defang_value(value: str) -> str:
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
        .replace("@", "[@]")
    )


def refang_value(value: str) -> str:
    return (
        value.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
        .replace("[@]", "@")
    )


def defang_iocs(values: list[str], refang: bool = False) -> list[dict[str, str]]:
    if not values:
        raise ValueError("Provide at least one value.")
    print_section("IOC Defang" if not refang else "IOC Refang")
    results: list[dict[str, str]] = []
    for value in values:
        converted = refang_value(value) if refang else defang_value(value)
        print(f"{value} -> {converted}")
        results.append({"input": value, "output": converted})
    return results


def extract_iocs_from_text(text: str, base_url: str | None = None) -> dict[str, list[str]]:
    found: dict[str, set[str]] = {key: set() for key in IOC_REGEXES}
    for kind, pattern in IOC_REGEXES.items():
        for match in pattern.findall(text):
            value = match.rstrip(").,;]")
            if kind == "url" and base_url:
                value = urljoin(base_url, value)
            found[kind].add(value)
    return {kind: sorted(values)[:100] for kind, values in found.items()}


def tls_certificate_summary(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, object]:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
    return {
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": cert.get("subjectAltName", []),
    }


def phishing_indicators(url: str, headers: dict[str, str], body: bytes) -> list[dict[str, str]]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    text = body.decode("utf-8", errors="ignore")[:128000]
    lower_text = text.lower()
    indicators: list[dict[str, str]] = []

    if re.search(r"<input[^>]+type=[\"']?password", lower_text):
        indicators.append({"severity": "high", "indicator": "password input present"})
    if re.search(r"<form[^>]+action=[\"']?http://", lower_text):
        indicators.append({"severity": "high", "indicator": "form posts to cleartext HTTP"})

    form_actions = re.findall(r"<form[^>]+action=[\"']?([^\"'\s>]+)", text, re.I)
    for action in form_actions[:10]:
        action_host = urlparse(urljoin(url, action)).hostname
        if action_host and host and action_host.lower() != host.lower():
            indicators.append({"severity": "high", "indicator": f"form posts to external host {action_host}"})

    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    if title:
        for brand in PHISHING_BRAND_MARKERS:
            if brand in title.lower() and brand not in host.lower():
                indicators.append({"severity": "medium", "indicator": f"title references brand not in hostname: {brand}"})

    for keyword in ("verify your account", "account suspended", "unusual activity", "confirm your identity", "gift card"):
        if keyword in lower_text:
            indicators.append({"severity": "medium", "indicator": f"phishing phrase: {keyword}"})

    if "Content-Security-Policy" not in headers:
        indicators.append({"severity": "low", "indicator": "missing Content-Security-Policy"})
    if parsed.scheme == "http":
        indicators.append({"severity": "medium", "indicator": "cleartext HTTP page"})

    unique: list[dict[str, str]] = []
    seen: set[str] = set()
    for indicator in indicators:
        key = indicator["indicator"]
        if key not in seen:
            seen.add(key)
            unique.append(indicator)
    return unique


def threat_site_triage(url: str, timeout: float, fetch_body: bool, output_markdown: str | None) -> dict[str, object]:
    normalized = normalize_url(refang_value(url))
    parsed = urlparse(normalized)
    host = parsed.hostname
    if not host:
        raise ValueError("URL must include a hostname.")

    print_section("Threat Site Triage")
    cyber_line("url", normalized)
    cyber_line("defanged", defang_value(normalized))
    print("[i] Defensive evidence collection only. Do not attack or disrupt third-party systems.")

    result: dict[str, object] = {
        "url": normalized,
        "defanged_url": defang_value(normalized),
        "host": host,
        "dns": {},
        "http": {},
        "tls": None,
        "iocs": {},
        "indicators": [],
        "takedown_report": None,
    }

    try:
        result["dns"] = resolve_dns(host)
    except ValueError as error:
        result["dns"] = {"error": str(error)}

    if parsed.scheme == "https":
        try:
            result["tls"] = tls_certificate_summary(host, timeout=timeout)
            print("[TLS] certificate collected")
        except (OSError, ssl.SSLError, TimeoutError) as error:
            result["tls"] = {"error": str(error)}
            print(f"[TLS] {error}")

    method = "GET" if fetch_body else "HEAD"
    try:
        status, headers, body = http_request(normalized, method=method, timeout=timeout)
        result["http"] = {
            "method": method,
            "status": status,
            "headers": headers,
            "body_sample_bytes": len(body),
        }
        print(f"[HTTP] {method} {status} ({len(body)} sampled bytes)")
        if fetch_body:
            result["iocs"] = extract_iocs_from_text(body.decode("utf-8", errors="ignore"), base_url=normalized)
            result["indicators"] = phishing_indicators(normalized, headers, body)
    except (ConnectionError, OSError) as error:
        result["http"] = {"method": method, "error": str(error)}
        print(f"[HTTP] {error}")

    indicators = result.get("indicators", [])
    if indicators:
        print("\n[Indicators]")
        for indicator in indicators:
            print(f"[{indicator['severity'].upper()}] {indicator['indicator']}")

    report_text = build_takedown_report(result)
    result["takedown_report"] = report_text
    if output_markdown:
        Path(output_markdown).write_text(report_text, encoding="utf-8")
        print(f"\n[+] Takedown evidence report saved to {output_markdown}")
    return result


def build_takedown_report(result: dict[str, object]) -> str:
    http_data = result.get("http") if isinstance(result.get("http"), dict) else {}
    indicators = result.get("indicators") if isinstance(result.get("indicators"), list) else []
    lines = [
        "# Threat Site Evidence Report",
        "",
        f"- URL: {result.get('defanged_url')}",
        f"- Host: {result.get('host')}",
        f"- Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        f"- HTTP status: {http_data.get('status', http_data.get('error', 'unknown')) if isinstance(http_data, dict) else 'unknown'}",
        "",
        "## Indicators",
    ]
    if indicators:
        for indicator in indicators:
            lines.append(f"- {indicator['severity'].upper()}: {indicator['indicator']}")
    else:
        lines.append("- No local phishing indicators found in sampled content.")
    lines.extend(
        [
            "",
            "## Recommended Actions",
            "- Preserve this report with timestamps and source context.",
            "- Submit to the registrar, hosting provider, CDN, and brand abuse mailbox where applicable.",
            "- Block the defanged URL/domain in approved security controls if policy allows.",
            "- Do not run exploit, brute force, or denial-of-service activity against the site.",
        ]
    )
    return "\n".join(lines) + "\n"


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


def install_tools_for_category(category: str, manager: str | None, execute: bool) -> dict[str, object]:
    if category not in TOOL_CATEGORIES:
        raise ValueError(f"Unknown category: {category}. Choices: {', '.join(sorted(TOOL_CATEGORIES))}")

    tools = [tool for tool in TOOL_CATEGORIES[category]["tools"] if tool in PACKAGE_NAMES]
    skipped = [tool for tool in TOOL_CATEGORIES[category]["tools"] if tool not in PACKAGE_NAMES]
    print_section("Batch Installer")
    cyber_line("category", category)
    cyber_line("mode", "execute" if execute else "dry-run")
    if skipped:
        print("[i] Skipping tools without package-manager mappings: " + ", ".join(skipped))

    results = []
    for tool in tools:
        try:
            results.append(install_system_tool(tool, manager=manager, execute=execute))
        except ValueError as error:
            print(f"[skip] {tool}: {error}")
            results.append({"tool": tool, "error": str(error), "executed": False})
    return {"category": category, "manager": manager or detect_package_manager(), "executed": execute, "results": results, "skipped": skipped}


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


def find_hatch() -> str | None:
    hatch_path = find_tool("hatch")
    if hatch_path:
        return hatch_path
    user_hatch = Path.home() / ".local" / "bin" / "hatch"
    if user_hatch.exists() and os.access(user_hatch, os.X_OK):
        return str(user_hatch)
    return None


def ensure_hatch(auto_install: bool = False) -> str | None:
    hatch_path = find_hatch()
    if hatch_path:
        return hatch_path
    if not auto_install:
        return None

    command = [sys.executable, "-m", "pip", "install", "--user", "hatch"]
    print_section("Hatch Installer")
    cyber_line("command", " ".join(command))
    result = run_external(command, timeout=900)
    output = result.stdout.strip() or result.stderr.strip()
    if output:
        print(output)
    return find_hatch()


def hatch_tool(
    hatch_args: list[str],
    install_missing: bool,
    timeout: float,
    dry_run: bool,
) -> dict[str, object]:
    args = list(hatch_args)
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        args = ["--version"]

    hatch_path = ensure_hatch(auto_install=install_missing)
    if dry_run and not hatch_path:
        hatch_path = "hatch"
    if not hatch_path:
        raise ValueError("hatch is not installed. Use `ktool hatch --install-missing -- --version` or see `ktool install-hints hatch`.")

    command = [hatch_path, *args]
    print_section("Hatch Tool")
    cyber_line("command", " ".join(shlex.quote(part) for part in command))
    print("[i] Running the official Hatch CLI locally for Python project/tooling workflows.")

    if dry_run:
        return {"command": command, "executed": False}

    result = run_external(command, timeout=timeout)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)
    return {
        "command": command,
        "executed": True,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def split_tool_names(value: str | None, allowed: list[str]) -> list[str]:
    if not value:
        return allowed
    selected = [item.strip() for item in value.split(",") if item.strip()]
    unknown = [item for item in selected if item not in allowed]
    if unknown:
        raise ValueError(f"Unsupported tool(s): {', '.join(unknown)}. Choices: {', '.join(allowed)}")
    return selected


def target_domain(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value.strip().split("/")[0]
    return validate_host(host).strip(".")


def target_port_from_url(value: str, default: int = 443) -> tuple[str, int]:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = parsed.hostname or validate_host(value)
    port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else default)
    return host, port


def find_seclists_roots() -> list[Path]:
    roots = []
    for candidate in SECLISTS_ROOT_CANDIDATES:
        path = Path(candidate).expanduser()
        if path.exists() and path.is_dir():
            roots.append(path)
    return roots


def find_seclists_wordlist(category: str) -> Path | None:
    if category not in SECLISTS_WORDLISTS:
        raise ValueError(f"Unknown SecLists category: {category}. Choices: {', '.join(sorted(SECLISTS_WORDLISTS))}")
    for root in find_seclists_roots():
        for relative in SECLISTS_WORDLISTS[category]:
            candidate = root / relative
            if candidate.exists() and candidate.is_file():
                return candidate
    return None


def seclists_find(category: str | None = None) -> dict[str, object]:
    categories = [category] if category else sorted(SECLISTS_WORDLISTS)
    roots = find_seclists_roots()
    print_section("SecLists Discovery")
    cyber_line("roots", ", ".join(str(root) for root in roots) if roots else "not found")
    if not roots:
        print(install_hint_text("seclists"))

    results: dict[str, object] = {"roots": [str(root) for root in roots], "wordlists": {}}
    for name in categories:
        found = find_seclists_wordlist(name)
        results["wordlists"][name] = str(found) if found else None
        status = str(found) if found else "missing"
        print(f"  - {name}: {status}")
    return results


def print_external_examples() -> dict[str, object]:
    examples = {
        "content-discovery": "ktool content-discovery https://target --tool gobuster --wordlist-kind directory-small --yes-i-am-authorized",
        "gobuster alias": "ktool gobuster https://target --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --yes-i-am-authorized",
        "dirb alias": "ktool dirb https://target --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt --yes-i-am-authorized",
        "fingerprint": "ktool fingerprint https://target --tools whatweb,wafw00f,httpx --yes-i-am-authorized",
        "tls-audit": "ktool tls-audit https://target --tools testssl.sh,sslscan --yes-i-am-authorized",
        "dns-enum": "ktool dns-enum target.tld --tools dnsrecon,subfinder,amass --yes-i-am-authorized",
        "url-discovery": "ktool url-discovery https://target --tools waybackurls,gau,katana --yes-i-am-authorized",
        "web-scan": "ktool web-scan https://target --tool nuclei --rate 20 --yes-i-am-authorized",
        "js-audit": "ktool js-audit https://target --tools retire,semgrep,trufflehog --output js-downloads --yes-i-am-authorized",
        "lab workspace": "ktool lab-init tryhackme-room --target 10.10.10.10 --client TryHackMe",
    }
    print_section("External Tool Examples")
    print("[i] These wrappers run installed tools only against authorized targets or labs.")
    for name, command in examples.items():
        print(f"\n[{name}]\n  {command}")
    return {"examples": examples, "tool_groups": EXTERNAL_WRAPPER_TOOLS}


def run_external_checked(
    tool: str,
    args: list[str],
    timeout: float,
    install_missing: bool,
    package_manager: str | None,
    dry_run: bool,
) -> dict[str, object]:
    tool_path = find_tool(tool)
    if not tool_path and install_missing and tool in PACKAGE_NAMES:
        tool_path = ensure_tool(tool, auto_install=True, manager=package_manager)
    if dry_run and not tool_path:
        tool_path = tool
    if not tool_path:
        print(f"\n[missing] {tool}")
        print(install_hint_text(tool))
        return {"tool": tool, "installed": False, "hint": INSTALL_HINTS.get(tool)}

    command = [tool_path, *args]
    print(f"\n[{tool}] {' '.join(shlex.quote(part) for part in command)}")
    if dry_run:
        return {"tool": tool, "installed": True, "command": command, "executed": False}

    result = run_external(command, timeout=timeout)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip(), file=sys.stderr)
    return {
        "tool": tool,
        "installed": True,
        "command": command,
        "executed": True,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def content_discovery(
    url: str,
    tool: str,
    wordlist: str | None,
    wordlist_kind: str,
    extensions: str | None,
    status_codes: str,
    threads: int,
    rate: int,
    timeout: float,
    output: str | None,
    install_missing: bool,
    package_manager: str | None,
    dry_run: bool,
) -> dict[str, object]:
    normalized = normalize_url(url)
    if tool not in {"gobuster", "ffuf", "dirb"}:
        raise ValueError("--tool must be gobuster, ffuf, or dirb.")
    if threads < 1 or threads > 100:
        raise ValueError("--threads must be between 1 and 100.")
    if rate < 1 or rate > 1000:
        raise ValueError("--rate must be between 1 and 1000.")

    selected_wordlist = Path(wordlist).expanduser() if wordlist else find_seclists_wordlist(wordlist_kind)
    if not selected_wordlist or not selected_wordlist.exists():
        raise ValueError(
            f"No wordlist found for {wordlist_kind}. Pass --wordlist or install SecLists.\n"
            + install_hint_text("seclists")
        )

    print_section("Content Discovery")
    cyber_line("url", normalized)
    cyber_line("tool", tool)
    cyber_line("wordlist", str(selected_wordlist))
    print("[i] Directory/content discovery is active traffic. Keep it inside authorized scope.")

    if tool == "gobuster":
        args = ["dir", "-u", normalized, "-w", str(selected_wordlist), "-t", str(threads), "--timeout", f"{int(timeout)}s"]
        if extensions:
            args.extend(["-x", extensions])
        if status_codes:
            args.extend(["-s", status_codes])
        if output:
            args.extend(["-o", output])
    elif tool == "ffuf":
        fuzz_url = normalized.rstrip("/") + "/FUZZ"
        args = ["-u", fuzz_url, "-w", str(selected_wordlist), "-t", str(threads), "-rate", str(rate), "-mc", status_codes]
        if extensions:
            args.extend(["-e", extensions])
        if output:
            args.extend(["-o", output])
    else:
        args = [normalized, str(selected_wordlist)]
        if extensions:
            args.extend(["-X", extensions])
        if output:
            args.extend(["-o", output])
        if status_codes:
            print("[i] Dirb does not support the same status-code filter as Gobuster/FFUF; status filter ignored.")

    return {
        "url": normalized,
        "wordlist": str(selected_wordlist),
        "result": run_external_checked(tool, args, timeout=timeout + 30, install_missing=install_missing, package_manager=package_manager, dry_run=dry_run),
    }


def external_web_wrapper(
    wrapper: str,
    target: str,
    tools_value: str | None,
    timeout: float,
    rate: int,
    output: str | None,
    install_missing: bool,
    package_manager: str | None,
    dry_run: bool,
) -> dict[str, object]:
    allowed = EXTERNAL_WRAPPER_TOOLS[wrapper]
    selected_tools = split_tool_names(tools_value, allowed)
    normalized_url = normalize_url(target) if wrapper in {"fingerprint", "tls-audit", "url-discovery", "web-scan", "js-audit"} else target_domain(target)
    domain = target_domain(normalized_url)
    host, port = target_port_from_url(normalized_url)

    print_section(wrapper.replace("-", " "))
    cyber_line("target", normalized_url)
    cyber_line("tools", ", ".join(selected_tools))
    print("[i] Wrapper mode: runs installed tools with conservative defaults; no exploitation or credential attacks.")

    results: list[dict[str, object]] = []
    for tool in selected_tools:
        if wrapper == "fingerprint":
            args = {
                "whatweb": ["--no-errors", normalized_url],
                "wafw00f": [normalized_url],
                "httpx": ["-u", normalized_url, "-silent", "-title", "-tech-detect", "-status-code"],
            }[tool]
        elif wrapper == "tls-audit":
            args = {
                "testssl.sh": ["--fast", normalized_url],
                "sslscan": [normalized_url],
                "nmap": ["-sV", "--script", "ssl-enum-ciphers", "-p", str(port), host],
            }[tool]
        elif wrapper == "dns-enum":
            args = {
                "dnsrecon": ["-d", domain],
                "subfinder": ["-d", domain, "-silent"],
                "amass": ["enum", "-passive", "-d", domain],
            }[tool]
        elif wrapper == "url-discovery":
            args = {
                "waybackurls": [domain],
                "gau": [domain],
                "katana": ["-u", normalized_url, "-silent", "-d", "2", "-rl", str(rate)],
            }[tool]
        elif wrapper == "web-scan":
            args = {
                "nuclei": ["-u", normalized_url, "-rl", str(rate), "-severity", "low,medium,high,critical", "-silent"],
                "nikto": ["-host", normalized_url, "-nointeractive"],
            }[tool]
        else:
            args = []
        if output and tool in {"httpx", "subfinder", "amass", "katana", "nuclei"}:
            args.extend(["-o", output])
        results.append(run_external_checked(tool, args, timeout, install_missing, package_manager, dry_run))

    return {"wrapper": wrapper, "target": normalized_url, "tools": selected_tools, "results": results}


def extract_javascript_urls(url: str, timeout: float) -> list[str]:
    normalized = normalize_url(url)
    status, _, body = http_request(normalized, method="GET", timeout=timeout)
    if status >= 500:
        print(f"[i] Page returned HTTP {status}; still checking any sampled body content.")
    html = body.decode("utf-8", errors="ignore")
    scripts = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html, flags=re.I)
    return sorted({urljoin(normalized, script) for script in scripts})


def js_audit(
    url: str,
    tools_value: str | None,
    output: str,
    timeout: float,
    install_missing: bool,
    package_manager: str | None,
    dry_run: bool,
) -> dict[str, object]:
    normalized = normalize_url(url)
    selected_tools = split_tool_names(tools_value, EXTERNAL_WRAPPER_TOOLS["js-audit"])
    output_dir = Path(output).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)

    print_section("JavaScript Audit")
    cyber_line("url", normalized)
    cyber_line("output", str(output_dir))
    print("[i] Downloads same-page JavaScript assets for local dependency/secret-pattern review.")

    script_urls = extract_javascript_urls(normalized, timeout=timeout)
    downloaded: list[str] = []
    for index, script_url in enumerate(script_urls[:50], start=1):
        try:
            _, _, body = http_request(script_url, method="GET", timeout=timeout)
        except ConnectionError as error:
            print(f"[skip] {script_url}: {error}")
            continue
        filename = output_dir / f"script-{index:03d}.js"
        filename.write_bytes(body)
        downloaded.append(str(filename))
        print(f"[js] {script_url} -> {filename}")

    tool_results = []
    for tool in selected_tools:
        args = {
            "retire": ["--path", str(output_dir)],
            "semgrep": ["--config", "auto", str(output_dir)],
            "trufflehog": ["filesystem", str(output_dir), "--no-update"],
        }[tool]
        tool_results.append(run_external_checked(tool, args, timeout, install_missing, package_manager, dry_run))

    return {"url": normalized, "scripts": script_urls, "downloaded": downloaded, "tools": selected_tools, "results": tool_results}


def slugify_name(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip()).strip("-").lower()
    return slug or "engagement"


def lab_init(name: str, client: str, target: str, output_dir: str | None) -> dict[str, object]:
    slug = slugify_name(name)
    base_dir = Path(output_dir or f"engagements/{slug}").expanduser()
    paths = {
        "base": base_dir,
        "evidence": base_dir / "evidence",
        "findings": base_dir / "findings",
        "reports": base_dir / "reports",
        "scans": base_dir / "scans",
        "notes": base_dir / "notes",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)

    scope = {
        "name": name,
        "client": client,
        "target": target,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "authorization": "lab/owned/written-scope target required before active tests",
    }
    (base_dir / "scope.json").write_text(json.dumps(scope, indent=2) + "\n", encoding="utf-8")
    (base_dir / "notes" / "README.md").write_text(
        f"# {name}\n\n- Client/lab: {client}\n- Target: {target}\n- Created UTC: {scope['created_at']}\n\n## Notes\n\n",
        encoding="utf-8",
    )
    print_section("Lab Workspace")
    print_key_value_table([(key, str(path)) for key, path in paths.items()])
    return {"workspace": str(base_dir), "scope": scope, "paths": {key: str(path) for key, path in paths.items()}}


def infer_web_url(target: str, ports: list[PortResult]) -> str | None:
    open_ports = {item.port for item in ports}
    for port in (443, 8443, 9443):
        if port in open_ports:
            suffix = "" if port == 443 else f":{port}"
            return f"https://{target}{suffix}"
    for port in (80, 8080, 8000):
        if port in open_ports:
            suffix = "" if port == 80 else f":{port}"
            return f"http://{target}{suffix}"
    return None


def build_target_brief_markdown(result: dict[str, object]) -> str:
    target = str(result.get("target", "unknown"))
    workspace = str(result.get("workspace", ""))
    url = result.get("url")
    ports = result.get("ports", [])
    open_ports = ", ".join(f"{item['port']}/tcp" for item in ports[:12]) if isinstance(ports, list) and ports else "none detected"
    dns = result.get("dns", {})
    addresses = dns.get("addresses", []) if isinstance(dns, dict) else []
    web = result.get("web", {}) if isinstance(result.get("web"), dict) else {}
    header_result = web.get("headers", {})
    missing_headers = header_result.get("missing_security_headers", []) if isinstance(header_result, dict) else []
    paths = web.get("paths", []) if isinstance(web.get("paths"), list) else []
    accessible_paths = [item["url"] for item in paths if isinstance(item, dict) and isinstance(item.get("status"), int) and item["status"] < 400][:8]

    lines = [
        "# Target Brief",
        "",
        f"- Target: {target}",
        f"- Workspace: {workspace}",
        f"- Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        f"- Web URL: {url or 'not inferred'}",
        f"- Resolved addresses: {', '.join(addresses) if addresses else 'none'}",
        f"- Open ports: {open_ports}",
        "",
        "## High-Value Notes",
    ]

    if missing_headers:
        lines.append(f"- Missing security headers: {', '.join(missing_headers)}")
    if accessible_paths:
        lines.append("- Accessible common paths:")
        for path in accessible_paths:
            lines.append(f"  - {path}")
    if not missing_headers and not accessible_paths:
        lines.append("- No immediate web hygiene findings were identified in the first-pass sample.")

    lines.extend(
        [
            "",
            "## Suggested Next Steps",
            f"- Run `ktool nmap {shlex.quote(target)} --top-ports 1000 --yes-i-am-authorized` for deeper service coverage.",
        ]
    )
    if url:
        lines.append(f"- Run `ktool web {shlex.quote(str(url))} --yes-i-am-authorized` for a focused web hygiene baseline.")
        lines.append(f"- Run `ktool content-discovery {shlex.quote(str(url))} --wordlist-kind directory-small --yes-i-am-authorized` if web scope is approved.")
    lines.append("- Save screenshots, raw output, and operator notes under this workspace before moving to deeper validation.")
    return "\n".join(lines) + "\n"


def target_brief(
    target: str,
    name: str | None,
    url: str | None,
    output_dir: str | None,
    ports: str,
    timeout: float,
    skip_whois: bool,
    skip_web: bool,
    install_missing: bool,
    package_manager: str | None,
) -> dict[str, object]:
    target = validate_host(target)
    workspace = lab_init(
        name=name or target,
        client="Authorized Assessment",
        target=target,
        output_dir=output_dir,
    )
    paths = {key: Path(value) for key, value in workspace["paths"].items()}
    selected_ports = parse_ports(ports)

    print_section("Target Brief")
    cyber_line("target", target)
    cyber_line("workspace", str(paths["base"]))

    results: dict[str, object] = {
        "target": target,
        "workspace": str(paths["base"]),
        "url": None,
        "dns": {},
        "whois": None,
        "ports": [],
        "web": None,
    }

    results["dns"] = resolve_dns(target)
    write_json_output(paths["scans"] / "dns.json", results["dns"])

    if skip_whois:
        results["whois"] = {"skipped": True}
    else:
        try:
            results["whois"] = whois_lookup(
                target,
                timeout=max(timeout * 20, 15.0),
                install_missing=install_missing,
                package_manager=package_manager,
            )
        except (ValueError, OSError, ConnectionError, TimeoutError) as error:
            results["whois"] = {"error": str(error)}
            print(f"[i] WHOIS skipped/failed: {error}")
    write_json_output(paths["scans"] / "whois.json", results["whois"])

    port_results = port_scanner(target, selected_ports, timeout=timeout, workers=32, delay=0.0)
    results["ports"] = [asdict(item) for item in port_results]
    write_json_output(paths["scans"] / "ports.json", results["ports"])

    inferred_url = normalize_url(url) if url else infer_web_url(target, port_results)
    results["url"] = inferred_url
    if skip_web:
        results["web"] = {"skipped": True}
    elif inferred_url:
        header_result = header_analyzer(inferred_url, timeout=max(timeout * 8, 5.0))
        path_results = directory_scanner(
            inferred_url,
            paths=DEFAULT_PATHS,
            timeout=max(timeout * 8, 5.0),
            delay=0.1,
            show_all=False,
        )
        results["web"] = {
            "headers": asdict(header_result),
            "paths": [asdict(item) for item in path_results],
        }
    else:
        results["web"] = {"skipped": True, "reason": "No common web port was open and no URL was supplied."}

    write_json_output(paths["scans"] / "web.json", results["web"])
    summary_path = paths["notes"] / "target-brief.md"
    summary_path.write_text(build_target_brief_markdown(results), encoding="utf-8")
    write_json_output(paths["reports"] / "target-brief.json", results)
    print(f"\n[+] Target brief saved to {summary_path}")
    return results


def is_tryhackme_lab_target(target: str) -> bool:
    try:
        address = ipaddress.ip_address(target)
        return address.is_private
    except ValueError:
        lowered = target.lower().strip(".")
        return lowered.endswith(".thm") or lowered.endswith(".local") or lowered in {"localhost"}


def tryhackme_workspace_paths(room: str, workspace: str | None) -> dict[str, Path]:
    slug = slugify_name(room)
    base_dir = Path(workspace or f"engagements/tryhackme-{slug}").expanduser()
    return {
        "base": base_dir,
        "evidence": base_dir / "evidence",
        "findings": base_dir / "findings",
        "reports": base_dir / "reports",
        "scans": base_dir / "scans",
        "notes": base_dir / "notes",
    }


def tryhackme_vpn_check(interface: str | None = None) -> dict[str, object]:
    selected_interface = interface or "tun0"
    print_section("TryHackMe VPN Check")
    cyber_line("interface", selected_interface)

    commands = []
    if find_tool("ip"):
        commands.append(("ip_addr", ["ip", "addr", "show", selected_interface]))
        commands.append(("ip_route", ["ip", "route"]))
    elif find_tool("ifconfig"):
        commands.append(("ifconfig", ["ifconfig", selected_interface]))
        commands.append(("netstat", ["netstat", "-rn"]))
    else:
        print("[i] Neither ip nor ifconfig was found. Install net-tools or iproute2 to inspect VPN state.")

    results: dict[str, object] = {"interface": selected_interface, "checks": {}}
    vpn_seen = False
    for name, command in commands:
        path = find_tool(command[0])
        if not path:
            continue
        actual_command = [path, *command[1:]]
        result = run_external(actual_command, timeout=10)
        output = result.stdout.strip() or result.stderr.strip()
        results["checks"][name] = {
            "command": actual_command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        print(f"\n[{name}]")
        print(output if output else "No output.")
        if name in {"ip_addr", "ifconfig"} and result.returncode == 0 and selected_interface in output:
            vpn_seen = True
        if name in {"ip_route", "netstat"} and re.search(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", output) and selected_interface in output:
            vpn_seen = True

    results["vpn_hint_seen"] = vpn_seen
    if vpn_seen:
        print("[OK] VPN interface/route hints were found.")
    else:
        print("[i] VPN hints were not obvious. Start your TryHackMe OpenVPN/WireGuard connection before scanning room targets.")
    return results


def write_tryhackme_runbook(paths: dict[str, Path], room: str, target: str, web_url: str | None) -> Path:
    runbook = paths["notes"] / "tryhackme-runbook.md"
    web_line = web_url or f"http://{target}"
    lines = [
        f"# TryHackMe Runbook: {room}",
        "",
        f"- Target: {target}",
        f"- Web URL: {web_line}",
        f"- Created UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## First Pass",
        "",
        "```bash",
        f"ktool thm --room {shlex.quote(room)} --target {shlex.quote(target)} --yes-i-am-authorized",
        f"ktool ports {shlex.quote(target)} --ports common --yes-i-am-authorized",
        f"ktool nmap {shlex.quote(target)} --top-ports 1000 --scripts --yes-i-am-authorized",
        f"ktool web {shlex.quote(web_line)} --yes-i-am-authorized",
        f"ktool gobuster {shlex.quote(web_line)} --wordlist-kind directory-small --yes-i-am-authorized",
        "```",
        "",
        "## Notes",
        "",
        "- Keep activity inside the active TryHackMe room scope.",
        "- Save screenshots, command output, and findings under this workspace.",
    ]
    runbook.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return runbook


def tryhackme_tool(
    room: str,
    target: str,
    workspace: str | None,
    interface: str | None,
    ports: str,
    web_url: str | None,
    content_scan: bool,
    content_tool: str,
    dry_run: bool,
    install_missing: bool,
    package_manager: str | None,
    allow_non_lab_target: bool,
) -> dict[str, object]:
    target = validate_host(target)
    if not allow_non_lab_target and not is_tryhackme_lab_target(target):
        raise ValueError("TryHackMe targets should be private lab IPs or .thm names. Use --allow-non-lab-target only for written-scope labs.")

    paths = tryhackme_workspace_paths(room, workspace)
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)

    selected_web_url = normalize_url(web_url) if web_url else f"http://{target}"
    scope = {
        "name": room,
        "client": "TryHackMe",
        "target": target,
        "web_url": selected_web_url,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "authorization": "TryHackMe room/lab target only",
    }
    (paths["base"] / "scope.json").write_text(json.dumps(scope, indent=2) + "\n", encoding="utf-8")
    runbook = write_tryhackme_runbook(paths, room, target, selected_web_url)

    print_section("TryHackMe Room")
    print_key_value_table(
        [
            ("room", room),
            ("target", target),
            ("workspace", str(paths["base"])),
            ("runbook", str(runbook)),
            ("mode", "dry-run" if dry_run else "execute"),
        ]
    )

    results: dict[str, object] = {
        "workspace": str(paths["base"]),
        "scope": scope,
        "runbook": str(runbook),
        "vpn": tryhackme_vpn_check(interface),
        "commands": [],
        "ports": [],
        "web": None,
        "content_discovery": None,
    }

    nmap_output = paths["scans"] / "nmap-initial.txt"
    nmap_args = ["-sV", "-sC", "-T3", "-oN", str(nmap_output), target]
    results["commands"].append({"tool": "nmap", "args": nmap_args})
    print("\n[TryHackMe nmap first pass]")
    nmap_result = run_external_checked(
        "nmap",
        nmap_args,
        timeout=900.0,
        install_missing=install_missing,
        package_manager=package_manager,
        dry_run=dry_run,
    )
    results["nmap"] = nmap_result

    if dry_run:
        print("\n[TryHackMe socket port check]")
        print(f"python TCP check: ports={ports} target={target}")
    else:
        results["ports"] = [
            asdict(item)
            for item in port_scanner(
                target=target,
                ports=parse_ports(ports),
                timeout=0.8,
                workers=64,
                delay=0.0,
            )
        ]

    if dry_run:
        print("\n[TryHackMe web baseline]")
        print(f"ktool web {selected_web_url} --yes-i-am-authorized")
    else:
        try:
            results["web"] = web_baseline(selected_web_url, timeout=5.0, delay=0.1)
        except (ValueError, OSError, ConnectionError, TimeoutError) as error:
            results["web"] = {"error": str(error)}
            print(f"[i] Web baseline skipped/failed: {error}")

    if content_scan:
        content_output = paths["scans"] / "content-discovery.txt"
        try:
            results["content_discovery"] = content_discovery(
                selected_web_url,
                tool=content_tool,
                wordlist=None,
                wordlist_kind="directory-small",
                extensions="txt,php,html",
                status_codes="200,204,301,302,307,401,403",
                threads=20,
                rate=50,
                timeout=180.0,
                output=str(content_output),
                install_missing=install_missing,
                package_manager=package_manager,
                dry_run=dry_run,
            )
        except (ValueError, OSError, ConnectionError, TimeoutError) as error:
            results["content_discovery"] = {"error": str(error)}
            print(f"[i] Content discovery skipped/failed: {error}")

    return results


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
            f"Use {TOOL_COMMAND} sudo-su -- <command args> to relaunch one {TOOL_NAME} command through sudo.",
            f"Use {TOOL_COMMAND} sudo-su with no command args to open the interactive menu as root.",
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
    print(f"[i] {TOOL_NAME} will not bypass operating-system controls. Use approved admin privileges or capabilities.")
    for name, lines in shown.items():
        print(f"\n[{name}]")
        for line in lines:
            print(f"  - {line}")
    return {"tool": selected, "guides": shown}


def permission_error_message(operation: str, error: object | str) -> str:
    return (
        f"{operation} needs approved OS privileges: {error}\n"
        f"{TOOL_NAME} will not bypass permission controls. Run `{TOOL_COMMAND} permission-guide` "
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
    print(f"[i] This uses approved sudo policy. {TOOL_NAME} does not bypass authentication or OS permissions.")

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


def readable_text_sample(data: bytes, limit: int) -> str:
    return data[:limit].decode("utf-8", errors="ignore")


def extract_android_permissions(text: str) -> list[str]:
    matches = set(re.findall(r'android:name=["\']([^"\']+)["\']', text))
    matches.update(re.findall(r"<uses-permission[^>]+name=['\"]([^'\"]+)['\"]", text, re.I))
    matches.update(re.findall(r"\bandroid\.permission\.[A-Z0-9_]+", text))
    return sorted(matches)


def merge_ioc_sets(target: dict[str, set[str]], text: str) -> None:
    extracted = extract_iocs_from_text(text)
    for kind, values in extracted.items():
        cleaned = {
            value
            for value in values
            if not value.lower().startswith("android.permission")
        }
        target.setdefault(kind, set()).update(cleaned)


def scan_mobile_text(
    label: str,
    text: str,
    permissions: set[str],
    iocs: dict[str, set[str]],
    findings: list[dict[str, object]],
) -> None:
    permissions.update(extract_android_permissions(text))
    merge_ioc_sets(iocs, text)
    for severity, kind, pattern in MOBILE_SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            findings.append({"severity": severity, "type": kind, "location": label})


def iter_audit_files(root: Path, max_files: int) -> Iterable[Path]:
    skipped_dirs = {".git", "__pycache__", "node_modules", "build", "dist", ".gradle"}
    count = 0
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [directory for directory in dirs if directory not in skipped_dirs]
        for file_name in files:
            path = Path(current_root) / file_name
            if path.suffix.lower() not in MOBILE_AUDIT_EXTENSIONS and path.name != "AndroidManifest.xml":
                continue
            yield path
            count += 1
            if count >= max_files:
                return


def mobile_artifact_audit(
    path: str,
    max_files: int,
    max_bytes: int,
    include_all_iocs: bool,
) -> dict[str, object]:
    target = Path(path).expanduser()
    if not target.exists():
        raise ValueError(f"Artifact path not found: {target}")
    if max_files < 1 or max_files > 5000:
        raise ValueError("--max-files must be between 1 and 5000.")
    if max_bytes < 1024 or max_bytes > 5_000_000:
        raise ValueError("--max-bytes must be between 1024 and 5000000.")

    print_section("Mobile Artifact Audit")
    cyber_line("path", str(target))
    print("[i] Defensive static triage only. This does not modify apps or generate payloads.")

    permissions: set[str] = set()
    iocs: dict[str, set[str]] = {key: set() for key in IOC_REGEXES}
    findings: list[dict[str, object]] = []
    scanned_files: list[str] = []
    apk_entries: list[str] = []
    errors: list[str] = []

    if target.is_file() and target.suffix.lower() == ".apk":
        try:
            with zipfile.ZipFile(target) as archive:
                apk_entries = archive.namelist()
                for entry in apk_entries[:max_files]:
                    suffix = Path(entry).suffix.lower()
                    if suffix not in MOBILE_AUDIT_EXTENSIONS and Path(entry).name != "AndroidManifest.xml":
                        continue
                    try:
                        data = archive.read(entry)[:max_bytes]
                    except (KeyError, RuntimeError, zipfile.BadZipFile) as error:
                        errors.append(f"{entry}: {error}")
                        continue
                    text = readable_text_sample(data, max_bytes)
                    if not text.strip():
                        continue
                    scanned_files.append(entry)
                    scan_mobile_text(entry, text, permissions, iocs, findings)
        except zipfile.BadZipFile as error:
            raise ValueError(f"APK is not a valid ZIP archive: {error}") from error
    elif target.is_dir():
        for file_path in iter_audit_files(target, max_files=max_files):
            try:
                text = file_path.read_text(encoding="utf-8", errors="ignore")[:max_bytes]
            except OSError as error:
                errors.append(f"{file_path}: {error}")
                continue
            if not text.strip():
                continue
            relative = str(file_path.relative_to(target))
            scanned_files.append(relative)
            scan_mobile_text(relative, text, permissions, iocs, findings)
    else:
        data = target.read_bytes()[:max_bytes]
        text = readable_text_sample(data, max_bytes)
        scanned_files.append(target.name)
        scan_mobile_text(target.name, text, permissions, iocs, findings)

    sensitive_permissions = sorted(permissions & ANDROID_SENSITIVE_PERMISSIONS)
    dangerous_permissions = sorted(permissions & ANDROID_DANGEROUS_PERMISSIONS)
    finding_keys: set[tuple[str, str, str]] = set()
    unique_findings: list[dict[str, object]] = []
    for finding in findings:
        key = (str(finding["severity"]), str(finding["type"]), str(finding["location"]))
        if key in finding_keys:
            continue
        finding_keys.add(key)
        unique_findings.append(finding)

    ioc_limit = 100 if include_all_iocs else 20
    ioc_payload = {
        kind: sorted(values)[:ioc_limit]
        for kind, values in iocs.items()
        if values
    }

    print_key_value_table(
        [
            ("files scanned", str(len(scanned_files))),
            ("apk entries", str(len(apk_entries)) if apk_entries else "n/a"),
            ("permissions", str(len(permissions))),
            ("sensitive permissions", str(len(sensitive_permissions))),
            ("findings", str(len(unique_findings))),
        ]
    )

    if sensitive_permissions:
        print("\n[Sensitive permissions]")
        for permission in sensitive_permissions[:40]:
            print(f"  - {permission}")
        if len(sensitive_permissions) > 40:
            print(f"[i] Showing first 40 sensitive permissions out of {len(sensitive_permissions)}.")

    if unique_findings:
        print("\n[Static indicators]")
        for finding in unique_findings[:50]:
            print(f"  - [{finding['severity'].upper()}] {finding['type']} in {finding['location']}")
        if len(unique_findings) > 50:
            print(f"[i] Showing first 50 findings out of {len(unique_findings)}.")
    else:
        print("[OK] No suspicious static indicators matched the local rules.")

    if ioc_payload:
        print("\n[IOC summary]")
        for kind, values in ioc_payload.items():
            preview = ", ".join(defang_value(value) for value in values[:10])
            print(f"  - {kind}: {preview}")

    return {
        "path": str(target),
        "artifact_type": "apk" if target.is_file() and target.suffix.lower() == ".apk" else "directory" if target.is_dir() else "file",
        "files_scanned": scanned_files,
        "apk_entries_sample": apk_entries[:100],
        "permissions": sorted(permissions),
        "dangerous_permissions": dangerous_permissions,
        "sensitive_permissions": sensitive_permissions,
        "iocs": ioc_payload,
        "findings": unique_findings,
        "errors": errors,
        "notes": [
            "Static triage only; confirm findings with authorized dynamic analysis in a lab.",
            "No backdoors, bypass payloads, exploit code, or persistence code were generated.",
        ],
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


def vps_ssh_base(host: str, port: int, identity: str | None, batch_mode: bool = True) -> list[str]:
    if port < 1 or port > 65535:
        raise ValueError("--ssh-port must be between 1 and 65535.")
    command = ["ssh", "-p", str(port), "-o", "ConnectTimeout=10"]
    command.extend(["-o", "BatchMode=yes" if batch_mode else "BatchMode=no"])
    if identity:
        command.extend(["-i", str(Path(identity).expanduser())])
    command.append(host)
    return command


def parse_vps_ssh_input(value: str) -> tuple[str | None, int | None, str | None]:
    """Accept either root@host or a small ssh command like: ssh -p 2222 -i key root@host."""
    text = value.strip()
    if not text:
        return None, None, None
    parts = shlex.split(text)
    if parts and parts[0] == "ssh":
        parts = parts[1:]

    host: str | None = None
    port: int | None = None
    identity: str | None = None
    index = 0
    while index < len(parts):
        part = parts[index]
        if part == "-p" and index + 1 < len(parts):
            port = int(parts[index + 1])
            index += 2
            continue
        if part.startswith("-p") and len(part) > 2:
            port = int(part[2:])
            index += 1
            continue
        if part == "-i" and index + 1 < len(parts):
            identity = parts[index + 1]
            index += 2
            continue
        if part.startswith("-i") and len(part) > 2:
            identity = part[2:]
            index += 1
            continue
        if part == "-o" and index + 1 < len(parts):
            index += 2
            continue
        if part.startswith("-"):
            index += 1
            continue
        host = part
        index += 1

    return host, port, identity


def prompt_vps_password() -> str | None:
    try:
        password = getpass.getpass("SSH login password [blank = key/agent]: ")
    except (EOFError, KeyboardInterrupt):
        print("\n[i] SSH password prompt skipped; falling back to key/agent auth.")
        return None
    return password or None


def run_interactive_pty(
    command: list[str],
    password: str,
    timeout: float | None = None,
    forward_stdin: bool = True,
    echo_output: bool = True,
) -> tuple[int, str]:
    output_chunks: list[str] = []
    timed_out = False
    deadline = time.monotonic() + timeout if timeout is not None else None

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(command[0], command)

    password_sent = False
    prompt_buffer = ""
    stdin_fd = sys.stdin.fileno() if forward_stdin and sys.stdin.isatty() else None
    try:
        while True:
            select_timeout: float | None = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                select_timeout = remaining

            read_fds = [fd]
            if stdin_fd is not None:
                read_fds.append(stdin_fd)
            ready, _, _ = select.select(read_fds, [], [], select_timeout)
            if not ready and deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                break

            if fd in ready:
                try:
                    data = os.read(fd, 1024)
                except OSError:
                    break
                if not data:
                    break
                decoded = data.decode(errors="replace")
                output_chunks.append(decoded)
                if echo_output:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                prompt_buffer = (prompt_buffer + decoded)[-500:].lower()
                if not password_sent and "password:" in prompt_buffer:
                    os.write(fd, (password + "\n").encode())
                    password_sent = True
                    prompt_buffer = ""

            if stdin_fd is not None and stdin_fd in ready:
                data = os.read(stdin_fd, 1024)
                if not data:
                    break
                os.write(fd, data)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    if timed_out:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    _, status = os.waitpid(pid, 0)
    if timed_out:
        output_chunks.append(f"\n[ERROR] Command timed out after {timeout}s.")
        return 124, "".join(output_chunks)
    return os.waitstatus_to_exitcode(status), "".join(output_chunks)


def run_interactive_ssh(command: list[str], password: str | None = None) -> int:
    if not password:
        return subprocess.run(command, check=False).returncode
    returncode, _ = run_interactive_pty(command, password, timeout=None, forward_stdin=True, echo_output=True)
    return returncode


def run_vps_script(
    label: str,
    script: str,
    host: str | None,
    ssh_port: int,
    identity: str | None,
    ssh_password: str | None,
    timeout: float,
    dry_run: bool,
) -> dict[str, object]:
    if host:
        ssh_path = find_tool("ssh")
        if not ssh_path and not dry_run:
            raise ValueError("ssh is not installed. Install OpenSSH client or run local VPS checks on the server.")
        command = vps_ssh_base(host, ssh_port, identity, batch_mode=ssh_password is None)
        command[0] = ssh_path or "ssh"
        command.append(script)
    else:
        command = ["sh", "-lc", script]

    print(f"\n[{label}]")
    print(color("$ " + " ".join(shlex.quote(part) for part in command), "90"))
    if dry_run:
        return {"label": label, "command": command, "executed": False}

    if host and ssh_password:
        returncode, output = run_interactive_pty(
            command,
            ssh_password,
            timeout=timeout,
            forward_stdin=True,
            echo_output=True,
        )
        if not output.strip():
            print("No output.")
        return {
            "label": label,
            "command": command,
            "executed": True,
            "returncode": returncode,
            "stdout": output,
            "stderr": "",
        }

    result = run_external(command, timeout=timeout)
    output = result.stdout.strip() or result.stderr.strip()
    if output:
        if len(output) > 6000:
            print(output[:6000] + "\n[i] Output truncated in console; full output is available in JSON report.")
        else:
            print(output)
    else:
        print("No output.")
    return {
        "label": label,
        "command": command,
        "executed": True,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def shell_list(values: list[str]) -> str:
    return " ".join(shlex.quote(value) for value in values)


def print_vps_banner() -> None:
    width = 70
    border = "+" + "-" * width + "+"
    print()
    print(color(border, "1;34"))
    print(color("|", "1;34") + color(f" {MYANMAR_FLAG} VPS CONTROL CENTER ".center(width), "1;34") + color("|", "1;34"))
    print(color("|", "1;34") + color(" login | health | storage | usage | pm2 | logs | ls ".center(width), "36") + color("|", "1;34"))
    print(color("|", "1;34") + color(" read-only checks unless you explicitly open ssh login ".center(width), "90") + color("|", "1;34"))
    print(color(border, "1;34"))


def print_vps_menu() -> None:
    items = [
        ("1", "VPS Login (SSH)"),
        ("2", "VPS Full Checker"),
        ("3", "VPS Storage Checker"),
        ("4", "VPS Usage Checker"),
        ("5", "PM2 Checker"),
        ("6", "Directory List / Size"),
        ("7", "Service Checker"),
        ("8", "Log Checker"),
        ("9", "Docker Checker"),
        ("10", "Back"),
    ]
    width = 70
    border = "+" + "-" * width + "+"
    print(color(border, "1;34"))
    for number, label in items:
        print(color("|", "1;34") + f" [{number.rjust(2)}] {label}".ljust(width) + color("|", "1;34"))
    print(color(border, "1;34"))


def prompt_vps_connection(require_host: bool = False) -> tuple[str | None, int, str | None]:
    prompt = "VPS SSH target (example root@150.95.26.242 or ssh root@150.95.26.242)"
    if require_host:
        prompt += ": "
    else:
        prompt += " [blank for local checks]: "
    host, parsed_port, parsed_identity = parse_vps_ssh_input(input(prompt).strip())
    if require_host and not host:
        raise ValueError("VPS login needs an SSH target, for example root@150.95.26.242.")
    if not host:
        return None, 22, None

    default_port = parsed_port or 22
    ssh_port = int(input(f"SSH port [{default_port}]: ").strip() or str(default_port))
    identity_default = parsed_identity or ""
    identity = input(f"SSH identity file [{identity_default or 'optional'}]: ").strip() or identity_default or None
    return host, ssh_port, identity


def vps_login_command(
    host: str,
    ssh_port: int,
    identity: str | None,
    connect: bool = False,
    ask_password: bool = False,
) -> dict[str, object]:
    if not host:
        raise ValueError("VPS login needs --host, for example root@203.0.113.10.")
    ssh_path = find_tool("ssh") or "ssh"
    command = vps_ssh_base(host, ssh_port, identity, batch_mode=False)
    command[0] = ssh_path

    print_vps_banner()
    print_section("VPS Login")
    cyber_line("host", host)
    cyber_line("command", " ".join(shlex.quote(part) for part in command))
    if not connect:
        print("[i] Login command preview only. Add --connect to open an interactive SSH session.")
        return {"host": host, "command": command, "connected": False}

    password = prompt_vps_password() if ask_password else None
    print("[i] Opening interactive SSH session. Exit SSH to return to your shell.")
    returncode = run_interactive_ssh(command, password=password)
    return {"host": host, "command": command, "connected": True, "returncode": returncode}


def vps_check(
    host: str | None,
    ssh_port: int,
    identity: str | None,
    ssh_password: str | None,
    paths: list[str] | None,
    services: list[str] | None,
    include_pm2: bool,
    include_logs: bool,
    include_docker: bool,
    timeout: float,
    dry_run: bool,
    check_types: list[str] | None = None,
) -> dict[str, object]:
    if timeout < 3 or timeout > 600:
        raise ValueError("--timeout must be between 3 and 600 seconds.")
    allowed_checks = {"summary", "storage", "usage", "network", "ls", "services", "pm2", "logs", "docker"}
    default_checks = ["summary", "storage", "usage", "network", "ls", "services"]
    if include_pm2:
        default_checks.append("pm2")
    if include_logs:
        default_checks.append("logs")
    if include_docker:
        default_checks.append("docker")
    selected_checks = check_types or default_checks
    unknown_checks = [item for item in selected_checks if item not in allowed_checks]
    if unknown_checks:
        raise ValueError(f"Unknown VPS check type(s): {', '.join(unknown_checks)}")

    selected_paths = paths or ["/", "/var/www", "/home", "/root", "/etc/nginx/sites-enabled"]
    selected_services = services or ["nginx", "apache2", "pm2", "docker", "postgresql", "mysql", "redis-server"]
    target = host or "local host"

    print_vps_banner()
    print_section("VPS Health Check")
    print_key_value_table(
        [
            ("target", target),
            ("mode", "ssh" if host else "local"),
            ("auth", "password prompt" if host and ssh_password else "key/agent or local"),
            ("checks", ", ".join(selected_checks)),
            ("pm2", "enabled" if include_pm2 else "skipped"),
            ("docker", "enabled" if include_docker else "skipped"),
            ("logs", "enabled" if include_logs else "skipped"),
            ("dry run", str(dry_run)),
        ]
    )
    print("[i] VPS checks are read-only: no restarts, deletes, package changes, or config edits.")

    path_text = shell_list(selected_paths)
    service_text = shell_list(selected_services)
    scripts: list[tuple[str, str, str]] = [
        (
            "summary",
            "system summary",
            "printf 'Host: '; hostname; printf 'User: '; whoami; "
            "printf 'Kernel: '; uname -a; printf 'Uptime: '; uptime; "
            "printf '\\nOS release:\\n'; cat /etc/os-release 2>/dev/null | sed -n '1,8p' || true",
        ),
        (
            "storage",
            "storage and inodes",
            "printf 'Disk usage:\\n'; df -hT 2>/dev/null || df -h; "
            "printf '\\nInodes:\\n'; df -ih 2>/dev/null || true",
        ),
        (
            "usage",
            "memory and cpu",
            "printf 'Memory:\\n'; (free -h 2>/dev/null || vm_stat 2>/dev/null || true); "
            "printf '\\nTop processes by memory:\\n'; ps aux 2>/dev/null | sort -nrk 4 | head -15; "
            "printf '\\nTop processes by cpu:\\n'; ps aux 2>/dev/null | sort -nrk 3 | head -15",
        ),
        (
            "network",
            "network listeners",
            "if command -v ss >/dev/null 2>&1; then ss -tulpn; "
            "elif command -v netstat >/dev/null 2>&1; then netstat -tulpn 2>/dev/null || netstat -an; "
            "else echo 'ss/netstat not found'; fi",
        ),
        (
            "ls",
            "directory inventory",
            f"for p in {path_text}; do printf '\\n## %s\\n' \"$p\"; "
            "ls -lah \"$p\" 2>&1 | sed -n '1,80p'; "
            "printf 'size: '; du -sh \"$p\" 2>/dev/null || true; done",
        ),
        (
            "services",
            "service status",
            f"if command -v systemctl >/dev/null 2>&1; then "
            f"for svc in {service_text}; do printf '\\n## %s\\n' \"$svc\"; "
            "systemctl --no-pager --full status \"$svc\" 2>&1 | sed -n '1,35p'; done; "
            "else echo 'systemctl not found'; fi",
        ),
    ]

    if include_pm2:
        scripts.append(
            (
                "pm2",
                "pm2 processes",
                "if command -v pm2 >/dev/null 2>&1; then pm2 list; "
                "printf '\\nPM2 startup info:\\n'; pm2 startup 2>/dev/null | sed -n '1,20p' || true; "
                "else echo 'pm2 not found'; fi",
            )
        )
    if include_logs:
        scripts.append(
            (
                "logs",
                "recent logs",
                "printf 'System warnings/errors:\\n'; "
                "(journalctl -p warning -n 80 --no-pager 2>/dev/null || tail -n 80 /var/log/syslog 2>/dev/null || true); "
                "printf '\\nAuth log sample:\\n'; "
                "(tail -n 80 /var/log/auth.log 2>/dev/null || tail -n 80 /var/log/secure 2>/dev/null || true); "
                "if command -v pm2 >/dev/null 2>&1; then printf '\\nPM2 logs:\\n'; pm2 logs --lines 60 --nostream 2>&1; fi",
            )
        )
    if include_docker:
        scripts.append(
            (
                "docker",
                "docker status",
                "if command -v docker >/dev/null 2>&1; then docker ps --format 'table {{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}'; "
                "printf '\\nDocker disk usage:\\n'; docker system df 2>&1; "
                "else echo 'docker not found'; fi",
            )
        )

    results = [
        run_vps_script(
            label,
            script,
            host=host,
            ssh_port=ssh_port,
            identity=identity,
            ssh_password=ssh_password,
            timeout=timeout,
            dry_run=dry_run,
        )
        for check_type, label, script in scripts
        if check_type in selected_checks
    ]
    return {
        "target": target,
        "mode": "ssh" if host else "local",
        "auth": "password prompt" if host and ssh_password else "key/agent or local",
        "paths": selected_paths,
        "services": selected_services,
        "include_pm2": include_pm2,
        "include_logs": include_logs,
        "include_docker": include_docker,
        "check_types": selected_checks,
        "dry_run": dry_run,
        "checks": results,
    }


def vps_console() -> None:
    print_vps_banner()
    host, ssh_port, identity = prompt_vps_connection()
    ssh_password = prompt_vps_password() if host else None
    while True:
        print_vps_menu()
        choice = input(color("vps> ", "1;34")).strip()
        try:
            if choice == "1":
                if not host:
                    host, ssh_port, identity = prompt_vps_connection(require_host=True)
                    ssh_password = prompt_vps_password()
                vps_login_command(host, ssh_port, identity, connect=True, ask_password=True)
            elif choice == "2":
                vps_check(host, ssh_port, identity, ssh_password, None, None, True, include_logs=False, include_docker=False, timeout=30.0, dry_run=False)
            elif choice == "3":
                vps_check(host, ssh_port, identity, ssh_password, None, None, False, include_logs=False, include_docker=False, timeout=30.0, dry_run=False, check_types=["storage"])
            elif choice == "4":
                vps_check(host, ssh_port, identity, ssh_password, None, None, False, include_logs=False, include_docker=False, timeout=30.0, dry_run=False, check_types=["summary", "usage", "network"])
            elif choice == "5":
                vps_check(host, ssh_port, identity, ssh_password, None, None, True, include_logs=False, include_docker=False, timeout=30.0, dry_run=False, check_types=["pm2"])
            elif choice == "6":
                path_text = input("Directories [/var/www,/home,/root]: ").strip()
                paths = [item.strip() for item in path_text.split(",") if item.strip()] if path_text else ["/var/www", "/home", "/root"]
                vps_check(host, ssh_port, identity, ssh_password, paths, None, False, include_logs=False, include_docker=False, timeout=30.0, dry_run=False, check_types=["ls"])
            elif choice == "7":
                service_text = input("Services [nginx,pm2,docker]: ").strip()
                services = [item.strip() for item in service_text.split(",") if item.strip()] if service_text else ["nginx", "pm2", "docker"]
                vps_check(host, ssh_port, identity, ssh_password, None, services, False, include_logs=False, include_docker=False, timeout=30.0, dry_run=False, check_types=["services"])
            elif choice == "8":
                vps_check(host, ssh_port, identity, ssh_password, None, None, True, include_logs=True, include_docker=False, timeout=30.0, dry_run=False, check_types=["logs"])
            elif choice == "9":
                vps_check(host, ssh_port, identity, ssh_password, None, None, False, include_logs=False, include_docker=True, timeout=30.0, dry_run=False, check_types=["docker"])
            elif choice == "10":
                return
            else:
                print("Invalid VPS option.")
        except (ValueError, OSError, ConnectionError, TimeoutError) as error:
            print(f"[ERROR] {error}")


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


def doctor(categories: list[str] | None = None) -> dict[str, object]:
    selected_categories = categories or ["recon", "scan", "web", "threat", "tooling"]
    print_section("Operator Readiness")
    print_key_value_table(
        [
            ("version", TOOL_VERSION),
            ("python", sys.version.split()[0]),
            ("executable", sys.executable),
            ("platform", platform.platform()),
            ("cwd", os.getcwd()),
            ("package manager", detect_package_manager() or "not detected"),
        ]
    )

    api_keys = {
        SHODAN_API_KEY_ENV: bool(os.environ.get(SHODAN_API_KEY_ENV)),
        NVD_API_KEY_ENV: bool(os.environ.get(NVD_API_KEY_ENV)),
        VIRUSTOTAL_API_KEY_ENV: bool(os.environ.get(VIRUSTOTAL_API_KEY_ENV)),
    }
    print("\n[API keys]")
    for env_name, present in api_keys.items():
        status = "set" if present else "missing"
        print(f"  [{status}] {env_name}")

    python_packages = {
        module: importlib.util.find_spec(module) is not None
        for module in sorted(PYTHON_PACKAGES)
    }
    if python_packages:
        print("\n[Python packages]")
        for module, present in python_packages.items():
            status = "installed" if present else "missing"
            print(f"  [{status}] {module}")

    seclists = {
        "roots": [str(root) for root in find_seclists_roots()],
        "directory-small": str(find_seclists_wordlist("directory-small") or ""),
        "subdomains": str(find_seclists_wordlist("subdomains") or ""),
    }
    print("\n[SecLists]")
    print(f"  roots: {', '.join(seclists['roots']) if seclists['roots'] else 'not found'}")
    print(f"  directory-small: {seclists['directory-small'] or 'missing'}")
    print(f"  subdomains: {seclists['subdomains'] or 'missing'}")

    tool_report = check_tools(selected_categories)
    missing_tools = sorted(
        item["tool"]
        for items in tool_report.values()
        for item in items
        if not item["installed"]
    )
    findings = []
    if not detect_package_manager():
        findings.append("No supported package manager detected for auto-install workflows.")
    if not seclists["roots"]:
        findings.append("SecLists was not found; content discovery will require a custom --wordlist.")
    if missing_tools:
        findings.append(f"Missing tools detected: {', '.join(missing_tools[:12])}")

    print("\n[Summary]")
    if findings:
        for finding in findings:
            print(f"  - {finding}")
    else:
        print("  - Core operator readiness checks passed.")

    return {
        "version": TOOL_VERSION,
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "cwd": os.getcwd(),
        "package_manager": detect_package_manager(),
        "api_keys": api_keys,
        "python_packages": python_packages,
        "seclists": seclists,
        "tools": tool_report,
        "findings": findings,
    }


def print_roadmap(category: str | None = None) -> dict[str, object]:
    selected_keys = [category] if category else list(TOOL_CATEGORIES)
    unknown = [key for key in selected_keys if key not in TOOL_CATEGORIES]
    if unknown:
        raise ValueError(f"Unknown category: {', '.join(unknown)}")

    print(f"\n=== {TOOL_NAME} Skill Roadmap ===")
    print("Use every active test only on owned systems, written-scope targets, or labs.")
    print(f"{TOOL_NAME} does not automate brute force, phishing, persistence, or exploitation.")

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
    payload_data = json_ready(data)

    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "owner": TOOL_OWNER,
        "tagline": TOOL_TAGLINE,
        "command": command,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": payload_data,
    }
    report_path = Path(path).expanduser()
    report_content = json.dumps(payload, indent=2)
    if command in SENSITIVE_REPORT_COMMANDS:
        saved_path = write_secret_file(str(report_path), report_content + "\n")
        print(f"\n[+] Sensitive report saved with mode 0600 to {saved_path}")
    else:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report_content + "\n", encoding="utf-8")
        print(f"\n[+] Report saved to {report_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME}: {TOOL_TAGLINE}.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_COMMAND} {TOOL_VERSION}",
    )
    parser.add_argument(
        "--yes-i-am-authorized",
        action="store_true",
        help="Confirm this target is in scope for a lab, owned system, or written authorization.",
    )
    parser.add_argument("--report", help="Write JSON report to this path.")

    subparsers = parser.add_subparsers(dest="command")

    roadmap_parser = subparsers.add_parser("roadmap", help="Show the skill roadmap and tool coverage.")
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

    doctor_parser = subparsers.add_parser("doctor", help="Check operator readiness, dependencies, API keys, and wordlists.")
    doctor_parser.add_argument(
        "--category",
        action="append",
        choices=sorted(TOOL_CATEGORIES),
        help="Limit checks to one category. Can be used more than once.",
    )
    doctor_parser.add_argument(
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

    install_many_parser = subparsers.add_parser("install-tools", help="Install package-manager tools for a workflow category.")
    install_many_parser.add_argument("--category", required=True, choices=sorted(TOOL_CATEGORIES), help="Tool category to install.")
    install_many_parser.add_argument("--manager", choices=["apt", "dnf", "pacman", "brew"], help="Package manager to use.")
    install_many_parser.add_argument("--execute", action="store_true", help="Run install commands. Omit for dry-run.")
    install_many_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    sudo_parser = subparsers.add_parser("sudo-su", help=f"Relaunch {TOOL_NAME} through sudo for approved root access.")
    sudo_parser.add_argument("--dry-run", action="store_true", help="Print the sudo command without running it.")
    sudo_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")
    sudo_parser.add_argument(
        "ktool_args",
        nargs=argparse.REMAINDER,
        help=f"{TOOL_COMMAND} command args to run as root. Use -- before the command, or omit for the root menu.",
    )

    hatch_parser = subparsers.add_parser("hatch", help="Run the Hatch Python project/tooling CLI.")
    hatch_parser.add_argument("--install-missing", action="store_true", help="Install Hatch with python -m pip install --user hatch if missing.")
    hatch_parser.add_argument("--timeout", type=float, default=120.0, help="Hatch command timeout in seconds.")
    hatch_parser.add_argument("--dry-run", action="store_true", help="Print the Hatch command without running it.")
    hatch_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")
    hatch_parser.add_argument(
        "hatch_args",
        nargs=argparse.REMAINDER,
        help="Arguments passed to Hatch. Use -- before args that begin with a dash.",
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

    examples_parser = subparsers.add_parser("external-examples", help="Show real-world lab wrapper examples.")
    examples_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    seclists_parser = subparsers.add_parser("seclists-find", help="Find installed SecLists roots and common wordlists.")
    seclists_parser.add_argument("--category", choices=sorted(SECLISTS_WORDLISTS), help="Show one wordlist category.")
    seclists_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    content_parser = subparsers.add_parser(
        "content-discovery",
        aliases=["gobuster", "ffuf", "dirb"],
        help="Run Gobuster, FFUF, or Dirb against an authorized web target.",
    )
    add_common_run_options(content_parser)
    add_install_options(content_parser)
    content_parser.add_argument("url", help="Base URL to enumerate.")
    content_parser.add_argument("--tool", choices=["gobuster", "ffuf", "dirb"], help="External tool to run. Alias commands choose this automatically.")
    content_parser.add_argument("--wordlist", help="Path to a web content wordlist.")
    content_parser.add_argument("--wordlist-kind", choices=sorted(SECLISTS_WORDLISTS), default="directory-small", help="SecLists wordlist kind when --wordlist is omitted.")
    content_parser.add_argument("--extensions", help="Comma-separated extensions, for example php,txt,bak.")
    content_parser.add_argument("--status-codes", default="200,204,301,302,307,401,403", help="Interesting HTTP status codes.")
    content_parser.add_argument("--threads", type=int, default=20, help="Worker threads.")
    content_parser.add_argument("--rate", type=int, default=50, help="FFUF request rate limit.")
    content_parser.add_argument("--timeout", type=float, default=120.0, help="Command timeout in seconds.")
    content_parser.add_argument("--output", help="Optional external-tool output file.")
    content_parser.add_argument("--dry-run", action="store_true", help="Print the command without running it.")

    fingerprint_parser = subparsers.add_parser("fingerprint", help="Run installed web fingerprinting tools.")
    add_common_run_options(fingerprint_parser)
    add_install_options(fingerprint_parser)
    fingerprint_parser.add_argument("target", help="Authorized URL to fingerprint.")
    fingerprint_parser.add_argument("--tools", default="whatweb,wafw00f,httpx", help="Comma-separated tools.")
    fingerprint_parser.add_argument("--timeout", type=float, default=120.0, help="Per-tool timeout in seconds.")
    fingerprint_parser.add_argument("--rate", type=int, default=20, help="Reserved for compatible tools.")
    fingerprint_parser.add_argument("--output", help="Optional output path for tools that support -o.")
    fingerprint_parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")

    tls_audit_parser = subparsers.add_parser("tls-audit", help="Run installed TLS review tools.")
    add_common_run_options(tls_audit_parser)
    add_install_options(tls_audit_parser)
    tls_audit_parser.add_argument("target", help="Authorized HTTPS URL or host.")
    tls_audit_parser.add_argument("--tools", default="testssl.sh,sslscan", help="Comma-separated tools.")
    tls_audit_parser.add_argument("--timeout", type=float, default=300.0, help="Per-tool timeout in seconds.")
    tls_audit_parser.add_argument("--rate", type=int, default=20, help="Reserved for compatible tools.")
    tls_audit_parser.add_argument("--output", help="Optional output path for tools that support -o.")
    tls_audit_parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")

    dns_enum_parser = subparsers.add_parser("dns-enum", help="Run passive/low-noise DNS enumeration tools.")
    add_common_run_options(dns_enum_parser)
    add_install_options(dns_enum_parser)
    dns_enum_parser.add_argument("target", help="Authorized domain.")
    dns_enum_parser.add_argument("--tools", default="dnsrecon,subfinder,amass", help="Comma-separated tools.")
    dns_enum_parser.add_argument("--timeout", type=float, default=300.0, help="Per-tool timeout in seconds.")
    dns_enum_parser.add_argument("--rate", type=int, default=20, help="Reserved for compatible tools.")
    dns_enum_parser.add_argument("--output", help="Optional output path for tools that support -o.")
    dns_enum_parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")

    url_discovery_parser = subparsers.add_parser("url-discovery", help="Run URL discovery/crawling tools.")
    add_common_run_options(url_discovery_parser)
    add_install_options(url_discovery_parser)
    url_discovery_parser.add_argument("target", help="Authorized URL or domain.")
    url_discovery_parser.add_argument("--tools", default="waybackurls,gau,katana", help="Comma-separated tools.")
    url_discovery_parser.add_argument("--timeout", type=float, default=300.0, help="Per-tool timeout in seconds.")
    url_discovery_parser.add_argument("--rate", type=int, default=20, help="Rate limit for compatible tools.")
    url_discovery_parser.add_argument("--output", help="Optional output path for tools that support -o.")
    url_discovery_parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")

    web_scan_parser = subparsers.add_parser("web-scan", help="Run installed safe web scan tools such as nuclei or nikto.")
    add_common_run_options(web_scan_parser)
    add_install_options(web_scan_parser)
    web_scan_parser.add_argument("target", help="Authorized URL.")
    web_scan_parser.add_argument("--tool", choices=EXTERNAL_WRAPPER_TOOLS["web-scan"], default="nuclei", help="Tool to run.")
    web_scan_parser.add_argument("--rate", type=int, default=20, help="Rate limit for compatible tools.")
    web_scan_parser.add_argument("--timeout", type=float, default=300.0, help="Command timeout in seconds.")
    web_scan_parser.add_argument("--output", help="Optional output path for tools that support -o.")
    web_scan_parser.add_argument("--dry-run", action="store_true", help="Print command without running it.")

    js_audit_parser = subparsers.add_parser("js-audit", help="Download page JavaScript and run local audit tools.")
    add_common_run_options(js_audit_parser)
    add_install_options(js_audit_parser)
    js_audit_parser.add_argument("url", help="Authorized URL to inspect.")
    js_audit_parser.add_argument("--tools", default="retire,semgrep,trufflehog", help="Comma-separated local audit tools.")
    js_audit_parser.add_argument("--output", default="js-downloads", help="Directory for downloaded JavaScript files.")
    js_audit_parser.add_argument("--browser", action="store_true", help=f"Accepted for workflow compatibility; {TOOL_NAME} uses static HTML extraction.")
    js_audit_parser.add_argument("--timeout", type=float, default=120.0, help="Network and per-tool timeout in seconds.")
    js_audit_parser.add_argument("--dry-run", action="store_true", help="Print audit commands after downloading scripts.")

    lab_parser = subparsers.add_parser(
        "lab-init",
        aliases=["engagement-init"],
        help="Create a lab/engagement workspace with evidence, scan, finding, and report folders.",
    )
    lab_parser.add_argument("name", help="Lab, room, or engagement name.")
    lab_parser.add_argument("--client", default="lab", help="Client or lab provider name.")
    lab_parser.add_argument("--target", required=True, help="Primary authorized target.")
    lab_parser.add_argument("--output-dir", help="Workspace directory. Defaults to engagements/<name>.")
    lab_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    brief_parser = subparsers.add_parser(
        "target-brief",
        aliases=["brief"],
        help="Create a workspace and run an authorized first-pass target brief.",
    )
    add_common_run_options(brief_parser)
    add_install_options(brief_parser)
    brief_parser.add_argument("target", help="Authorized hostname or IP address.")
    brief_parser.add_argument("--name", help="Engagement name. Defaults to the target value.")
    brief_parser.add_argument("--url", help="Optional URL. If omitted, infer from common open web ports.")
    brief_parser.add_argument("--output-dir", help="Workspace directory. Defaults to engagements/<name>.")
    brief_parser.add_argument("--ports", default="common", help="Port list, range, or 'common'.")
    brief_parser.add_argument("--timeout", type=float, default=0.7, help="Socket timeout in seconds for first-pass checks.")
    brief_parser.add_argument("--skip-whois", action="store_true", help="Skip WHOIS lookup.")
    brief_parser.add_argument("--skip-web", action="store_true", help="Skip web header/path checks.")

    thm_parser = subparsers.add_parser(
        "tryhackme",
        aliases=["thm"],
        help="Create a TryHackMe room workspace and run safe first-pass lab enumeration.",
    )
    add_common_run_options(thm_parser)
    add_install_options(thm_parser)
    thm_parser.add_argument("--room", required=True, help="TryHackMe room name.")
    thm_parser.add_argument("--target", required=True, help="Room target IP or .thm hostname.")
    thm_parser.add_argument("--workspace", help="Workspace directory. Defaults to engagements/tryhackme-<room>.")
    thm_parser.add_argument("--interface", default="tun0", help="VPN interface to inspect.")
    thm_parser.add_argument("--ports", default="common", help="Python TCP port set: common, 22,80,443, or 1-1024.")
    thm_parser.add_argument("--web-url", help="Web URL. Defaults to http://<target>.")
    thm_parser.add_argument("--content-scan", action="store_true", help="Run content discovery using SecLists if available.")
    thm_parser.add_argument("--content-tool", choices=["gobuster", "ffuf", "dirb"], default="gobuster", help="Content discovery tool for --content-scan.")
    thm_parser.add_argument("--dry-run", action="store_true", help="Create workspace and print external commands without active scans.")
    thm_parser.add_argument("--allow-non-lab-target", action="store_true", help="Allow a non-private/non-.thm target when you have written scope.")

    shodan_parser = subparsers.add_parser("shodan", help="Run a passive Shodan host intelligence lookup.")
    add_common_run_options(shodan_parser)
    shodan_parser.add_argument("target", help="Authorized host or IP address to look up.")
    shodan_parser.add_argument("--api-key", help=f"Shodan API key. Defaults to {SHODAN_API_KEY_ENV}.")
    shodan_parser.add_argument("--timeout", type=float, default=10.0, help="API timeout in seconds.")
    shodan_parser.add_argument("--history", action="store_true", help="Ask Shodan for historical banners when available.")
    shodan_parser.add_argument("--minify", action="store_true", help="Return Shodan's compact host response.")

    cve_parser = subparsers.add_parser("cve-lookup", aliases=["cve", "nvd"], help="Search the NVD CVE database.")
    cve_parser.add_argument("query", help="CVE ID or keyword query, for example CVE-2024-3094 or 'nginx 1.18'.")
    cve_parser.add_argument("--api-key", help=f"Optional NVD API key. Defaults to {NVD_API_KEY_ENV}.")
    cve_parser.add_argument("--timeout", type=float, default=20.0, help="API timeout in seconds.")
    cve_parser.add_argument("--limit", type=int, default=10, help="Maximum CVE records to return.")
    cve_parser.add_argument("--exact", action="store_true", help="Use NVD keywordExactMatch for phrase queries.")
    cve_parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Filter by CVSS v3 severity.")
    cve_parser.add_argument("--kev-only", action="store_true", help="Only return CVEs listed in CISA KEV.")
    cve_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    vt_parser = subparsers.add_parser("virustotal", aliases=["vt"], help="Look up an IOC in VirusTotal.")
    vt_parser.add_argument("indicator", help="Hash, URL, domain, or IP address.")
    vt_parser.add_argument("--api-key", help=f"VirusTotal API key. Defaults to {VIRUSTOTAL_API_KEY_ENV}.")
    vt_parser.add_argument("--timeout", type=float, default=15.0, help="API timeout in seconds.")
    vt_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    threat_parser = subparsers.add_parser("threat-site-triage", help="Safely collect evidence from a suspected malicious website.")
    add_common_run_options(threat_parser)
    threat_parser.add_argument("url", help="Suspicious URL to triage. Defanged URLs are accepted.")
    threat_parser.add_argument("--timeout", type=float, default=5.0, help="Network timeout in seconds.")
    threat_parser.add_argument("--fetch-body", action="store_true", help="Fetch a small body sample for IOC and phishing checks.")
    threat_parser.add_argument("--output-markdown", help="Write a takedown evidence report to this path.")

    defang_parser = subparsers.add_parser("defang", help="Defang or refang URLs, domains, emails, and IOC values.")
    defang_parser.add_argument("values", nargs="+", help="Values to defang/refang.")
    defang_parser.add_argument("--refang", action="store_true", help="Convert defanged values back to normal form.")
    defang_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

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

    mobile_parser = subparsers.add_parser("mobile-artifact-audit", aliases=["apk-audit"], help="Defensively audit an APK, decompiled APK folder, or mobile repo.")
    mobile_parser.add_argument("path", help="Path to an APK, decompiled APK directory, or source/repo directory.")
    mobile_parser.add_argument("--max-files", type=int, default=800, help="Maximum text-like files or APK entries to scan.")
    mobile_parser.add_argument("--max-bytes", type=int, default=250000, help="Maximum bytes sampled per file.")
    mobile_parser.add_argument("--all-iocs", action="store_true", help="Include up to 100 IOCs per type instead of 20.")
    mobile_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

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

    vps_parser = subparsers.add_parser(
        "vps-check",
        aliases=["vps", "vps-health"],
        help="Run read-only VPS health checks locally or over SSH.",
    )
    vps_parser.add_argument("--host", help="SSH target such as root@203.0.113.10. Omit to check the local host.")
    vps_parser.add_argument("--ssh-port", type=int, default=22, help="SSH port for --host.")
    vps_parser.add_argument("--identity", help="SSH private key path for --host.")
    vps_parser.add_argument("--path", action="append", help="Directory to list and size-check. Can be used more than once.")
    vps_parser.add_argument("--service", action="append", help="systemd service to inspect. Can be used more than once.")
    vps_parser.add_argument("--no-pm2", action="store_false", dest="include_pm2", help="Skip PM2 process checks.")
    vps_parser.add_argument("--logs", action="store_true", help="Include recent system/auth/PM2 logs.")
    vps_parser.add_argument("--docker", action="store_true", help="Include Docker container and disk checks.")
    vps_parser.add_argument(
        "--only",
        action="append",
        choices=["summary", "storage", "usage", "network", "ls", "services", "pm2", "logs", "docker"],
        help="Run only this VPS check type. Can be used more than once.",
    )
    vps_parser.add_argument("--timeout", type=float, default=30.0, help="Timeout per check in seconds.")
    vps_parser.add_argument("--ask-password", action="store_true", help="Prompt for an SSH password for remote checks.")
    vps_parser.add_argument("--dry-run", action="store_true", help="Print the local/SSH commands without running checks.")
    vps_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    vps_ui_parser = subparsers.add_parser("vps-ui", aliases=["vps-menu"], help="Open the blue VPS control center.")
    vps_ui_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    vps_login_parser = subparsers.add_parser("vps-login", help="Show or open an SSH login command for a VPS.")
    vps_login_parser.add_argument("--host", required=True, help="SSH target such as root@203.0.113.10.")
    vps_login_parser.add_argument("--ssh-port", type=int, default=22, help="SSH port.")
    vps_login_parser.add_argument("--identity", help="SSH private key path.")
    vps_login_parser.add_argument("--connect", action="store_true", help="Open the SSH session instead of previewing the command.")
    vps_login_parser.add_argument("--ask-password", action="store_true", help="Prompt for the SSH login password before connecting.")
    vps_login_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    for command_name, help_text in {
        "vps-storage": "Run VPS storage and inode checks.",
        "vps-usage": "Run VPS CPU, memory, uptime, and listener checks.",
        "vps-pm2": "Run VPS PM2 process checks.",
        "vps-ls": "List and size-check VPS directories.",
        "vps-services": "Inspect VPS systemd services.",
        "vps-logs": "Show recent VPS system/auth/PM2 logs.",
        "vps-docker": "Show Docker containers and Docker disk usage.",
    }.items():
        subparser = subparsers.add_parser(command_name, help=help_text)
        subparser.add_argument("--host", help="SSH target such as root@203.0.113.10. Omit to check the local host.")
        subparser.add_argument("--ssh-port", type=int, default=22, help="SSH port for --host.")
        subparser.add_argument("--identity", help="SSH private key path for --host.")
        subparser.add_argument("--path", action="append", help="Directory to list and size-check. Can be used more than once.")
        subparser.add_argument("--service", action="append", help="systemd service to inspect. Can be used more than once.")
        subparser.add_argument("--timeout", type=float, default=30.0, help="Timeout per check in seconds.")
        subparser.add_argument("--ask-password", action="store_true", help="Prompt for an SSH password for remote checks.")
        subparser.add_argument("--dry-run", action="store_true", help="Print the local/SSH commands without running checks.")
        subparser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

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
        help="Confirm this target is in scope for a lab, owned system, or written authorization.",
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

        choice = input(color("ktool> ", "1;32")).strip().lower()

        try:
            if choice in {"?", "h", "help"}:
                print("\n[i] Enter a menu number, or use q to exit the console.")
            elif choice in {"q", "quit", "exit", "45"}:
                print_exit_screen("Session closed from the interactive menu.", 0)
                break
            elif choice == "1":
                print_roadmap()
            elif choice == "2":
                check_tools()
            elif choice == "46":
                doctor()
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
                command_text = input(f"{TOOL_COMMAND} args to run as root [blank for root menu]: ").strip()
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
            elif choice == "47":
                target = input("Authorized host/IP: ").strip()
                name = input("Engagement name [target]: ").strip() or None
                url = input("Optional URL [auto infer]: ").strip() or None
                output_dir = input("Workspace directory [engagements/<name>]: ").strip() or None
                ports = input("Ports [common]: ").strip() or "common"
                skip_whois = input("Skip WHOIS? [y/N]: ").strip().lower() in {"y", "yes"}
                skip_web = input("Skip web checks? [y/N]: ").strip().lower() in {"y", "yes"}
                target_brief(
                    target=target,
                    name=name,
                    url=url,
                    output_dir=output_dir,
                    ports=ports,
                    timeout=0.7,
                    skip_whois=skip_whois,
                    skip_web=skip_web,
                    install_missing=False,
                    package_manager=None,
                )
            elif choice == "32":
                args = shlex.split(input("Hatch args [--version]: ").strip() or "--version")
                install_missing = input("Install Hatch if missing? [y/N]: ").strip().lower() in {"y", "yes"}
                hatch_tool(args, install_missing=install_missing, timeout=120.0, dry_run=False)
            elif choice == "33":
                url = input("Suspicious URL: ").strip()
                fetch_body = input("Fetch body sample? [y/N]: ").strip().lower() in {"y", "yes"}
                output = input("Markdown report path [optional]: ").strip() or None
                threat_site_triage(url, timeout=5.0, fetch_body=fetch_body, output_markdown=output)
            elif choice == "34":
                mode = input("Mode (defang/refang) [defang]: ").strip().lower() or "defang"
                values = shlex.split(input("Values: ").strip())
                defang_iocs(values, refang=mode == "refang")
            elif choice == "35":
                target = input("Authorized host/IP: ").strip()
                api_key = input(f"Shodan API key [{SHODAN_API_KEY_ENV} env]: ").strip() or None
                shodan_lookup(target, api_key=api_key, timeout=10.0, history=False, minify=False)
            elif choice == "36":
                query = input("CVE ID or keyword query: ").strip()
                severity = input("Severity filter (LOW/MEDIUM/HIGH/CRITICAL) [none]: ").strip().upper() or None
                kev_only = input("CISA KEV only? [y/N]: ").strip().lower() in {"y", "yes"}
                cve_database_lookup(
                    query,
                    api_key=None,
                    timeout=20.0,
                    limit=10,
                    exact=False,
                    severity=severity,
                    kev_only=kev_only,
                )
            elif choice == "37":
                indicator = input("Hash, URL, domain, or IP: ").strip()
                api_key = input(f"VirusTotal API key [{VIRUSTOTAL_API_KEY_ENV} env]: ").strip() or None
                virustotal_lookup(indicator, api_key=api_key, timeout=15.0)
            elif choice == "38":
                path = input("APK, decompiled APK folder, or repo path: ").strip()
                mobile_artifact_audit(path, max_files=800, max_bytes=250000, include_all_iocs=False)
            elif choice == "39":
                print_external_examples()
            elif choice == "40":
                category = input(f"SecLists category ({', '.join(sorted(SECLISTS_WORDLISTS))}) [all]: ").strip() or None
                seclists_find(category)
            elif choice == "41":
                url = input("Base URL (https://example.com): ").strip()
                tool = input("Tool (gobuster/ffuf/dirb) [gobuster]: ").strip() or "gobuster"
                wordlist = input("Wordlist path [auto SecLists directory-small]: ").strip() or None
                dry_run = input("Dry run only? [y/N]: ").strip().lower() in {"y", "yes"}
                content_discovery(
                    url,
                    tool=tool,
                    wordlist=wordlist,
                    wordlist_kind="directory-small",
                    extensions=None,
                    status_codes="200,204,301,302,307,401,403",
                    threads=20,
                    rate=50,
                    timeout=120.0,
                    output=None,
                    install_missing=False,
                    package_manager=None,
                    dry_run=dry_run,
                )
            elif choice == "42":
                name = input("Lab/engagement name: ").strip()
                client = input("Client/lab provider [lab]: ").strip() or "lab"
                target = input("Primary target: ").strip()
                output_dir = input("Output directory [engagements/<name>]: ").strip() or None
                lab_init(name=name, client=client, target=target, output_dir=output_dir)
            elif choice == "43":
                room = input("TryHackMe room name: ").strip()
                target = input("Room target IP/host: ").strip()
                web_url = input(f"Web URL [http://{target}]: ").strip() or None
                content_scan = input("Run content discovery too? [y/N]: ").strip().lower() in {"y", "yes"}
                content_tool = input("Content tool (gobuster/ffuf/dirb) [gobuster]: ").strip() or "gobuster"
                dry_run = input("Dry run only? [y/N]: ").strip().lower() in {"y", "yes"}
                tryhackme_tool(
                    room=room,
                    target=target,
                    workspace=None,
                    interface=None,
                    ports="common",
                    web_url=web_url,
                    content_scan=content_scan,
                    content_tool=content_tool,
                    dry_run=dry_run,
                    install_missing=False,
                    package_manager=None,
                    allow_non_lab_target=False,
                )
            elif choice == "44":
                vps_console()
            else:
                print("Invalid choice. Use ? for help or q to exit.")
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
        elif args.command == "doctor":
            results = doctor(args.category)
        elif args.command == "install-hints":
            results = print_install_hints(args.tool)
        elif args.command == "install-tool":
            results = install_system_tool(args.tool, manager=args.manager, execute=args.execute)
        elif args.command == "install-tools":
            results = install_tools_for_category(args.category, manager=args.manager, execute=args.execute)
        elif args.command == "sudo-su":
            results = sudo_su(args.ktool_args, dry_run=args.dry_run)
        elif args.command == "hatch":
            results = hatch_tool(
                args.hatch_args,
                install_missing=args.install_missing,
                timeout=args.timeout,
                dry_run=args.dry_run,
            )
        elif args.command == "external-examples":
            results = print_external_examples()
        elif args.command == "seclists-find":
            results = seclists_find(args.category)
        elif args.command in {"lab-init", "engagement-init"}:
            results = lab_init(
                name=args.name,
                client=args.client,
                target=args.target,
                output_dir=args.output_dir,
            )
        elif args.command in {"tryhackme", "thm"}:
            require_authorization(args.yes_i_am_authorized)
            results = tryhackme_tool(
                room=args.room,
                target=args.target,
                workspace=args.workspace,
                interface=args.interface,
                ports=args.ports,
                web_url=args.web_url,
                content_scan=args.content_scan,
                content_tool=args.content_tool,
                dry_run=args.dry_run,
                install_missing=args.install_missing,
                package_manager=args.package_manager,
                allow_non_lab_target=args.allow_non_lab_target,
            )
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
        elif args.command in {"vps-check", "vps", "vps-health"}:
            ssh_password = prompt_vps_password() if args.host and args.ask_password else None
            results = vps_check(
                host=args.host,
                ssh_port=args.ssh_port,
                identity=args.identity,
                ssh_password=ssh_password,
                paths=args.path,
                services=args.service,
                include_pm2=args.include_pm2,
                include_logs=args.logs,
                include_docker=args.docker,
                timeout=args.timeout,
                dry_run=args.dry_run,
                check_types=args.only,
            )
        elif args.command in {"vps-ui", "vps-menu"}:
            vps_console()
            results = {"opened": "vps-ui"}
        elif args.command == "vps-login":
            results = vps_login_command(
                host=args.host,
                ssh_port=args.ssh_port,
                identity=args.identity,
                connect=args.connect,
                ask_password=args.ask_password,
            )
        elif args.command in {"vps-storage", "vps-usage", "vps-pm2", "vps-ls", "vps-services", "vps-logs", "vps-docker"}:
            check_map = {
                "vps-storage": ["storage"],
                "vps-usage": ["summary", "usage", "network"],
                "vps-pm2": ["pm2"],
                "vps-ls": ["ls"],
                "vps-services": ["services"],
                "vps-logs": ["logs"],
                "vps-docker": ["docker"],
            }
            ssh_password = prompt_vps_password() if args.host and args.ask_password else None
            results = vps_check(
                host=args.host,
                ssh_port=args.ssh_port,
                identity=args.identity,
                ssh_password=ssh_password,
                paths=args.path,
                services=args.service,
                include_pm2=args.command in {"vps-pm2", "vps-logs"},
                include_logs=args.command == "vps-logs",
                include_docker=args.command == "vps-docker",
                timeout=args.timeout,
                dry_run=args.dry_run,
                check_types=check_map[args.command],
            )
        elif args.command == "permission-guide":
            results = permission_guide(args.tool)
        elif args.command == "conn-watch":
            results = connection_watch(args.iterations, interval=args.interval, show_all=args.show_all)
        elif args.command == "log-watch":
            results = log_watch(args.file, lines=args.lines, follow=args.follow, duration=args.duration, alerts_only=args.alerts_only)
        elif args.command == "ioc-triage":
            results = ioc_triage(args.values)
        elif args.command in {"mobile-artifact-audit", "apk-audit"}:
            results = mobile_artifact_audit(
                args.path,
                max_files=args.max_files,
                max_bytes=args.max_bytes,
                include_all_iocs=args.all_iocs,
            )
        elif args.command == "defang":
            results = defang_iocs(args.values, refang=args.refang)
        elif args.command in {"cve-lookup", "cve", "nvd"}:
            results = cve_database_lookup(
                args.query,
                api_key=args.api_key,
                timeout=args.timeout,
                limit=args.limit,
                exact=args.exact,
                severity=args.severity,
                kev_only=args.kev_only,
            )
        elif args.command in {"virustotal", "vt"}:
            results = virustotal_lookup(
                args.indicator,
                api_key=args.api_key,
                timeout=args.timeout,
            )
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
        elif args.command in {"content-discovery", "gobuster", "ffuf", "dirb"}:
            selected_tool = args.tool or (args.command if args.command in {"gobuster", "ffuf", "dirb"} else "gobuster")
            results = content_discovery(
                args.url,
                tool=selected_tool,
                wordlist=args.wordlist,
                wordlist_kind=args.wordlist_kind,
                extensions=args.extensions,
                status_codes=args.status_codes,
                threads=args.threads,
                rate=args.rate,
                timeout=args.timeout,
                output=args.output,
                install_missing=args.install_missing,
                package_manager=args.package_manager,
                dry_run=args.dry_run,
            )
        elif args.command in {"fingerprint", "tls-audit", "dns-enum", "url-discovery"}:
            results = external_web_wrapper(
                args.command,
                target=args.target,
                tools_value=args.tools,
                timeout=args.timeout,
                rate=args.rate,
                output=args.output,
                install_missing=args.install_missing,
                package_manager=args.package_manager,
                dry_run=args.dry_run,
            )
        elif args.command == "web-scan":
            results = external_web_wrapper(
                "web-scan",
                target=args.target,
                tools_value=args.tool,
                timeout=args.timeout,
                rate=args.rate,
                output=args.output,
                install_missing=args.install_missing,
                package_manager=args.package_manager,
                dry_run=args.dry_run,
            )
        elif args.command == "js-audit":
            results = js_audit(
                args.url,
                tools_value=args.tools,
                output=args.output,
                timeout=args.timeout,
                install_missing=args.install_missing,
                package_manager=args.package_manager,
                dry_run=args.dry_run,
            )
        elif args.command in {"target-brief", "brief"}:
            results = target_brief(
                target=args.target,
                name=args.name,
                url=args.url,
                output_dir=args.output_dir,
                ports=args.ports,
                timeout=args.timeout,
                skip_whois=args.skip_whois,
                skip_web=args.skip_web,
                install_missing=args.install_missing,
                package_manager=args.package_manager,
            )
        elif args.command == "shodan":
            results = shodan_lookup(
                args.target,
                api_key=args.api_key,
                timeout=args.timeout,
                history=args.history,
                minify=args.minify,
            )
        elif args.command == "threat-site-triage":
            results = threat_site_triage(
                args.url,
                timeout=args.timeout,
                fetch_body=args.fetch_body,
                output_markdown=args.output_markdown,
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
            "doctor",
            "install-hints",
            "install-tool",
            "install-tools",
            "sudo-su",
            "hatch",
            "external-examples",
            "seclists-find",
            "lab-init",
            "engagement-init",
            "target-brief",
            "brief",
            "tryhackme",
            "thm",
            "password-audit",
            "password-check",
            "password-generate",
            "admin-password",
            "awareness-plan",
            "local-posture",
            "vps-check",
            "vps",
            "vps-health",
            "vps-ui",
            "vps-menu",
            "vps-login",
            "vps-storage",
            "vps-usage",
            "vps-pm2",
            "vps-ls",
            "vps-services",
            "vps-logs",
            "vps-docker",
            "permission-guide",
            "conn-watch",
            "log-watch",
            "ioc-triage",
            "mobile-artifact-audit",
            "apk-audit",
            "defang",
            "cve-lookup",
            "cve",
            "nvd",
            "virustotal",
            "vt",
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
