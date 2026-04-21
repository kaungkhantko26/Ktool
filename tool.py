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
import email.utils
import fnmatch
import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


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

BACKUP_CHECK_PATHS = [
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "db.sql",
    "database.sql",
    "site.zip",
    "www.zip",
    "public_html.zip",
    "config.php.bak",
    "settings.py.bak",
    ".env.bak",
    "admin.bak",
    "index.php~",
    "wp-config.php.bak",
]

ROUTER_CHECKLIST = [
    "Change the default admin password and use a unique long passphrase.",
    "Use WPA2-AES or WPA3 for WiFi; avoid WEP, WPA, and WPS.",
    "Disable WPS, UPnP, and remote administration unless explicitly needed.",
    "Update router firmware from the vendor's official source.",
    "Use a separate guest network for visitors and IoT devices.",
    "Review connected devices and remove unknown clients.",
    "Back up the router configuration after hardening it.",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS for future visits.",
    "Content-Security-Policy": "Helps reduce cross-site scripting impact.",
    "X-Frame-Options": "Helps prevent clickjacking in older browsers.",
    "X-Content-Type-Options": "Helps prevent MIME-sniffing issues.",
    "Referrer-Policy": "Limits sensitive URL data in referrers.",
    "Permissions-Policy": "Restricts powerful browser features.",
}

CHECKLISTS = {
    "web": [
        "Confirm written authorization and exact in-scope URLs.",
        "Capture screenshots and timestamps for each finding.",
        "Review security headers and cookie flags.",
        "Check common exposed paths and backup/config files.",
        "Fingerprint frameworks and server technologies.",
        "Review public JavaScript files and source maps.",
        "Run TLS checks and note weak protocol/cipher issues.",
        "Validate findings manually before reporting.",
    ],
    "network": [
        "Confirm in-scope IP ranges and maintenance windows.",
        "Run conservative port and service discovery.",
        "Record service versions and exposed management ports.",
        "Check SMB/SNMP only when explicitly in scope.",
        "Collect packet captures only on owned/administered networks.",
        "Document firewall/VPN observations and access assumptions.",
    ],
    "email": [
        "Check MX, SPF, DMARC, and DKIM selector records.",
        "Review SMTP STARTTLS support and public banner exposure.",
        "Do not verify mailbox existence or send unsolicited messages.",
        "Document spoofing risk based on DNS controls.",
    ],
    "vehicle": [
        "Treat Ktool plate results as format guidance only, not an ownership lookup.",
        "Compare the plate against the registration book/card and tax records.",
        "Verify chassis/VIN and engine numbers physically match the documents.",
        "Confirm seller identity and sale documents through legal channels.",
        "Use RTAD or another official channel for owner or registration verification.",
        "Walk away if plate, chassis, engine, or document details do not match.",
    ],
    "report": [
        "Each finding has title, severity, affected asset, evidence, impact, remediation, and references.",
        "Evidence is reproducible and sanitized.",
        "Risk ratings are consistent across findings.",
        "Recommendations are practical and specific.",
        "Scope, limitations, timeline, and authorization notes are included.",
    ],
}

TOOL_NAME = "Ktool"
TOOL_OWNER = "Ktool owner"
USER_AGENT = "Ktool/2.0 (+authorized-security-testing)"

MYANMAR_REGION_CODES = {
    "YGN": "Yangon Region",
    "MDY": "Mandalay Region",
    "NPT": "Naypyidaw Union Territory",
    "NPW": "Naypyidaw Union Territory",
    "SGG": "Sagaing Region",
    "MGW": "Magway Region",
    "BGO": "Bago Region",
    "AYY": "Ayeyarwady Region",
    "TNI": "Tanintharyi Region",
    "MON": "Mon State",
    "KYN": "Kayin State",
    "KYH": "Kayah State",
    "KCN": "Kachin State",
    "KCH": "Kachin State",
    "SHN": "Shan State",
    "CHN": "Chin State",
    "RKE": "Rakhine State",
    "RKH": "Rakhine State",
}


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
        ("13", "WiFi Security Check"),
        ("14", "Vulnerability Lookup"),
        ("15", "Awareness Plan"),
        ("16", "Local Posture Review"),
        ("17", "Install Hints"),
        ("18", "Web Vulnerability Search"),
        ("19", "Email Security Check"),
        ("20", "SEToolkit Info"),
        ("21", "Clear Screen"),
        ("22", "Restart Console"),
        ("23", "External Tool Runner"),
        ("24", "IP Privacy Check"),
        ("25", "Myanmar Plate Check"),
        ("26", "More Safety Checks"),
        ("27", "Exit"),
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
        "skills": ["Security headers", "Common path discovery", "JavaScript exposure review", "Proxy-based manual testing"],
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
            "retire",
            "trufflehog",
            "semgrep",
            "linkfinder",
            "secretfinder",
            "sourcemapper",
            "playwright",
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
            "js-audit",
            "ssl-cert-check",
            "http-methods",
            "robots-check",
            "backup-file-check",
            "redirect-check",
            "cookie-audit",
        ],
    },
    "email": {
        "title": "Email Security Testing",
        "skills": ["Email format review", "MX/SPF/DMARC/DKIM checks", "SMTP banner and TLS capability review"],
        "tools": ["dig", "host", "nslookup", "swaks", "checkdmarc"],
        "implemented": ["email-check", "email-domain", "smtp-check"],
    },
    "pentest": {
        "title": "Pentest Workflow",
        "skills": ["Scope control", "Evidence management", "Finding documentation", "Report preparation"],
        "tools": ["Ktool"],
        "implemented": [
            "scope",
            "evidence-init",
            "engagement-init",
            "evidence-snapshot",
            "finding-new",
            "report-init",
            "report-export",
            "export-html-report",
            "checklist",
            "recon-workflow",
            "web-workflow",
        ],
    },
    "privacy": {
        "title": "Network Privacy and Egress Review",
        "skills": ["Public egress IP review", "VPN/proxy indicator checks", "DNS leak awareness"],
        "tools": ["ip", "curl", "wg", "openvpn", "tor", "nmcli"],
        "implemented": ["privacy-methods", "ip-privacy-check"],
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
        "tools": ["wireshark", "tcpdump", "ettercap", "traceroute", "mtr", "arp-scan", "ss"],
        "implemented": ["capture", "network-diagnostics", "local-network-discovery", "lan-device-list", "tools"],
    },
    "wireless": {
        "title": "Wireless Security",
        "skills": ["WiFi audit on owned networks only", "Interface inventory", "Encryption posture review", "Capture analysis"],
        "tools": ["aircrack-ng", "airodump-ng", "kismet", "iw", "nmcli", "ip"],
        "implemented": [
            "wireless-info",
            "wifi-check",
            "wifi-scan",
            "wifi-device-users",
            "router-checklist",
            "dns-leak-check",
            "tools",
        ],
    },
    "mobile": {
        "title": "Mobile and iPhone Checks",
        "skills": ["iPhone WiFi reachability", "Bonjour/mDNS discovery", "Trusted USB device health inventory"],
        "tools": ["ping", "ip", "avahi-browse", "ideviceinfo", "idevice_id", "idevicepair", "usbmuxd"],
        "implemented": ["iphone-check", "iphone-usb-info", "iphone-health-guide"],
    },
    "vehicle": {
        "title": "Vehicle Verification Support",
        "skills": ["Plate format review", "Region code hints", "Legal document verification checklist"],
        "tools": ["ktool"],
        "implemented": ["myanmar-plate-check", "myanmar-vehicle-checklist", "checklist vehicle"],
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
        "tools": ["linpeas", "winpeas", "lynis", "chkrootkit", "rkhunter", "ufw", "nft", "iptables", "ss"],
        "implemented": ["local-posture", "linux-audit", "firewall-check", "service-audit", "update-check", "ssh-audit-local"],
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
    "dig": ["dig"],
    "host": ["host"],
    "swaks": ["swaks"],
    "checkdmarc": ["checkdmarc"],
    "ip": ["ip"],
    "curl": ["curl"],
    "wg": ["wg"],
    "openvpn": ["openvpn"],
    "tor": ["tor"],
    "ping": ["ping"],
    "avahi-browse": ["avahi-browse"],
    "ideviceinfo": ["ideviceinfo"],
    "idevice_id": ["idevice_id"],
    "idevicepair": ["idevicepair"],
    "usbmuxd": ["usbmuxd"],
    "retire": ["retire"],
    "trufflehog": ["trufflehog"],
    "semgrep": ["semgrep"],
    "linkfinder": ["linkfinder", "LinkFinder"],
    "secretfinder": ["secretfinder", "SecretFinder"],
    "sourcemapper": ["sourcemapper"],
    "ss": ["ss"],
    "ufw": ["ufw"],
    "nft": ["nft"],
    "iptables": ["iptables"],
    "apt": ["apt"],
    "dnf": ["dnf"],
    "pacman": ["pacman"],
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
    "nslookup": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install dnsutils",
        "Arch": "sudo pacman -S bind",
        "Fedora": "sudo dnf install bind-utils",
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
    "ip": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install iproute2",
        "Arch": "sudo pacman -S iproute2",
        "Fedora": "sudo dnf install iproute",
    },
    "curl": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install curl",
        "Arch": "sudo pacman -S curl",
        "Fedora": "sudo dnf install curl",
    },
    "wg": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install wireguard-tools",
        "Arch": "sudo pacman -S wireguard-tools",
        "Fedora": "sudo dnf install wireguard-tools",
        "Safety": "Use only for lawful privacy or authorized corporate/lab networks.",
    },
    "openvpn": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install openvpn",
        "Arch": "sudo pacman -S openvpn",
        "Fedora": "sudo dnf install openvpn",
        "Safety": "Use only for lawful privacy or authorized corporate/lab networks.",
    },
    "tor": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install tor",
        "Arch": "sudo pacman -S tor",
        "Fedora": "sudo dnf install tor",
        "Safety": "Use Tor for lawful privacy. Ktool does not route scans or attacks through Tor.",
    },
    "ping": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install iputils-ping",
        "Arch": "sudo pacman -S iputils",
        "Fedora": "sudo dnf install iputils",
    },
    "avahi-browse": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install avahi-utils",
        "Arch": "sudo pacman -S avahi",
        "Fedora": "sudo dnf install avahi-tools",
    },
    "ideviceinfo": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install libimobiledevice-utils usbmuxd",
        "Arch": "sudo pacman -S libimobiledevice usbmuxd",
        "Fedora": "sudo dnf install libimobiledevice-utils usbmuxd",
        "Safety": "Requires a trusted/unlocked iPhone pairing. Ktool does not bypass device locks or pairing.",
    },
    "idevice_id": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install libimobiledevice-utils usbmuxd",
        "Arch": "sudo pacman -S libimobiledevice usbmuxd",
        "Fedora": "sudo dnf install libimobiledevice-utils usbmuxd",
    },
    "idevicepair": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install libimobiledevice-utils usbmuxd",
        "Arch": "sudo pacman -S libimobiledevice usbmuxd",
        "Fedora": "sudo dnf install libimobiledevice-utils usbmuxd",
    },
    "usbmuxd": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install usbmuxd",
        "Arch": "sudo pacman -S usbmuxd",
        "Fedora": "sudo dnf install usbmuxd",
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
    "retire": {
        "npm": "npm install -g retire",
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install npm && sudo npm install -g retire",
    },
    "trufflehog": {
        "GitHub releases": "Download from https://github.com/trufflesecurity/trufflehog/releases",
        "Docker": "docker run --rm -v \"$PWD:/work\" trufflesecurity/trufflehog:latest filesystem /work",
    },
    "semgrep": {
        "Python": "python3 -m pip install semgrep",
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install pipx && pipx install semgrep",
    },
    "linkfinder": {
        "Python": "python3 -m pip install jsbeautifier requests",
        "GitHub": "git clone https://github.com/GerbenJavado/LinkFinder && cd LinkFinder && python3 setup.py install",
    },
    "secretfinder": {
        "Python": "python3 -m pip install jsbeautifier requests",
        "GitHub": "git clone https://github.com/m4ll0k/SecretFinder && cd SecretFinder && python3 -m pip install -r requirements.txt",
    },
    "sourcemapper": {
        "npm": "npm install -g sourcemapper",
    },
    "playwright": {
        "Python": "python3 -m pip install playwright",
        "Browser install": "python3 -m playwright install chromium",
    },
    "dig": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install dnsutils",
        "Arch": "sudo pacman -S bind",
        "Fedora": "sudo dnf install bind-utils",
    },
    "host": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install bind9-host",
        "Arch": "sudo pacman -S bind",
        "Fedora": "sudo dnf install bind-utils",
    },
    "swaks": {
        "Debian/Ubuntu/Kali": "sudo apt update && sudo apt install swaks",
        "Arch": "sudo pacman -S swaks",
        "Fedora": "sudo dnf install swaks",
        "Safety": "Use only for controlled SMTP diagnostics. Ktool does not send test emails.",
    },
    "checkdmarc": {
        "Python": "python3 -m pip install checkdmarc",
        "pipx": "pipx install checkdmarc",
    },
}

INSTALL_PACKAGES = {
    "apt": {
        "nmap": "nmap",
        "whois": "whois",
        "tcpdump": "tcpdump",
        "nikto": "nikto",
        "iw": "iw",
        "nmcli": "network-manager",
        "ip": "iproute2",
        "curl": "curl",
        "wg": "wireguard-tools",
        "openvpn": "openvpn",
        "tor": "tor",
        "ping": "iputils-ping",
        "avahi-browse": "avahi-utils",
        "ideviceinfo": "libimobiledevice-utils",
        "idevice_id": "libimobiledevice-utils",
        "idevicepair": "libimobiledevice-utils",
        "usbmuxd": "usbmuxd",
        "searchsploit": "exploitdb",
        "masscan": "masscan",
        "nc": "netcat-openbsd",
        "theHarvester": "theharvester",
        "sublist3r": "sublist3r",
        "burpsuite": "burpsuite",
        "zaproxy": "zaproxy",
        "sqlmap": "sqlmap",
        "hydra": "hydra",
        "john": "john",
        "hashcat": "hashcat",
        "wireshark": "wireshark",
        "ettercap": "ettercap-graphical",
        "aircrack-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "kismet": "kismet",
        "setoolkit": "set",
        "whatweb": "whatweb",
        "wapiti": "wapiti",
        "testssl.sh": "testssl.sh",
        "sslscan": "sslscan",
        "gobuster": "gobuster",
        "ffuf": "ffuf",
        "feroxbuster": "feroxbuster",
        "dnsrecon": "dnsrecon",
        "dnsenum": "dnsenum",
        "amass": "amass",
        "smbclient": "smbclient",
        "snmpwalk": "snmp",
        "traceroute": "traceroute",
        "mtr": "mtr",
        "arp-scan": "arp-scan",
        "lynis": "lynis",
        "chkrootkit": "chkrootkit",
        "rkhunter": "rkhunter",
        "wafw00f": "wafw00f",
        "semgrep": "semgrep",
        "dig": "dnsutils",
        "host": "bind9-host",
        "nslookup": "dnsutils",
        "swaks": "swaks",
    },
    "pacman": {
        "nmap": "nmap",
        "whois": "whois",
        "tcpdump": "tcpdump",
        "iw": "iw",
        "nmcli": "networkmanager",
        "ip": "iproute2",
        "curl": "curl",
        "wg": "wireguard-tools",
        "openvpn": "openvpn",
        "tor": "tor",
        "ping": "iputils",
        "avahi-browse": "avahi",
        "ideviceinfo": "libimobiledevice",
        "idevice_id": "libimobiledevice",
        "idevicepair": "libimobiledevice",
        "usbmuxd": "usbmuxd",
        "masscan": "masscan",
        "nc": "openbsd-netcat",
        "hydra": "hydra",
        "john": "john",
        "hashcat": "hashcat",
        "wireshark": "wireshark-qt",
        "ettercap": "ettercap",
        "aircrack-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "kismet": "kismet",
        "whatweb": "whatweb",
        "sslscan": "sslscan",
        "gobuster": "gobuster",
        "snmpwalk": "net-snmp",
        "traceroute": "traceroute",
        "mtr": "mtr",
        "arp-scan": "arp-scan",
        "lynis": "lynis",
        "chkrootkit": "chkrootkit",
        "rkhunter": "rkhunter",
        "dig": "bind",
        "host": "bind",
        "nslookup": "bind",
        "swaks": "swaks",
    },
    "dnf": {
        "nmap": "nmap",
        "whois": "whois",
        "tcpdump": "tcpdump",
        "iw": "iw",
        "nmcli": "NetworkManager",
        "ip": "iproute",
        "curl": "curl",
        "wg": "wireguard-tools",
        "openvpn": "openvpn",
        "tor": "tor",
        "ping": "iputils",
        "avahi-browse": "avahi-tools",
        "ideviceinfo": "libimobiledevice-utils",
        "idevice_id": "libimobiledevice-utils",
        "idevicepair": "libimobiledevice-utils",
        "usbmuxd": "usbmuxd",
        "masscan": "masscan",
        "nc": "nmap-ncat",
        "hashcat": "hashcat",
        "sslscan": "sslscan",
        "smbclient": "samba-client",
        "snmpwalk": "net-snmp-utils",
        "traceroute": "traceroute",
        "mtr": "mtr",
        "arp-scan": "arp-scan",
        "lynis": "lynis",
        "rkhunter": "rkhunter",
        "wafw00f": "wafw00f",
        "dig": "bind-utils",
        "host": "bind-utils",
        "nslookup": "bind-utils",
        "swaks": "swaks",
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


def parse_email_address(address: str) -> tuple[str, str]:
    parsed_name, parsed_address = email.utils.parseaddr(address.strip())
    _ = parsed_name
    if not parsed_address or parsed_address != address.strip():
        raise ValueError(f"Invalid email address: {address}")
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", parsed_address):
        raise ValueError(f"Invalid email address: {address}")
    local_part, domain = parsed_address.rsplit("@", 1)
    if len(local_part) > 64 or len(parsed_address) > 254:
        raise ValueError("Email address is longer than common SMTP limits.")
    return local_part, domain.lower().strip(".")


def clean_dns_line(line: str) -> str:
    line = line.strip()
    if not line:
        return line
    if line.startswith('"') and line.endswith('"'):
        return line[1:-1]
    return line.replace('" "', "").strip('"')


def dns_query(name: str, record_type: str, timeout: float) -> dict[str, object]:
    name = name.strip().strip(".")
    record_type = record_type.upper()
    commands: list[tuple[str, list[str]]] = [
        ("dig", ["+short", record_type, name]),
        ("host", ["-t", record_type, name]),
        ("nslookup", ["-type=" + record_type, name]),
    ]

    for tool, args in commands:
        tool_path = find_tool(tool)
        if not tool_path:
            continue
        command = [tool_path, *args]
        result = run_external(command, timeout=timeout)
        raw_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        records = [clean_dns_line(line) for line in raw_lines]
        return {
            "tool": tool,
            "command": command,
            "returncode": result.returncode,
            "records": records,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    print("[missing] dig/host/nslookup")
    print(install_hint_text("dig"))
    return {"tool": None, "records": [], "error": "No DNS query tool installed."}


def mx_hosts(mx_records: list[str]) -> list[str]:
    hosts: list[str] = []
    for record in mx_records:
        if " mail exchanger =" in record:
            host = record.rsplit("=", 1)[-1].strip()
        else:
            parts = record.split()
            host = parts[-1] if parts else ""
        host = host.rstrip(".")
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def email_domain_audit(domain: str, dkim_selector: str | None, timeout: float, use_checkdmarc: bool) -> dict[str, object]:
    domain = validate_host(domain).lower().strip(".")
    print(f"\n[+] Email domain security check for {domain}")
    print("[i] This checks public DNS mail controls only; it does not send email.")

    mx = dns_query(domain, "MX", timeout)
    txt = dns_query(domain, "TXT", timeout)
    dmarc = dns_query(f"_dmarc.{domain}", "TXT", timeout)
    dkim = dns_query(f"{dkim_selector}._domainkey.{domain}", "TXT", timeout) if dkim_selector else None

    spf_records = [record for record in txt.get("records", []) if "v=spf1" in record.lower()]
    dmarc_records = [record for record in dmarc.get("records", []) if "v=dmarc1" in record.lower()]
    dkim_records = [
        record
        for record in (dkim or {}).get("records", [])
        if "v=dkim1" in record.lower() or "p=" in record.lower()
    ]

    findings: list[dict[str, object]] = []
    if not mx.get("records"):
        findings.append({"severity": "high", "type": "missing_mx", "detail": "No MX records found."})
    if not spf_records:
        findings.append({"severity": "medium", "type": "missing_spf", "detail": "No SPF TXT record found."})
    elif len(spf_records) > 1:
        findings.append({"severity": "medium", "type": "multiple_spf", "detail": "Multiple SPF records can break SPF validation."})
    if not dmarc_records:
        findings.append({"severity": "medium", "type": "missing_dmarc", "detail": "No DMARC record found at _dmarc."})
    else:
        joined_dmarc = " ".join(dmarc_records).lower()
        if "p=none" in joined_dmarc:
            findings.append({"severity": "low", "type": "dmarc_monitor_only", "detail": "DMARC policy is p=none."})
    if dkim_selector and not dkim_records:
        findings.append({"severity": "medium", "type": "missing_dkim_selector", "detail": f"No DKIM record found for selector {dkim_selector}."})

    print("\n[MX]")
    for record in mx.get("records", []) or ["No MX records found."]:
        print(f"  {record}")
    print("\n[SPF]")
    for record in spf_records or ["No SPF record found."]:
        print(f"  {record}")
    print("\n[DMARC]")
    for record in dmarc_records or ["No DMARC record found."]:
        print(f"  {record}")
    if dkim_selector:
        print(f"\n[DKIM:{dkim_selector}]")
        for record in dkim_records or ["No DKIM record found for selector."]:
            print(f"  {record}")

    if findings:
        print("\n[Potential email issues]")
        for finding in findings:
            print(f"[{finding['severity'].upper()}] {finding['type']}: {finding['detail']}")
    else:
        print("\n[OK] No obvious email DNS posture issues found.")

    checkdmarc_result = None
    if use_checkdmarc:
        checkdmarc_result = run_tool_command("checkdmarc", [domain, "--format", "json"], timeout)

    return {
        "domain": domain,
        "mx": mx,
        "spf": spf_records,
        "dmarc": dmarc_records,
        "dkim_selector": dkim_selector,
        "dkim": dkim_records,
        "findings": findings,
        "checkdmarc": checkdmarc_result,
    }


def email_address_check(address: str, dkim_selector: str | None, timeout: float, use_checkdmarc: bool) -> dict[str, object]:
    local_part, domain = parse_email_address(address)
    print(f"\n[+] Email address check for {address}")
    print("[i] Ktool validates format and domain posture only; it does not verify mailbox existence.")

    disposable_domains = {
        "10minutemail.com",
        "guerrillamail.com",
        "mailinator.com",
        "tempmail.com",
        "yopmail.com",
    }
    warnings: list[str] = []
    if domain in disposable_domains:
        warnings.append("Domain appears in a small built-in disposable email list.")
    if local_part.lower() in {"admin", "administrator", "root", "support", "info", "sales"}:
        warnings.append("Local part is a common role account.")

    for warning in warnings:
        print(f"[WARN] {warning}")

    domain_result = email_domain_audit(domain, dkim_selector=dkim_selector, timeout=timeout, use_checkdmarc=use_checkdmarc)
    return {
        "address": address,
        "local_part": local_part,
        "domain": domain,
        "warnings": warnings,
        "domain_audit": domain_result,
    }


def smtp_read(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        lines = text.splitlines()
        if lines and re.match(r"^\d{3} ", lines[-1]):
            break
        if len(b"".join(chunks)) > 16384:
            break
    return b"".join(chunks).decode("utf-8", errors="replace")


def smtp_check(target: str, port: int, timeout: float, starttls: bool) -> dict[str, object]:
    target = validate_host(target)
    if port not in {25, 465, 587}:
        raise ValueError("--port must be one of 25, 465, or 587.")

    print(f"\n[+] SMTP banner/TLS check for {target}:{port}")
    print("[i] This reads SMTP capabilities only; it does not send mail, verify users, or attempt login.")

    context = ssl.create_default_context()
    with socket.create_connection((target, port), timeout=timeout) as raw_sock:
        if port == 465:
            sock: socket.socket = context.wrap_socket(raw_sock, server_hostname=target)
            tls_active = True
        else:
            sock = raw_sock
            tls_active = False

        with sock:
            banner = smtp_read(sock, timeout)
            sock.sendall(b"EHLO ktool.local\r\n")
            ehlo = smtp_read(sock, timeout)
            starttls_available = "STARTTLS" in ehlo.upper()
            tls_ehlo = ""

            if starttls and starttls_available and not tls_active:
                sock.sendall(b"STARTTLS\r\n")
                starttls_response = smtp_read(sock, timeout)
                if starttls_response.startswith("220"):
                    tls_sock = context.wrap_socket(sock, server_hostname=target)
                    tls_active = True
                    tls_sock.sendall(b"EHLO ktool.local\r\n")
                    tls_ehlo = smtp_read(tls_sock, timeout)
                    try:
                        tls_sock.sendall(b"QUIT\r\n")
                    except OSError:
                        pass
                else:
                    tls_ehlo = starttls_response
            else:
                try:
                    sock.sendall(b"QUIT\r\n")
                except OSError:
                    pass

    print("\n[BANNER]")
    print(banner.strip() or "No banner received.")
    print("\n[EHLO]")
    print(ehlo.strip() or "No EHLO response received.")
    print(f"\n[STARTTLS] {'available' if starttls_available else 'not advertised'}")
    print(f"[TLS ACTIVE] {'yes' if tls_active else 'no'}")
    if tls_ehlo:
        print("\n[TLS EHLO]")
        print(tls_ehlo.strip())

    return {
        "target": target,
        "port": port,
        "banner": banner,
        "ehlo": ehlo,
        "starttls_available": starttls_available,
        "tls_active": tls_active,
        "tls_ehlo": tls_ehlo,
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


def ssl_cert_check(target: str, port: int, timeout: float) -> dict[str, object]:
    normalized = normalize_url(target) if "://" in target else f"https://{target}"
    parsed = urlparse(normalized)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Invalid HTTPS target: {target}")
    check_port = port or parsed.port or 443

    print(f"\n[+] TLS certificate check for {host}:{check_port}")
    context = ssl.create_default_context()
    with socket.create_connection((host, check_port), timeout=timeout) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            cipher = tls_sock.cipher()
            tls_version = tls_sock.version()

    not_after = cert.get("notAfter", "")
    expires_at = None
    days_left = None
    if not_after:
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires_at - datetime.now(timezone.utc)).days

    subject_alt_names = [
        value
        for name_type, value in cert.get("subjectAltName", [])
        if name_type.lower() == "dns"
    ]
    issuer = " / ".join("=".join(item) for part in cert.get("issuer", []) for item in part)
    subject = " / ".join("=".join(item) for part in cert.get("subject", []) for item in part)

    findings: list[str] = []
    if days_left is not None and days_left < 0:
        findings.append("Certificate is expired.")
    elif days_left is not None and days_left <= 14:
        findings.append("Certificate expires within 14 days.")
    if subject_alt_names and host not in subject_alt_names and not any(
        san.startswith("*.") and host.endswith(san[1:]) for san in subject_alt_names
    ):
        findings.append("Hostname was not an exact/wildcard match in DNS subjectAltName list.")

    print(f"Subject: {subject or 'N/A'}")
    print(f"Issuer: {issuer or 'N/A'}")
    print(f"TLS version: {tls_version or 'N/A'}")
    print(f"Cipher: {cipher[0] if cipher else 'N/A'}")
    print(f"Expires: {expires_at.isoformat() if expires_at else 'N/A'}")
    print(f"Days left: {days_left if days_left is not None else 'N/A'}")
    if subject_alt_names:
        print("SANs:")
        for san in subject_alt_names[:25]:
            print(f"  - {san}")
        if len(subject_alt_names) > 25:
            print(f"  ... {len(subject_alt_names) - 25} more")
    for finding in findings:
        print(f"[WARN] {finding}")

    return {
        "target": normalized,
        "host": host,
        "port": check_port,
        "subject": subject,
        "issuer": issuer,
        "tls_version": tls_version,
        "cipher": cipher,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": days_left,
        "subject_alt_names": subject_alt_names,
        "findings": findings,
    }


def http_methods_check(url: str, timeout: float) -> dict[str, object]:
    normalized = normalize_url(url)
    print(f"\n[+] HTTP methods check for {normalized}")
    result = check_http_methods(normalized, timeout)
    print(f"OPTIONS status: {result.get('status') or 'N/A'}")
    allowed = result.get("allow") or []
    risky = result.get("risky") or []
    print(f"Allow: {', '.join(allowed) if allowed else 'No Allow header returned.'}")
    if risky:
        print(f"[WARN] Risky methods advertised: {', '.join(risky)}")
    if result.get("error"):
        print(f"[ERROR] {result['error']}")
    return {"url": normalized, **result}


def robots_check(url: str, timeout: float) -> dict[str, object]:
    base_url = normalize_url(url)
    print(f"\n[+] robots.txt and security.txt check for {base_url}")
    paths = ["robots.txt", ".well-known/security.txt", "security.txt"]
    results: list[dict[str, object]] = []
    for path in paths:
        full_url = f"{base_url}/{path}"
        try:
            status, headers, body = http_request(full_url, method="GET", timeout=timeout)
            text = body.decode("utf-8", errors="replace")
            preview = "\n".join(text.splitlines()[:20])
            print(f"\n[{status}] {full_url}")
            print(preview if preview else "No response body sampled.")
            results.append({"url": full_url, "status": status, "headers": headers, "preview": preview})
        except ConnectionError as error:
            print(f"\n[ERROR] {full_url} -> {error}")
            results.append({"url": full_url, "status": None, "error": str(error)})
    return {"base_url": base_url, "results": results}


def backup_file_check(url: str, timeout: float, delay: float, show_all: bool) -> dict[str, object]:
    base_url = normalize_url(url)
    print(f"\n[+] Backup/exposed file check for {base_url}")
    print("[i] Safe HEAD/GET checks for common accidental exposure paths only.")
    results = directory_scanner(base_url, BACKUP_CHECK_PATHS, timeout=timeout, delay=delay, show_all=show_all)
    interesting = [
        asdict(item)
        for item in results
        if item.status is not None and item.status < 400
    ]
    if interesting:
        print("\n[WARN] Accessible backup-like paths need manual validation.")
    return {"base_url": base_url, "results": [asdict(item) for item in results], "interesting": interesting}


class TrackingRedirectHandler(HTTPRedirectHandler):
    def __init__(self) -> None:
        self.chain: list[dict[str, object]] = []
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self.chain.append({"from": req.full_url, "to": newurl, "status": code})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def redirect_check(url: str, timeout: float) -> dict[str, object]:
    normalized = normalize_url(url)
    print(f"\n[+] Redirect chain check for {normalized}")
    handler = TrackingRedirectHandler()
    opener = build_opener(handler)
    request = Request(normalized, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
            status = response.status
    except HTTPError as error:
        final_url = error.geturl()
        status = error.code
    except URLError as error:
        reason = getattr(error, "reason", error)
        raise ConnectionError(str(reason)) from error

    for hop in handler.chain:
        print(f"[{hop['status']}] {hop['from']} -> {hop['to']}")
    print(f"Final: HTTP {status} {final_url}")
    findings: list[str] = []
    if normalized.startswith("http://") and final_url.startswith("http://"):
        findings.append("No HTTPS redirect observed.")
    if len(handler.chain) > 5:
        findings.append("Redirect chain is long.")
    for finding in findings:
        print(f"[WARN] {finding}")
    return {"url": normalized, "final_url": final_url, "status": status, "chain": handler.chain, "findings": findings}


def cookie_audit(url: str, timeout: float) -> dict[str, object]:
    normalized = normalize_url(url)
    print(f"\n[+] Cookie flag audit for {normalized}")
    status, headers, _ = http_request(normalized, method="GET", timeout=timeout)
    parsed = urlparse(normalized)
    issues = analyze_cookie_flags(headers, parsed.scheme)
    cookie_headers = [value for key, value in headers.items() if key.lower() == "set-cookie"]
    print(f"Status: HTTP {status}")
    if not cookie_headers:
        print("No Set-Cookie header observed.")
    for cookie_header in cookie_headers:
        print(f"Set-Cookie: {cookie_header}")
    if issues:
        print("\n[Cookie flag issues]")
        for issue in issues:
            print(f"[WARN] {issue['cookie']} missing {', '.join(issue['missing_flags'])}")
    else:
        print("[OK] No missing cookie flags observed in sampled response.")
    return {"url": normalized, "status": status, "cookies": cookie_headers, "issues": issues}


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
        "js-audit": "ktool js-audit https://example.com --browser --tools retire,semgrep,trufflehog --yes-i-am-authorized",
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


def tools_from_category(category: str | None) -> list[str]:
    if not category:
        tools: list[str] = []
        for details in TOOL_CATEGORIES.values():
            tools.extend(details["tools"])
        return sorted(set(tools))
    if category not in TOOL_CATEGORIES:
        raise ValueError(f"Unknown category: {category}")
    return sorted(set(TOOL_CATEGORIES[category]["tools"]))


def install_tools(
    manager: str,
    tools: list[str],
    execute: bool,
    timeout: float,
) -> dict[str, object]:
    package_map = INSTALL_PACKAGES.get(manager)
    if not package_map:
        raise ValueError(f"Unsupported package manager: {manager}")

    packages = sorted({package_map[tool] for tool in tools if tool in package_map})
    manual = sorted({tool for tool in tools if tool not in package_map})

    if manager == "apt":
        command = ["sudo", "apt", "update", "&&", "sudo", "apt", "install", "-y", *packages]
        executable_command = ["sudo", "apt", "install", "-y", *packages]
        update_command = ["sudo", "apt", "update"]
    elif manager == "pacman":
        command = ["sudo", "pacman", "-S", "--needed", *packages]
        executable_command = command
        update_command = None
    else:
        command = ["sudo", "dnf", "install", "-y", *packages]
        executable_command = command
        update_command = None

    print("\n[+] Ktool package install plan")
    if packages:
        print(f"[manager] {manager}")
        print("[packages] " + " ".join(packages))
        if manager == "apt":
            print("[command] sudo apt update && sudo apt install -y " + " ".join(packages))
        else:
            print("[command] " + " ".join(command))
    else:
        print("[i] No package-manager installable tools selected.")

    if manual:
        print("\n[manual install required]")
        for tool in manual:
            print(f"\n{install_hint_text(tool)}")

    result: dict[str, object] = {
        "manager": manager,
        "packages": packages,
        "manual": manual,
        "executed": False,
    }
    if execute and packages:
        print("\n[+] Executing install command. Sudo may ask for your password.")
        if update_command:
            update_result = run_external(update_command, timeout=timeout)
            result["update"] = {
                "command": update_command,
                "returncode": update_result.returncode,
                "stdout": update_result.stdout,
                "stderr": update_result.stderr,
            }
            if update_result.stdout.strip():
                print(update_result.stdout.strip())
            if update_result.stderr.strip():
                print(update_result.stderr.strip(), file=sys.stderr)

        install_result = run_external(executable_command, timeout=timeout)
        result["executed"] = True
        result["install"] = {
            "command": executable_command,
            "returncode": install_result.returncode,
            "stdout": install_result.stdout,
            "stderr": install_result.stderr,
        }
        if install_result.stdout.strip():
            print(install_result.stdout.strip())
        if install_result.stderr.strip():
            print(install_result.stderr.strip(), file=sys.stderr)
    elif execute:
        print("[i] Nothing installable through this package manager.")
    else:
        print("\n[i] Dry run only. Add --execute to install packages.")

    return result


def interactive_external_runner() -> dict[str, object] | None:
    print("\n[+] External Tool Runner")
    print("1. Web fingerprint")
    print("2. TLS audit")
    print("3. Content discovery")
    print("4. DNS enum")
    print("5. URL discovery")
    print("6. Web scanner")
    print("7. Fast scan")
    print("8. SMB enum")
    print("9. SNMP enum")
    print("10. Network diagnostics")
    print("11. Local network discovery")
    print("12. Linux audit")
    print("13. Screenshot audit")
    print("14. JavaScript audit")
    print("15. Show examples")

    choice = input("Select external runner: ").strip()
    if choice == "1":
        url = input("URL: ").strip()
        tools = split_tool_list(input("Tools [whatweb,wafw00f,httpx]: ").strip(), ["whatweb", "wafw00f", "httpx"])
        return run_fingerprint(url, tools, timeout=60.0)
    if choice == "2":
        target = input("HTTPS URL or host: ").strip()
        tools = split_tool_list(input("Tools [testssl.sh,sslscan]: ").strip(), ["testssl.sh", "sslscan"])
        return run_tls_audit(target, tools, timeout=300.0)
    if choice == "3":
        url = input("Base URL: ").strip()
        tool = input("Tool [ffuf/gobuster/feroxbuster] [ffuf]: ").strip() or "ffuf"
        wordlist = input("Wordlist path: ").strip()
        extensions = input("Extensions [optional]: ").strip() or None
        return run_content_discovery(url, tool, wordlist, timeout=300.0, rate=50, extensions=extensions)
    if choice == "4":
        domain = input("Domain: ").strip()
        tools = split_tool_list(input("Tools [dnsrecon,subfinder,assetfinder,amass]: ").strip(), ["dnsrecon", "subfinder", "assetfinder", "amass"])
        return run_dns_enum(domain, tools, timeout=300.0)
    if choice == "5":
        url = input("Base URL/domain: ").strip()
        tools = split_tool_list(input("Tools [waybackurls,gau,katana,hakrawler]: ").strip(), ["waybackurls", "gau", "katana", "hakrawler"])
        return run_url_discovery(url, tools, timeout=240.0)
    if choice == "6":
        url = input("Target URL: ").strip()
        tool = input("Tool [nuclei/wapiti/nikto/dalfox/xsstrike] [nuclei]: ").strip() or "nuclei"
        return run_web_scan(url, tool=tool, timeout=900.0, rate=20)
    if choice == "7":
        target = input("Target host/IP: ").strip()
        tool = input("Tool [rustscan/masscan] [rustscan]: ").strip() or "rustscan"
        ports = input("Ports [1-1000]: ").strip() or "1-1000"
        return run_fast_scan(target, tool=tool, ports=ports, timeout=240.0)
    if choice == "8":
        target = input("Target host/IP: ").strip()
        tool = input("Tool [enum4linux-ng/smbclient] [enum4linux-ng]: ").strip() or "enum4linux-ng"
        return run_smb_enum(target, tool=tool, timeout=180.0)
    if choice == "9":
        target = input("Target host/IP: ").strip()
        community = input("Community [public]: ").strip() or "public"
        return run_snmp_enum(target, community=community, timeout=120.0)
    if choice == "10":
        target = input("Target host/IP: ").strip()
        tools = split_tool_list(input("Tools [traceroute,mtr]: ").strip(), ["traceroute", "mtr"])
        return run_network_diagnostics(target, tools, timeout=120.0)
    if choice == "11":
        interface = input("Interface [optional]: ").strip() or None
        return run_local_network_discovery(interface, timeout=120.0)
    if choice == "12":
        tools = split_tool_list(input("Tools [lynis,chkrootkit,rkhunter]: ").strip(), ["lynis", "chkrootkit", "rkhunter"])
        return run_linux_audit(tools, timeout=600.0)
    if choice == "13":
        url = input("Target URL: ").strip()
        tool = input("Tool [gowitness/aquatone] [gowitness]: ").strip() or "gowitness"
        output = input("Output dir [screenshots]: ").strip() or "screenshots"
        return run_screenshot_audit(url, tool=tool, timeout=240.0, output=output)
    if choice == "14":
        url = input("Target URL: ").strip()
        tools = split_tool_list(input("External tools [optional: retire,semgrep,trufflehog]: ").strip(), [])
        use_browser = input("Run browser console check with Playwright? [y/N]: ").strip().lower() in {"y", "yes"}
        output = input("Download JS output dir [optional]: ").strip() or None
        return run_javascript_audit(url, tools=tools, timeout=120.0, browser=use_browser, output=output)
    if choice == "15":
        return print_external_tool_examples()

    print("Invalid external runner choice.")
    return None


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


def extract_script_urls(html: str, base_url: str) -> list[str]:
    urls: set[str] = set()
    for match in re.finditer(r"<script\b[^>]*\bsrc=[\"']([^\"']+)[\"']", html, re.IGNORECASE):
        src = match.group(1).strip()
        if src and not src.lower().startswith(("data:", "javascript:")):
            urls.add(urljoin(base_url + "/", src))
    return sorted(urls)


def source_map_url(js_url: str, js_text: str) -> str | None:
    match = re.search(r"sourceMappingURL=([^\s*]+)", js_text)
    if match:
        return urljoin(js_url, match.group(1).strip())
    if js_url.endswith(".js"):
        return f"{js_url}.map"
    return None


def scan_javascript_text(js_url: str, js_text: str, timeout: float) -> dict[str, object]:
    patterns = {
        "possible_api_key": re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']"),
        "firebase_config": re.compile(r"firebaseapp\.com|AIza[0-9A-Za-z_-]{20,}"),
        "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
        "debugger_statement": re.compile(r"\bdebugger\s*;"),
        "console_error_logging": re.compile(r"\bconsole\.(error|warn)\s*\("),
        "local_storage_token": re.compile(r"(?i)localStorage\.(setItem|getItem)\s*\(\s*[\"'][^\"']*(token|secret|auth|jwt)[^\"']*[\"']"),
    }
    findings: list[dict[str, object]] = []
    lines = js_text.splitlines()
    for index, line in enumerate(lines, start=1):
        for name, pattern in patterns.items():
            if pattern.search(line):
                findings.append({"type": name, "line": index})

    map_url = source_map_url(js_url, js_text)
    map_result: dict[str, object] | None = None
    if map_url:
        try:
            status, headers, body = http_request(map_url, method="GET", timeout=timeout)
            content_type = headers.get("Content-Type", "")
            accessible = status < 400 and (b"sources" in body[:4096] or "json" in content_type.lower())
            map_result = {
                "url": map_url,
                "status": status,
                "accessible": accessible,
                "content_type": content_type,
            }
        except ConnectionError as error:
            map_result = {"url": map_url, "status": None, "accessible": False, "error": str(error)}

    return {
        "url": js_url,
        "bytes_sampled": len(js_text.encode("utf-8", errors="ignore")),
        "findings": findings,
        "source_map": map_result,
    }


def run_browser_console_audit(url: str, timeout: float) -> dict[str, object]:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[missing] playwright")
        print(install_hint_text("playwright"))
        return {"tool": "playwright", "installed": False}

    normalized = normalize_url(url)
    console_entries: list[dict[str, object]] = []
    page_errors: list[str] = []
    request_failures: list[dict[str, str]] = []

    print(f"\n[+] Running browser console audit for {normalized}")
    print("[i] Headless Chromium records JavaScript console errors, page errors, and failed requests.")

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.on(
                "console",
                lambda message: console_entries.append(
                    {
                        "type": message.type,
                        "text": message.text,
                        "location": message.location,
                    }
                ),
            )
            page.on("pageerror", lambda error: page_errors.append(str(error)))
            page.on(
                "requestfailed",
                lambda request: request_failures.append(
                    {
                        "url": request.url,
                        "failure": request.failure or "",
                    }
                ),
            )
            page.goto(normalized, wait_until="load", timeout=int(timeout * 1000))
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightTimeoutError:
                pass
            browser.close()
    except Exception as error:
        print(f"[ERROR] Browser console audit failed: {error}")
        print(install_hint_text("playwright"))
        return {"tool": "playwright", "installed": True, "error": str(error)}

    interesting_console = [entry for entry in console_entries if entry["type"] in {"error", "warning"}]
    print(f"[SUMMARY] Console warnings/errors: {len(interesting_console)}")
    print(f"[SUMMARY] Page errors: {len(page_errors)}")
    print(f"[SUMMARY] Failed requests: {len(request_failures)}")
    for entry in interesting_console[:20]:
        print(f"[CONSOLE:{entry['type']}] {entry['text']}")
    for error in page_errors[:10]:
        print(f"[PAGEERROR] {error}")
    for failure in request_failures[:10]:
        print(f"[REQUESTFAILED] {failure['url']} -> {failure['failure']}")

    return {
        "tool": "playwright",
        "installed": True,
        "console": console_entries,
        "page_errors": page_errors,
        "request_failures": request_failures,
    }


def run_js_external_tool(
    tool: str,
    target_url: str,
    js_urls: list[str],
    local_dir: Path,
    timeout: float,
) -> dict[str, object]:
    results: dict[str, object] = {"tool": tool, "results": []}
    if tool == "retire":
        for js_url in js_urls:
            results["results"].append(run_tool_command("retire", ["--js", js_url, "--outputformat", "json"], timeout))
    elif tool == "trufflehog":
        results["results"].append(run_tool_command("trufflehog", ["filesystem", str(local_dir), "--no-update"], timeout))
    elif tool == "semgrep":
        results["results"].append(run_tool_command("semgrep", ["--config", "p/javascript", "--json", "--quiet", str(local_dir)], timeout))
    elif tool == "linkfinder":
        for js_url in js_urls:
            results["results"].append(run_tool_command("linkfinder", ["-i", js_url, "-o", "cli"], timeout))
    elif tool == "secretfinder":
        for js_url in js_urls:
            results["results"].append(run_tool_command("secretfinder", ["-i", js_url, "-o", "cli"], timeout))
    elif tool == "sourcemapper":
        output_dir = local_dir / "sourcemapper-output"
        output_dir.mkdir(exist_ok=True)
        for js_url in js_urls:
            results["results"].append(run_tool_command("sourcemapper", ["-url", js_url, "-output", str(output_dir)], timeout))
    else:
        print(f"[skip] Unsupported JavaScript audit tool: {tool}")
        results["supported"] = False
    return results


def run_javascript_audit(
    url: str,
    tools: list[str],
    timeout: float,
    browser: bool,
    output: str | None,
) -> dict[str, object]:
    normalized = normalize_url(url)
    print(f"\n[+] JavaScript vulnerability/error audit for {normalized}")
    print("[i] This reviews public frontend JavaScript and browser errors; it does not bypass authentication.")

    status, _, body = http_request(normalized, method="GET", timeout=timeout)
    html = body.decode("utf-8", errors="ignore")
    js_urls = extract_script_urls(html, normalized)
    print(f"[STATUS] HTTP {status}")
    print(f"[JS] Found {len(js_urls)} external script URL(s).")
    for js_url in js_urls[:50]:
        print(f"  - {js_url}")
    if len(js_urls) > 50:
        print(f"  ... {len(js_urls) - 50} more")

    work_dir_context = tempfile.TemporaryDirectory() if output is None else None
    local_dir = Path(output) if output else Path(work_dir_context.name)
    local_dir.mkdir(parents=True, exist_ok=True)

    builtin_results: list[dict[str, object]] = []
    for js_url in js_urls:
        try:
            js_status, _, js_body = http_request(js_url, method="GET", timeout=timeout)
            js_text = js_body.decode("utf-8", errors="ignore")
        except ConnectionError as error:
            builtin_results.append({"url": js_url, "error": str(error)})
            continue

        filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", urlparse(js_url).path.strip("/") or "script.js")
        if not filename.endswith(".js"):
            filename += ".js"
        (local_dir / filename[-160:]).write_text(js_text, encoding="utf-8", errors="ignore")
        analysis = scan_javascript_text(js_url, js_text, timeout=timeout)
        analysis["status"] = js_status
        builtin_results.append(analysis)

    findings = [
        {"url": result["url"], **finding}
        for result in builtin_results
        for finding in result.get("findings", [])
    ]
    source_maps = [
        result["source_map"]
        for result in builtin_results
        if result.get("source_map") and result["source_map"].get("accessible")
    ]

    if findings:
        print("\n[Potential JavaScript issues]")
        for finding in findings[:50]:
            print(f"[JS] {finding['type']} at {finding['url']}:{finding['line']}")
    else:
        print("\n[OK] No obvious JavaScript exposure patterns found in sampled files.")

    if source_maps:
        print("\n[Accessible source maps]")
        for source_map in source_maps:
            print(f"[MAP] {source_map['url']} HTTP {source_map['status']}")

    browser_result = run_browser_console_audit(normalized, timeout=timeout) if browser else None

    external_results: list[dict[str, object]] = []
    for tool in tools:
        external_results.append(run_js_external_tool(tool, normalized, js_urls, local_dir, timeout))

    result_payload = {
        "url": normalized,
        "status": status,
        "script_urls": js_urls,
        "download_dir": str(local_dir) if output else None,
        "builtin": builtin_results,
        "findings": findings,
        "accessible_source_maps": source_maps,
        "browser": browser_result,
        "external": external_results,
    }
    if work_dir_context:
        work_dir_context.cleanup()
    return result_payload


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


def command_output(tool: str, args: list[str], timeout: float) -> dict[str, object]:
    tool_path = find_tool(tool)
    if not tool_path:
        return {"tool": tool, "installed": False, "stdout": "", "stderr": ""}
    command = [tool_path, *args]
    result = run_external(command, timeout=timeout)
    return {
        "tool": tool,
        "installed": True,
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def firewall_check(timeout: float) -> dict[str, object]:
    print("\n[+] Local firewall status check")
    print("[i] Read-only local firewall inventory.")
    commands = [
        ("ufw", ["status", "verbose"]),
        ("nft", ["list", "ruleset"]),
        ("iptables", ["-S"]),
    ]
    results: dict[str, object] = {}
    for tool, args in commands:
        key = f"{tool} {' '.join(args)}"
        result = command_output(tool, args, timeout)
        results[key] = result
        print(f"\n[{key}]")
        if not result["installed"]:
            print(f"[missing] {tool}")
            continue
        output = str(result.get("stdout", "")).strip() or str(result.get("stderr", "")).strip()
        print(output[:6000] if output else "No output.")
        if len(output) > 6000:
            print(f"... output truncated, {len(output) - 6000} more characters in JSON report.")
    return results


def service_audit(timeout: float) -> dict[str, object]:
    print("\n[+] Listening service audit")
    print("[i] Uses local ss/netstat output only.")
    if find_tool("ss"):
        result = command_output("ss", ["-tulpen"], timeout)
        key = "ss -tulpen"
    elif find_tool("netstat"):
        args = ["-anv"] if sys.platform == "darwin" else ["-tulpen"]
        result = command_output("netstat", args, timeout)
        key = f"netstat {' '.join(args)}"
    else:
        print("[missing] ss/netstat")
        return {"installed": False, "error": "ss or netstat is required."}

    output = str(result.get("stdout", "")).strip() or str(result.get("stderr", "")).strip()
    print(f"\n[{key}]")
    print(output if output else "No listening services reported.")
    return {"command_name": key, "result": result}


def update_check(timeout: float) -> dict[str, object]:
    print("\n[+] Package update check")
    print("[i] Read-only package manager check. Ktool does not install updates here.")
    plans = [
        ("apt", ["list", "--upgradable"]),
        ("dnf", ["check-update"]),
        ("pacman", ["-Qu"]),
    ]
    for tool, args in plans:
        if not find_tool(tool):
            continue
        result = command_output(tool, args, timeout)
        output = str(result.get("stdout", "")).strip() or str(result.get("stderr", "")).strip()
        print(f"\n[{tool} {' '.join(args)}]")
        print(output if output else "No updates reported by package manager.")
        return {"manager": tool, "result": result}
    print("[missing] apt/dnf/pacman")
    return {"manager": None, "error": "No supported package manager found."}


def ssh_audit_local(timeout: float) -> dict[str, object]:
    print("\n[+] Local SSH configuration audit")
    paths = [Path("/etc/ssh/sshd_config"), Path.home() / ".ssh" / "config"]
    findings: list[dict[str, str]] = []
    files: dict[str, object] = {}

    risky_server_options = {
        "PermitRootLogin": {"yes", "without-password", "prohibit-password"},
        "PasswordAuthentication": {"yes"},
        "PermitEmptyPasswords": {"yes"},
        "X11Forwarding": {"yes"},
    }

    for path in paths:
        print(f"\n[{path}]")
        if not path.exists():
            print("Not found.")
            files[str(path)] = {"exists": False}
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            print(f"Cannot read: {error}")
            files[str(path)] = {"exists": True, "readable": False, "error": str(error)}
            continue

        files[str(path)] = {"exists": True, "readable": True, "lines": len(text.splitlines())}
        active_lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        file_findings = 0
        for line in active_lines:
            parts = line.split()
            if len(parts) < 2:
                continue
            key, value = parts[0], parts[1].lower()
            for option, risky_values in risky_server_options.items():
                if key.lower() == option.lower() and value in {item.lower() for item in risky_values}:
                    finding = {"file": str(path), "option": option, "value": parts[1], "detail": "Review this SSH setting."}
                    findings.append(finding)
                    file_findings += 1
                    print(f"[REVIEW] {option} {parts[1]}")
        if not active_lines:
            print("No active options found.")
        elif file_findings == 0:
            print("No risky options found in active lines.")

    sshd = command_output("sshd", ["-T"], timeout) if find_tool("sshd") else {"installed": False}
    if sshd.get("installed"):
        print("\n[sshd -T]")
        output = str(sshd.get("stdout", "")).strip() or str(sshd.get("stderr", "")).strip()
        print(output[:4000] if output else "No output.")

    return {"files": files, "findings": findings, "sshd_effective_config": sshd}


def router_checklist() -> dict[str, object]:
    print("\n[+] Router hardening checklist")
    for index, item in enumerate(ROUTER_CHECKLIST, start=1):
        print(f"[ ] {index}. {item}")
    return {"items": ROUTER_CHECKLIST}


def dns_leak_check(include_public: bool, endpoint: str, timeout: float) -> dict[str, object]:
    print("\n[+] DNS leak awareness check")
    print("[i] Compares local resolver configuration with optional public egress IP.")
    commands: list[tuple[str, list[str]]] = []
    if find_tool("resolvectl"):
        commands.append(("resolvectl", ["status"]))
    elif find_tool("systemd-resolve"):
        commands.append(("systemd-resolve", ["--status"]))
    commands.extend([("cat", ["/etc/resolv.conf"]), ("nmcli", ["dev", "show"])])

    results: dict[str, object] = {"commands": {}, "public_egress": None}
    for tool, args in commands:
        key = f"{tool} {' '.join(args)}"
        result = command_output(tool, args, timeout)
        results["commands"][key] = result
        print(f"\n[{key}]")
        if not result["installed"]:
            print(f"[missing] {tool}")
            continue
        output = str(result.get("stdout", "")).strip() or str(result.get("stderr", "")).strip()
        print(output[:5000] if output else "No output.")

    if include_public:
        results["public_egress"] = public_egress_check(endpoint, timeout)
    return results


def lan_device_list(timeout: float) -> dict[str, object]:
    print("\n[+] Local LAN device list")
    print("[i] Read-only neighbor/ARP table. This does not scan the network.")
    commands = [("ip", ["neigh"]), ("arp", ["-a"])]
    results: dict[str, object] = {}
    for tool, args in commands:
        key = f"{tool} {' '.join(args)}"
        result = command_output(tool, args, timeout)
        results[key] = result
        print(f"\n[{key}]")
        if not result["installed"]:
            print(f"[missing] {tool}")
            continue
        output = str(result.get("stdout", "")).strip() or str(result.get("stderr", "")).strip()
        print(output if output else "No neighbor entries reported.")
    return results


def parse_neighbor_devices(text: str, source: str) -> list[dict[str, object]]:
    devices: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        ip_address = None
        mac_address = None
        interface = None
        hostname = None
        state = None

        linux_match = re.search(
            r"^(?P<ip>[0-9a-fA-F:.]+)\s+dev\s+(?P<iface>\S+).*?\s+lladdr\s+(?P<mac>[0-9a-fA-F:]{11,17})(?:\s+(?P<state>\S+))?",
            line,
        )
        arp_match = re.search(
            r"^(?P<host>\S+)\s+\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]{11,17}|incomplete)(?:\s+on\s+(?P<iface>\S+))?",
            line,
        )

        if linux_match:
            ip_address = linux_match.group("ip")
            mac_address = linux_match.group("mac")
            interface = linux_match.group("iface")
            state = linux_match.group("state")
        elif arp_match:
            ip_address = arp_match.group("ip")
            mac_address = arp_match.group("mac")
            interface = arp_match.group("iface")
            hostname = arp_match.group("host")
            if mac_address == "incomplete":
                state = "incomplete"
        else:
            continue

        if not ip_address or not mac_address or mac_address == "incomplete":
            continue
        try:
            parsed_ip = ipaddress.ip_address(ip_address)
            if parsed_ip.is_multicast or parsed_ip.is_unspecified:
                continue
        except ValueError:
            continue
        if ip_address.endswith(".255") or mac_address.lower() == "ff:ff:ff:ff:ff:ff":
            continue
        key = (ip_address, mac_address.lower())
        if key in seen:
            continue
        seen.add(key)
        devices.append(
            {
                "ip": ip_address,
                "mac": mac_address.lower(),
                "interface": interface,
                "hostname": hostname if hostname and hostname != "?" else None,
                "state": state,
                "source": source,
                "user": "unknown",
            }
        )
    return devices


def reverse_dns_name(ip_address: str, timeout: float) -> str | None:
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (OSError, socket.herror, socket.gaierror, TimeoutError):
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)


def parse_arp_scan_devices(text: str) -> list[dict[str, object]]:
    devices: list[dict[str, object]] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        ip_address, mac_address = parts[0].strip(), parts[1].strip().lower()
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip_address):
            continue
        if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac_address):
            continue
        vendor = parts[2].strip() if len(parts) > 2 else ""
        devices.append(
            {
                "ip": ip_address,
                "mac": mac_address,
                "interface": None,
                "hostname": None,
                "state": "active-discovery",
                "source": "arp-scan",
                "vendor": vendor,
                "user": "unknown",
            }
        )
    return devices


def current_wifi_context(interface: str | None, timeout: float) -> dict[str, object]:
    commands: list[tuple[str, list[str]]] = [
        ("hostname", []),
        ("ip", ["addr", "show"]),
        ("ip", ["route"]),
        ("iw", ["dev"]),
        ("nmcli", ["-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"]),
    ]
    if interface:
        commands.append(("iw", ["dev", interface, "link"]))

    context: dict[str, object] = {}
    for tool, args in commands:
        key = f"{tool} {' '.join(args)}".strip()
        context[key] = command_output(tool, args, timeout)
    return context


def wifi_device_user_check(
    interface: str | None,
    active: bool,
    resolve_names: bool,
    timeout: float,
    assume_authorized: bool,
) -> dict[str, object]:
    print("\n[+] WiFi device/user check")
    print("[i] Ktool can show devices visible to your local machine. It cannot identify private owner names.")
    print("[i] User is reported as unknown unless your network exposes a hostname.")

    if active:
        require_authorization(assume_authorized)

    context = current_wifi_context(interface, timeout)
    print("\n[Local WiFi/network context]")
    for key, result in context.items():
        if not isinstance(result, dict):
            continue
        print(f"\n[{key}]")
        if not result.get("installed"):
            print(f"[missing] {str(key).split()[0]}")
            continue
        output = str(result.get("stdout", "")).strip() or str(result.get("stderr", "")).strip()
        print(output[:3000] if output else "No output.")

    neighbor_results = {
        "ip neigh": command_output("ip", ["neigh"], timeout),
        "arp -a": command_output("arp", ["-a"], timeout),
    }
    devices: list[dict[str, object]] = []
    print("\n[Visible neighbor devices]")
    for key, result in neighbor_results.items():
        if not result.get("installed"):
            print(f"[missing] {str(key).split()[0]}")
            continue
        output = str(result.get("stdout", "")).strip() or str(result.get("stderr", "")).strip()
        parsed = parse_neighbor_devices(output, key)
        devices.extend(parsed)

    deduped: dict[tuple[str, str], dict[str, object]] = {}
    for device in devices:
        deduped[(str(device["ip"]), str(device["mac"]))] = device
    devices = list(deduped.values())

    active_result = None
    if active:
        args = ["--localnet"]
        if interface:
            args.extend(["--interface", interface])
        active_result = run_tool_command("arp-scan", args, timeout, active=True)
        if active_result.get("installed") and active_result.get("stdout"):
            for device in parse_arp_scan_devices(str(active_result.get("stdout", ""))):
                deduped[(str(device["ip"]), str(device["mac"]))] = device
            devices = list(deduped.values())

    if resolve_names:
        for device in devices:
            if not device.get("hostname"):
                name = reverse_dns_name(str(device["ip"]), timeout=min(timeout, 3.0))
                if name:
                    device["hostname"] = name
                    device["user"] = name

    if not devices:
        print("No neighbor devices found. Try again after communicating with devices on your LAN, or use --active on your own network.")
    else:
        print("IP | MAC | Hostname/User hint | Interface | Source")
        for device in sorted(devices, key=lambda item: str(item["ip"])):
            hint = str(device.get("hostname") or device.get("user") or "unknown")
            interface_text = str(device.get("interface") or "?")
            print(f"{device['ip']} | {device['mac']} | {hint} | {interface_text} | {device['source']}")

    return {
        "interface": interface,
        "active": active,
        "resolve_names": resolve_names,
        "context": context,
        "neighbor_results": neighbor_results,
        "active_result": active_result,
        "devices": devices,
        "privacy_note": "Ktool does not identify private owner names. Hostnames are only local network hints.",
    }


def parse_nmcli_wifi_rows(output: str) -> list[dict[str, object]]:
    networks: list[dict[str, object]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split(":")
        while len(parts) < 6:
            parts.append("")
        in_use, ssid, security, signal, frequency, channel = parts[:6]
        try:
            signal_value: int | None = int(signal) if signal else None
        except ValueError:
            signal_value = None
        networks.append(
            {
                "in_use": in_use.strip() == "*",
                "ssid": ssid.strip() or "<hidden>",
                "security": security.strip(),
                "signal": signal_value,
                "frequency": frequency.strip(),
                "channel": channel.strip(),
            }
        )
    return networks


def classify_wifi_security(security: str) -> tuple[str, str]:
    value = security.upper().strip()
    if not value or value == "--":
        return "high", "Open network: no WiFi encryption advertised."
    if "WEP" in value:
        return "high", "WEP is obsolete and should not be used."
    if "WPA1" in value or value == "WPA":
        return "medium", "WPA1/TKIP-era security is legacy and should be replaced."
    if "WPA3" in value:
        return "info", "WPA3-capable network observed."
    if "WPA2" in value:
        return "info", "WPA2 network observed."
    return "low", f"Review advertised WiFi security: {security}"


def wifi_scan(rescan: bool, timeout: float) -> dict[str, object]:
    print("\n[+] WiFi network scan")
    print("[i] Read-only scan using NetworkManager. It does not capture handshakes or test passwords.")

    nmcli_result = command_output(
        "nmcli",
        ["-t", "-f", "IN-USE,SSID,SECURITY,SIGNAL,FREQ,CHAN", "device", "wifi", "list", "--rescan", "yes" if rescan else "no"],
        timeout,
    )
    if not nmcli_result["installed"]:
        print("[missing] nmcli")
        print(install_hint_text("nmcli"))
        return {"networks": [], "nmcli": nmcli_result}

    if nmcli_result.get("stderr"):
        stderr = str(nmcli_result["stderr"]).strip()
        if stderr:
            print(stderr, file=sys.stderr)

    networks = parse_nmcli_wifi_rows(str(nmcli_result.get("stdout", "")))
    if not networks:
        print("[i] No WiFi networks returned by nmcli.")
    else:
        print("[SSID] Security | Signal | Channel")
        for network in networks[:80]:
            marker = "*" if network["in_use"] else " "
            print(
                f"{marker} {network['ssid']} | {network['security'] or 'OPEN'} | "
                f"{network['signal'] if network['signal'] is not None else '?'} | {network['channel'] or '?'}"
            )
        if len(networks) > 80:
            print(f"[i] Showing first 80 networks out of {len(networks)}.")

    findings: list[dict[str, object]] = []
    for network in networks:
        severity, detail = classify_wifi_security(str(network["security"]))
        if severity in {"high", "medium"}:
            findings.append(
                {
                    "severity": severity,
                    "type": "weak_wifi_security",
                    "ssid": network["ssid"],
                    "detail": detail,
                }
            )

    if findings:
        print("\n[Potential WiFi issues]")
        for finding in findings[:30]:
            print(f"[{finding['severity'].upper()}] {finding['ssid']}: {finding['detail']}")
    else:
        print("\n[OK] No open/WEP/WPA1 networks were highlighted by the scan.")

    return {"networks": networks, "findings": findings, "nmcli": nmcli_result}


def wifi_security_check(interface: str | None, scan: bool, timeout: float) -> dict[str, object]:
    print("\n[+] WiFi security checker")
    print("[i] Defensive/read-only mode. Ktool does not enable monitor mode, capture handshakes, deauth clients, or crack keys.")

    results: dict[str, object] = {
        "interface": interface,
        "commands": {},
        "scan": None,
        "findings": [],
    }

    command_plan: list[tuple[str, list[str]]] = [
        ("nmcli", ["device", "status"]),
        ("nmcli", ["-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"]),
        ("ip", ["route"]),
    ]
    if find_tool("resolvectl"):
        command_plan.append(("resolvectl", ["status"]))
    elif find_tool("systemd-resolve"):
        command_plan.append(("systemd-resolve", ["--status"]))
    command_plan.append(("iw", ["dev"]))
    if interface:
        command_plan.append(("iw", ["dev", interface, "link"]))

    for tool, args in command_plan:
        key = f"{tool} {' '.join(args)}"
        result = command_output(tool, args, timeout)
        results["commands"][key] = result
        print(f"\n[{key}]")
        if not result["installed"]:
            print(f"[missing] {tool}")
            if tool in INSTALL_HINTS:
                print(install_hint_text(tool))
            continue
        output = str(result.get("stdout", "")).strip() or str(result.get("stderr", "")).strip()
        print(output if output else "No output.")

    active_wifi = command_output("nmcli", ["-t", "-f", "ACTIVE,SSID,SECURITY,SIGNAL,FREQ,CHAN", "device", "wifi", "list", "--rescan", "no"], timeout)
    active_networks = [
        network
        for network in parse_nmcli_wifi_rows(str(active_wifi.get("stdout", "")))
        if network.get("in_use")
    ]
    results["active_wifi"] = active_networks
    results["commands"]["nmcli active wifi"] = active_wifi

    findings: list[dict[str, object]] = []
    if active_networks:
        print("\n[Active WiFi]")
        for network in active_networks:
            severity, detail = classify_wifi_security(str(network["security"]))
            print(
                f"* {network['ssid']} | {network['security'] or 'OPEN'} | "
                f"signal {network['signal'] if network['signal'] is not None else '?'} | channel {network['channel'] or '?'}"
            )
            if severity in {"high", "medium"}:
                findings.append(
                    {
                        "severity": severity,
                        "type": "active_wifi_weak_security",
                        "ssid": network["ssid"],
                        "detail": detail,
                    }
                )
            if network.get("signal") is not None and int(network["signal"]) < 30:
                findings.append(
                    {
                        "severity": "low",
                        "type": "weak_signal",
                        "ssid": network["ssid"],
                        "detail": "Low WiFi signal can cause instability and roaming problems.",
                    }
                )
    else:
        print("\n[i] No active WiFi connection found through nmcli.")

    scan_result = wifi_scan(rescan=True, timeout=timeout) if scan else None
    results["scan"] = scan_result
    if scan_result:
        findings.extend(scan_result.get("findings", []))

    results["findings"] = findings
    if findings:
        print("\n[WiFi security summary]")
        for finding in findings[:40]:
            label = finding.get("ssid", finding.get("type"))
            print(f"[{finding['severity'].upper()}] {label}: {finding['detail']}")
    else:
        print("\n[OK] No obvious WiFi security issues found from read-only checks.")

    recommendations = [
        "Use WPA3-Personal/Enterprise where possible; WPA2-AES is the minimum practical baseline.",
        "Disable open, WEP, and WPA1/TKIP networks.",
        "Use a strong unique WiFi passphrase or 802.1X for enterprise networks.",
        "Keep router/AP firmware updated.",
        "Separate guest WiFi from internal systems.",
        "Disable WPS if it is enabled.",
    ]
    print("\n[Recommendations]")
    for item in recommendations:
        print(f"  - {item}")
    results["recommendations"] = recommendations
    return results


def privacy_methods() -> dict[str, object]:
    methods = [
        {
            "name": "Trusted VPN",
            "use": "Lawful privacy, remote work, lab segmentation, and protecting traffic on untrusted networks.",
            "notes": "Choose a provider or corporate VPN you trust; verify DNS handling and kill-switch behavior.",
        },
        {
            "name": "Tor Browser",
            "use": "Privacy-preserving web browsing and research where Tor is legal and appropriate.",
            "notes": "Use Tor Browser for browsing. Ktool does not route scans or assessment traffic through Tor.",
        },
        {
            "name": "Corporate proxy",
            "use": "Approved enterprise egress control, logging, and policy enforcement.",
            "notes": "Document proxy use in the engagement scope and avoid bypassing client logging requirements.",
        },
        {
            "name": "Separate lab network",
            "use": "Keeping test traffic away from personal or production networks.",
            "notes": "Prefer isolated lab infrastructure for training, exploit validation, and noisy scanner testing.",
        },
    ]
    boundaries = [
        "Do not use privacy tooling to attack third-party systems.",
        "Do not bypass authorization, rate limits, client logging, or legal controls.",
        "Do not use Ktool to chain scanners through anonymizing proxies.",
        "For professional work, document the egress IPs and VPN/proxy setup in the rules of engagement.",
    ]

    print("\n[+] Safe IP privacy methods")
    for method in methods:
        print(f"\n{method['name']}")
        print(f"  Use: {method['use']}")
        print(f"  Note: {method['notes']}")

    print("\n[Boundaries]")
    for item in boundaries:
        print(f"  - {item}")

    return {"methods": methods, "boundaries": boundaries}


def public_ip_lookup(endpoint: str, timeout: float) -> dict[str, object]:
    normalized = normalize_url(endpoint)
    try:
        status, headers, body = http_request(normalized, method="GET", timeout=timeout)
    except ConnectionError as error:
        print(f"[WARN] Public egress lookup failed: {error}")
        return {"endpoint": normalized, "status": None, "error": str(error)}

    text = body.decode("utf-8", errors="ignore").strip()
    print(f"[PUBLIC EGRESS] {text if text else 'No response body.'}")
    return {
        "endpoint": normalized,
        "status": status,
        "content_type": headers.get("Content-Type", ""),
        "body": text,
    }


def proxy_environment() -> dict[str, str]:
    names = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ]
    return {name: os.environ[name] for name in names if os.environ.get(name)}


def ip_privacy_check(include_public: bool, endpoint: str, timeout: float) -> dict[str, object]:
    print("\n[+] IP privacy and egress checker")
    print("[i] Read-only review. Ktool does not hide traffic, route scans through proxies, or bypass logging.")

    command_plan: list[tuple[str, list[str]]] = [
        ("ip", ["addr", "show"]),
        ("ip", ["route"]),
        ("nmcli", ["connection", "show", "--active"]),
        ("wg", ["show"]),
        ("systemctl", ["is-active", "tor"]),
        ("systemctl", ["is-active", "openvpn"]),
    ]
    if find_tool("resolvectl"):
        command_plan.append(("resolvectl", ["status"]))
    elif find_tool("systemd-resolve"):
        command_plan.append(("systemd-resolve", ["--status"]))

    results: dict[str, object] = {
        "commands": {},
        "proxy_environment": proxy_environment(),
        "public_egress": None,
        "findings": [],
    }

    combined_output = ""
    for tool, args in command_plan:
        key = f"{tool} {' '.join(args)}"
        result = command_output(tool, args, timeout)
        results["commands"][key] = result
        print(f"\n[{key}]")
        if not result["installed"]:
            print(f"[missing] {tool}")
            if tool in INSTALL_HINTS:
                print(install_hint_text(tool))
            continue
        output = str(result.get("stdout", "")).strip() or str(result.get("stderr", "")).strip()
        combined_output += "\n" + output.lower()
        print(output if output else "No output.")

    proxy_env = results["proxy_environment"]
    print("\n[Proxy environment]")
    if proxy_env:
        for name, value in proxy_env.items():
            print(f"{name}={value}")
    else:
        print("No HTTP(S)/SOCKS proxy environment variables are set.")

    public_result = public_ip_lookup(endpoint, timeout=timeout) if include_public else None
    results["public_egress"] = public_result
    if not include_public:
        print("\n[i] Public egress IP lookup skipped. Add --public to query the configured endpoint.")

    findings: list[dict[str, object]] = []
    if not proxy_env:
        findings.append(
            {
                "severity": "info",
                "type": "no_proxy_env",
                "detail": "No proxy environment variables are set for shell-launched tools.",
            }
        )
    if not any(marker in combined_output for marker in ("tun0", "wg0", "wireguard", "openvpn")):
        findings.append(
            {
                "severity": "info",
                "type": "no_obvious_vpn_interface",
                "detail": "No obvious tun/wg/OpenVPN indicator was observed in local command output.",
            }
        )
    if "nameserver" in combined_output or "dns servers" in combined_output:
        findings.append(
            {
                "severity": "info",
                "type": "dns_review_required",
                "detail": "Review DNS servers for possible DNS leaks when using VPN or privacy tooling.",
            }
        )

    results["findings"] = findings
    print("\n[Privacy review notes]")
    for finding in findings:
        print(f"[{finding['severity'].upper()}] {finding['type']}: {finding['detail']}")

    recommendations = [
        "Use privacy tooling only for lawful privacy or authorized assessment infrastructure.",
        "Document approved egress IPs in the rules of engagement.",
        "Verify public IP and DNS behavior before an assessment starts.",
        "Use a VPN kill switch where appropriate.",
        "Keep client logging and authorization requirements intact.",
    ]
    print("\n[Recommendations]")
    for item in recommendations:
        print(f"  - {item}")
    results["recommendations"] = recommendations
    return results


def parse_ping_summary(output: str) -> dict[str, object]:
    packet_loss = None
    average_ms = None
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", output)
    if loss_match:
        packet_loss = float(loss_match.group(1))
    avg_match = re.search(r"(?:rtt|round-trip).*?=\s*([\d.]+)/([\d.]+)/([\d.]+)/", output)
    if avg_match:
        average_ms = float(avg_match.group(2))
    return {"packet_loss_percent": packet_loss, "average_ms": average_ms}


def iphone_health_guide() -> dict[str, object]:
    checks = [
        "On iPhone: Settings > Wi-Fi, confirm it is connected to the expected SSID.",
        "Tap the Wi-Fi network info button and check signal, IP address, router, DNS, and Private Wi-Fi Address.",
        "Run Ktool `iphone-check --ip <iphone-ip>` from the same trusted LAN to test reachability.",
        "For USB health info, unlock the iPhone, tap Trust This Computer, then run `iphone-usb-info`.",
        "On iPhone: Settings > Battery > Battery Health & Charging for Apple’s official battery health value.",
        "Keep iOS updated and avoid unknown configuration profiles or unmanaged VPNs.",
    ]
    print("\n[+] iPhone WiFi and health checklist")
    for index, item in enumerate(checks, start=1):
        print(f"{index}. {item}")
    return {"checks": checks}


def iphone_usb_info(timeout: float) -> dict[str, object]:
    print("\n[+] iPhone USB device info")
    print("[i] Requires an unlocked iPhone that trusts this computer. Ktool does not bypass pairing or passcodes.")

    results: dict[str, object] = {"commands": {}, "findings": []}
    commands = [
        ("idevice_id", ["-l"]),
        ("idevicepair", ["validate"]),
        ("ideviceinfo", []),
        ("ideviceinfo", ["-q", "com.apple.mobile.battery"]),
    ]

    for tool, args in commands:
        key = f"{tool} {' '.join(args)}".strip()
        result = command_output(tool, args, timeout)
        results["commands"][key] = result
        print(f"\n[{key}]")
        if not result["installed"]:
            print(f"[missing] {tool}")
            print(install_hint_text(tool))
            continue
        output = str(result.get("stdout", "")).strip() or str(result.get("stderr", "")).strip()
        print(output if output else "No output.")

    battery_text = str(results["commands"].get("ideviceinfo -q com.apple.mobile.battery", {}).get("stdout", ""))
    capacity_match = re.search(r"BatteryCurrentCapacity:\s*(\d+)", battery_text)
    if capacity_match:
        capacity = int(capacity_match.group(1))
        if capacity < 30:
            results["findings"].append(
                {
                    "severity": "low",
                    "type": "low_battery",
                    "detail": f"Connected iPhone battery is at {capacity}%.",
                }
            )

    if results["findings"]:
        print("\n[iPhone USB findings]")
        for finding in results["findings"]:
            print(f"[{finding['severity'].upper()}] {finding['type']}: {finding['detail']}")
    return results


def iphone_mdns_discovery(timeout: float) -> dict[str, object]:
    print("\n[+] iPhone Bonjour/mDNS discovery")
    print("[i] This only reads local mDNS advertisements on your LAN.")

    avahi = command_output("avahi-browse", ["-a", "-t"], timeout)
    if not avahi["installed"]:
        print("[missing] avahi-browse")
        print(install_hint_text("avahi-browse"))
        return {"installed": False, "matches": []}

    output = str(avahi.get("stdout", ""))
    keywords = ("iphone", "ipad", "_apple-mobdev2", "_airplay", "_raop", "_companion-link")
    matches = [line for line in output.splitlines() if any(keyword in line.lower() for keyword in keywords)]
    if matches:
        for line in matches[:80]:
            print(line)
        if len(matches) > 80:
            print(f"[i] Showing first 80 matches out of {len(matches)}.")
    else:
        print("[i] No obvious iPhone/iPad Bonjour records found.")
    if str(avahi.get("stderr", "")).strip():
        print(str(avahi["stderr"]).strip(), file=sys.stderr)
    return {"installed": True, "command": avahi.get("command"), "matches": matches, "stdout": output, "stderr": avahi.get("stderr", "")}


def iphone_wifi_check(
    ip_address: str | None,
    name: str | None,
    count: int,
    timeout: float,
    mdns: bool,
    usb: bool,
) -> dict[str, object]:
    print("\n[+] iPhone WiFi and device health check")
    print("[i] Use only for your own iPhone or an authorized device. Ktool does not bypass iPhone privacy controls.")

    if count < 1 or count > 20:
        raise ValueError("--count must be between 1 and 20.")

    results: dict[str, object] = {
        "ip": ip_address,
        "name": name,
        "ping": None,
        "neighbor": None,
        "mdns": None,
        "usb": None,
        "findings": [],
    }

    if ip_address:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            raise ValueError("--ip must be a valid IPv4 or IPv6 address.") from None

        ping_args = ["-c", str(count), "-W", str(max(1, int(timeout))), ip_address]
        ping_result = command_output("ping", ping_args, timeout=max(timeout * count, timeout + 2))
        results["ping"] = ping_result
        print(f"\n[ping {ip_address}]")
        if not ping_result["installed"]:
            print("[missing] ping")
            print(install_hint_text("ping"))
        else:
            output = str(ping_result.get("stdout", "")).strip() or str(ping_result.get("stderr", "")).strip()
            print(output if output else "No output.")
            summary = parse_ping_summary(output)
            results["ping_summary"] = summary
            loss = summary.get("packet_loss_percent")
            avg = summary.get("average_ms")
            if loss is not None and loss > 0:
                results["findings"].append(
                    {
                        "severity": "medium" if loss >= 25 else "low",
                        "type": "packet_loss",
                        "detail": f"Ping packet loss is {loss}%.",
                    }
                )
            if avg is not None and avg > 150:
                results["findings"].append(
                    {
                        "severity": "low",
                        "type": "high_latency",
                        "detail": f"Average latency is {avg} ms.",
                    }
                )

        neighbor_result = command_output("ip", ["neigh", "show", ip_address], timeout)
        results["neighbor"] = neighbor_result
        print(f"\n[ip neigh show {ip_address}]")
        if not neighbor_result["installed"]:
            print("[missing] ip")
            print(install_hint_text("ip"))
        else:
            output = str(neighbor_result.get("stdout", "")).strip() or str(neighbor_result.get("stderr", "")).strip()
            print(output if output else "No neighbor entry found.")
    else:
        print("[i] No --ip provided, so WiFi reachability and neighbor checks were skipped.")

    if mdns or name:
        mdns_result = iphone_mdns_discovery(timeout=timeout)
        results["mdns"] = mdns_result
        if name and mdns_result.get("matches"):
            lowered = name.lower()
            name_matches = [line for line in mdns_result["matches"] if lowered in line.lower()]
            results["mdns_name_matches"] = name_matches
            if not name_matches:
                results["findings"].append(
                    {
                        "severity": "info",
                        "type": "mdns_name_not_seen",
                        "detail": f"No Bonjour entry matched requested name: {name}",
                    }
                )

    if usb:
        results["usb"] = iphone_usb_info(timeout=timeout)

    if results["findings"]:
        print("\n[iPhone WiFi findings]")
        for finding in results["findings"]:
            print(f"[{finding['severity'].upper()}] {finding['type']}: {finding['detail']}")
    else:
        print("\n[OK] No obvious iPhone WiFi health issues found from selected checks.")

    recommendations = [
        "Keep the iPhone on the expected trusted SSID and avoid open/WEP/WPA1 networks.",
        "Use WPA2-AES or WPA3 on the access point.",
        "Check iPhone Settings > Battery > Battery Health & Charging for official battery condition.",
        "If ping loss is high, move closer to the AP, check channel congestion, and reboot the AP/iPhone if needed.",
        "For USB checks, unlock the iPhone and trust the computer; do not attempt to bypass pairing.",
    ]
    print("\n[Recommendations]")
    for item in recommendations:
        print(f"  - {item}")
    results["recommendations"] = recommendations
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


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip().lower()).strip("-")
    return slug or "ktool-engagement"


def ktool_dir() -> Path:
    path = Path(".ktool")
    path.mkdir(exist_ok=True)
    return path


def scope_file_path(path: str | None = None) -> Path:
    return Path(path) if path else ktool_dir() / "scope.json"


def load_scope(path: str | None = None) -> dict[str, object]:
    scope_path = scope_file_path(path)
    if not scope_path.exists():
        return {"targets": [], "created_at": datetime.now(timezone.utc).isoformat()}
    return json.loads(scope_path.read_text(encoding="utf-8"))


def save_scope_data(data: dict[str, object], path: str | None = None) -> Path:
    scope_path = scope_file_path(path)
    scope_path.parent.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    scope_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return scope_path


def target_identifier(value: str) -> str:
    if "://" in value:
        host = host_from_url_or_host(value)
        return host.lower().strip(".")
    return value.lower().strip().strip(".")


def target_in_scope(target: str, entries: list[dict[str, object]]) -> tuple[bool, dict[str, object] | None]:
    normalized = target_identifier(target)
    for entry in entries:
        pattern = str(entry.get("target", "")).lower().strip().strip(".")
        if not pattern:
            continue
        if pattern.startswith("*.") and normalized.endswith(pattern[1:]):
            return True, entry
        if fnmatch.fnmatch(normalized, pattern):
            return True, entry
        if normalized == pattern:
            return True, entry
    return False, None


def scope_manager(action: str, target: str | None, note: str | None, path: str | None) -> dict[str, object]:
    data = load_scope(path)
    entries = list(data.get("targets", []))

    if action == "add":
        if not target:
            raise ValueError("scope add requires --target.")
        normalized = target_identifier(target)
        in_scope, _ = target_in_scope(normalized, entries)
        if not in_scope:
            entries.append(
                {
                    "target": normalized,
                    "note": note or "",
                    "added_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            data["targets"] = entries
            saved = save_scope_data(data, path)
            print(f"[+] Added scope target: {normalized}")
            print(f"[+] Scope saved to {saved}")
        else:
            print(f"[i] Scope target already covered: {normalized}")
    elif action == "list":
        print("\n[+] Ktool scope targets")
        if not entries:
            print("  No scope targets saved yet.")
        for entry in entries:
            note_text = f" - {entry.get('note')}" if entry.get("note") else ""
            print(f"  - {entry.get('target')}{note_text}")
    elif action == "check":
        if not target:
            raise ValueError("scope check requires --target.")
        in_scope, match = target_in_scope(target, entries)
        status = "IN SCOPE" if in_scope else "OUT OF SCOPE"
        print(f"[{status}] {target_identifier(target)}")
        if match:
            print(f"Matched: {match.get('target')}")
    elif action == "remove":
        if not target:
            raise ValueError("scope remove requires --target.")
        normalized = target_identifier(target)
        remaining = [entry for entry in entries if str(entry.get("target")) != normalized]
        data["targets"] = remaining
        saved = save_scope_data(data, path)
        print(f"[+] Removed {len(entries) - len(remaining)} scope entry for {normalized}")
        print(f"[+] Scope saved to {saved}")
    elif action == "clear":
        data["targets"] = []
        saved = save_scope_data(data, path)
        print(f"[+] Cleared scope file: {saved}")
    else:
        raise ValueError(f"Unsupported scope action: {action}")

    return data


def ensure_target_in_scope_or_warn(target: str, scope_path: str | None) -> dict[str, object]:
    data = load_scope(scope_path)
    entries = list(data.get("targets", []))
    if not entries:
        print("[i] No .ktool/scope.json entries found. Document scope with: ktool scope add --target <target>")
        return {"configured": False, "in_scope": None}
    in_scope, match = target_in_scope(target, entries)
    if in_scope:
        print(f"[scope] {target_identifier(target)} matched {match.get('target')}")
    else:
        print(f"[WARN] {target_identifier(target)} does not match saved Ktool scope. Confirm authorization before continuing.")
    return {"configured": True, "in_scope": in_scope, "match": match}


def evidence_init(target: str, base_dir: str) -> dict[str, object]:
    normalized = target_identifier(target)
    root = Path(base_dir) / slugify(normalized)
    folders = ["evidence", "screenshots", "scans", "notes", "reports", "findings"]
    for folder in folders:
        (root / folder).mkdir(parents=True, exist_ok=True)
    readme = root / "README.md"
    if not readme.exists():
        readme.write_text(
            f"# Ktool Evidence: {normalized}\n\n"
            "Use this folder for authorized assessment evidence only.\n\n"
            "- `evidence/`: raw proof files\n"
            "- `screenshots/`: visual evidence\n"
            "- `scans/`: scan output\n"
            "- `notes/`: working notes\n"
            "- `findings/`: finding JSON files\n"
            "- `reports/`: exported reports\n",
            encoding="utf-8",
        )
    print(f"[+] Evidence workspace created: {root}")
    return {"target": normalized, "root": str(root), "folders": folders}


def checklist(category: str) -> dict[str, object]:
    if category not in CHECKLISTS:
        raise ValueError(f"Unknown checklist: {category}")
    print(f"\n[+] Ktool {category} checklist")
    for index, item in enumerate(CHECKLISTS[category], start=1):
        print(f"[ ] {index}. {item}")
    return {"category": category, "items": CHECKLISTS[category]}


def normalize_myanmar_plate_text(value: str) -> str:
    value = value.strip().upper()
    value = re.sub(r"[\s/_]+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-")


def myanmar_plate_tokens(value: str) -> list[str]:
    return re.findall(r"[A-Z0-9]+", value.upper())


def myanmar_plate_check(plate: str | None, region: str | None, vehicle_type: str | None) -> dict[str, object]:
    if not plate:
        raise ValueError("myanmar-plate-check requires a plate value.")

    normalized = normalize_myanmar_plate_text(plate)
    tokens = myanmar_plate_tokens(normalized)
    explicit_region = normalize_myanmar_plate_text(region) if region else None
    region_code = explicit_region or (tokens[0] if tokens and tokens[0] in MYANMAR_REGION_CODES else None)
    body_tokens = tokens[:]
    if region_code and body_tokens and body_tokens[0] == region_code:
        body_tokens = body_tokens[1:]
    body = "".join(body_tokens)

    checks: list[dict[str, object]] = []

    def add_check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    add_check("plate text present", bool(body), "Plate body after optional region extraction.")
    add_check("letters or digits only", bool(body) and body.isalnum(), "Ktool removes spaces, slashes, and dashes before this check.")
    add_check("contains number", any(char.isdigit() for char in body), "Vehicle plates normally include numeric registration data.")
    add_check("reasonable length", 3 <= len(body) <= 16, "Short or very long values need manual document review.")

    common_patterns = [
        r"\d{1,3}[A-Z]{1,4}\d{1,5}",
        r"[A-Z]{1,4}\d{1,6}",
        r"\d{1,6}[A-Z]{1,4}",
        r"\d{3,8}",
    ]
    pattern_match = any(re.fullmatch(pattern, body) for pattern in common_patterns)
    add_check(
        "common plate shape",
        pattern_match,
        "Common observed shapes only. Myanmar registrations can vary by vehicle class and issuing authority.",
    )

    region_known = region_code in MYANMAR_REGION_CODES if region_code else False
    if region_code:
        add_check(
            "region code hint",
            region_known,
            MYANMAR_REGION_CODES.get(region_code, "Region code was not in Ktool's local guidance list."),
        )

    passed_count = sum(1 for item in checks if item["passed"])
    status = "review-needed"
    if body and passed_count == len(checks):
        status = "format-plausible"
    elif body and passed_count >= max(1, len(checks) - 1):
        status = "format-needs-manual-check"

    print("\n[+] Ktool Myanmar vehicle plate review")
    print(f"Input: {plate}")
    print(f"Normalized: {normalized}")
    if vehicle_type:
        print(f"Vehicle type note: {vehicle_type}")
    if region_code:
        region_label = MYANMAR_REGION_CODES.get(region_code, "unknown region code")
        print(f"Region hint: {region_code} - {region_label}")
    else:
        print("Region hint: not supplied or not detected.")
    print(f"Plate body: {body or 'not detected'}")
    print(f"Status: {status}")

    print("\nChecks:")
    for item in checks:
        marker = "OK" if item["passed"] else "REVIEW"
        print(f"  [{marker}] {item['name']}: {item['detail']}")

    print("\nLegal verification:")
    for index, item in enumerate(CHECKLISTS["vehicle"], start=1):
        print(f"  {index}. {item}")
    print("\n[i] Ktool does not search private owner names or registration records.")

    return {
        "input": plate,
        "normalized": normalized,
        "region_code": region_code,
        "region_hint": MYANMAR_REGION_CODES.get(region_code) if region_code else None,
        "vehicle_type": vehicle_type,
        "plate_body": body,
        "status": status,
        "checks": checks,
        "owner_lookup": "not supported; use RTAD or another official legal channel",
        "verification_checklist": CHECKLISTS["vehicle"],
    }


def myanmar_vehicle_checklist() -> dict[str, object]:
    print("\n[+] Ktool Myanmar vehicle verification checklist")
    for index, item in enumerate(CHECKLISTS["vehicle"], start=1):
        print(f"[ ] {index}. {item}")
    print("\n[i] Owner names and private registration data must be verified through official/legal channels.")
    return {"category": "vehicle", "items": CHECKLISTS["vehicle"], "owner_lookup": "not supported"}


def finding_new(
    title: str,
    severity: str,
    asset: str,
    evidence: str,
    impact: str,
    remediation: str,
    references: str,
    output_dir: str,
) -> dict[str, object]:
    finding = {
        "id": f"KT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "title": title,
        "severity": severity,
        "asset": asset,
        "evidence": evidence,
        "impact": impact,
        "remediation": remediation,
        "references": [item.strip() for item in references.split(",") if item.strip()],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{finding['id']}-{slugify(title)}.json"
    path.write_text(json.dumps(finding, indent=2), encoding="utf-8")
    print(f"[+] Finding saved: {path}")
    return {"path": str(path), "finding": finding}


def report_init(client: str, target: str, output: str) -> dict[str, object]:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ValueError(f"Report already exists: {path}")
    content = (
        f"# Ktool Pentest Report - {client}\n\n"
        "## Scope\n\n"
        f"- Target: {target}\n"
        "- Authorization: Documented by tester/client.\n\n"
        "## Executive Summary\n\n"
        "Write a concise business-risk summary here.\n\n"
        "## Methodology\n\n"
        "- Reconnaissance\n"
        "- Web and network validation\n"
        "- Evidence review\n"
        "- Remediation guidance\n\n"
        "## Findings\n\n"
        "Export findings with `ktool report-export` or add them manually.\n\n"
        "## Limitations\n\n"
        "Document testing windows, unavailable systems, and excluded techniques.\n"
    )
    path.write_text(content, encoding="utf-8")
    print(f"[+] Report template created: {path}")
    return {"path": str(path), "client": client, "target": target}


def load_finding_files(findings_dir: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for path in sorted(Path(findings_dir).glob("*.json")):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            item["_path"] = str(path)
            findings.append(item)
        except json.JSONDecodeError:
            print(f"[WARN] Skipping invalid finding JSON: {path}")
    return findings


def report_export(client: str, target: str, findings_dir: str, output: str) -> dict[str, object]:
    findings = load_finding_files(findings_dir)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: severity_order.get(str(item.get("severity", "info")).lower(), 9))

    lines = [
        f"# Ktool Pentest Report - {client}",
        "",
        "## Scope",
        "",
        f"- Target: {target}",
        "- Authorization: Documented by tester/client.",
        "",
        "## Findings Summary",
        "",
    ]
    if findings:
        for finding in findings:
            lines.append(f"- {finding.get('severity', 'info').upper()}: {finding.get('title', 'Untitled')} ({finding.get('asset', target)})")
    else:
        lines.append("- No finding JSON files were found.")

    lines.extend(["", "## Detailed Findings", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding.get('title', 'Untitled')}",
                "",
                f"- ID: {finding.get('id', 'N/A')}",
                f"- Severity: {finding.get('severity', 'info')}",
                f"- Asset: {finding.get('asset', target)}",
                "",
                "Evidence:",
                "",
                str(finding.get("evidence", "")),
                "",
                "Impact:",
                "",
                str(finding.get("impact", "")),
                "",
                "Remediation:",
                "",
                str(finding.get("remediation", "")),
                "",
            ]
        )
        refs = finding.get("references", [])
        if refs:
            lines.append("References:")
            lines.append("")
            for ref in refs:
                lines.append(f"- {ref}")
            lines.append("")

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"[+] Report exported: {path}")
    return {"path": str(path), "findings": findings}


def engagement_init(client: str, target: str, base_dir: str, scope_file: str | None) -> dict[str, object]:
    normalized = target_identifier(target)
    print(f"\n[+] Ktool engagement init for {normalized}")
    evidence = evidence_init(normalized, base_dir=base_dir)
    scope = scope_manager("add", target=normalized, note=f"Engagement: {client}", path=scope_file)
    report_path = Path(str(evidence["root"])) / "reports" / "report.md"
    if report_path.exists():
        print(f"[i] Report already exists: {report_path}")
        report = {"path": str(report_path), "created": False}
    else:
        report = report_init(client, target=normalized, output=str(report_path))
        report["created"] = True
    return {"client": client, "target": normalized, "evidence": evidence, "scope": scope, "report": report}


def evidence_snapshot(command: list[str], output_dir: str, timeout: float) -> dict[str, object]:
    if not command:
        raise ValueError("evidence-snapshot requires a command after --, for example: ktool evidence-snapshot -- date")
    if command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("evidence-snapshot requires a command to run.")

    print(f"\n[+] Evidence snapshot: {' '.join(command)}")
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc).isoformat()
    result = run_external(command, timeout=timeout)
    completed_at = datetime.now(timezone.utc).isoformat()
    transcript = (
        f"$ {' '.join(command)}\n"
        f"started_at: {started_at}\n"
        f"completed_at: {completed_at}\n"
        f"returncode: {result.returncode}\n\n"
        "STDOUT\n"
        f"{result.stdout}\n"
        "STDERR\n"
        f"{result.stderr}\n"
    )
    digest = hashlib.sha256(transcript.encode("utf-8")).hexdigest()
    filename = f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{slugify(command[0])}.txt"
    path = out_dir / filename
    path.write_text(transcript, encoding="utf-8")
    hash_path = out_dir / f"{filename}.sha256"
    hash_path.write_text(f"{digest}  {filename}\n", encoding="utf-8")
    print(f"[+] Snapshot saved: {path}")
    print(f"[+] SHA256: {digest}")
    return {
        "command": command,
        "returncode": result.returncode,
        "path": str(path),
        "sha256_path": str(hash_path),
        "sha256": digest,
        "started_at": started_at,
        "completed_at": completed_at,
    }


def export_html_report(input_path: str, output_path: str) -> dict[str, object]:
    source = Path(input_path)
    if not source.exists():
        raise ValueError(f"Input report not found: {input_path}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
        body = html.escape(json.dumps(payload, indent=2))
    except json.JSONDecodeError:
        body = html.escape(source.read_text(encoding="utf-8"))

    title = f"Ktool Report - {source.name}"
    content = (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"  <title>{html.escape(title)}</title>\n"
        "  <style>body{font-family:Arial,sans-serif;margin:32px;line-height:1.5;background:#f7f7f8;color:#111}"
        "main{max-width:1100px;margin:auto;background:#fff;border:1px solid #ddd;padding:24px}"
        "pre{white-space:pre-wrap;background:#111;color:#e8ffe8;padding:16px;overflow:auto}"
        "h1{margin-top:0}</style>\n"
        "</head>\n"
        "<body><main>\n"
        f"<h1>{html.escape(title)}</h1>\n"
        f"<p>Generated: {html.escape(datetime.now(timezone.utc).isoformat())}</p>\n"
        f"<pre>{body}</pre>\n"
        "</main></body></html>\n"
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    print(f"[+] HTML report saved: {output}")
    return {"input": str(source), "output": str(output)}


def recon_workflow(domain: str, timeout: float, scope_path: str | None) -> dict[str, object]:
    domain = validate_host(domain).strip(".")
    scope = ensure_target_in_scope_or_warn(domain, scope_path)
    print(f"\n[+] Ktool recon workflow for {domain}")
    results: dict[str, object] = {"target": domain, "scope": scope}
    results["dns"] = resolve_dns(domain)
    try:
        results["whois"] = whois_lookup(domain, timeout=timeout)
    except (ValueError, TimeoutError, OSError) as error:
        print(f"[WARN] WHOIS skipped: {error}")
        results["whois"] = {"error": str(error)}
    results["subdomains"] = [asdict(item) for item in subdomain_finder(domain, DEFAULT_SUBDOMAINS)]
    results["email"] = email_domain_audit(domain, dkim_selector=None, timeout=timeout, use_checkdmarc=False)
    results["passive_assets"] = run_passive_assets(domain, tools=["subfinder", "assetfinder", "amass"], timeout=timeout)
    return results


def web_workflow(url: str, timeout: float, delay: float, scope_path: str | None) -> dict[str, object]:
    normalized = normalize_url(url)
    scope = ensure_target_in_scope_or_warn(normalized, scope_path)
    host = host_from_url_or_host(normalized)
    print(f"\n[+] Ktool web workflow for {normalized}")
    results: dict[str, object] = {"url": normalized, "scope": scope}
    results["baseline"] = web_baseline(normalized, timeout=timeout, delay=delay)
    results["fingerprint"] = run_fingerprint(normalized, tools=["whatweb", "wafw00f", "httpx"], timeout=timeout)
    results["tls"] = run_tls_audit(normalized, tools=["testssl.sh", "sslscan"], timeout=max(timeout, 60.0))
    results["js"] = run_javascript_audit(normalized, tools=[], timeout=max(timeout, 30.0), browser=False, output=None)
    results["vuln_search"] = web_vulnerability_search(
        normalized,
        timeout=timeout,
        delay=delay,
        use_searchsploit=True,
        use_nikto=False,
        nikto_timeout=timeout,
    )
    results["email"] = email_domain_audit(host, dkim_selector=None, timeout=timeout, use_checkdmarc=False)
    return results


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

        if key == "vehicle":
            print("  Safety boundary: do not search private owner data; verify records through official/legal channels.")
        elif key in {"passwords", "exploitation", "awareness", "post", "wireless", "privacy", "mobile"}:
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

    install_parser = subparsers.add_parser("install-tools", help="Install supported Linux packages for Ktool tools.")
    install_parser.add_argument(
        "--manager",
        choices=sorted(INSTALL_PACKAGES),
        default="apt",
        help="Package manager to use.",
    )
    install_parser.add_argument(
        "--category",
        choices=sorted(TOOL_CATEGORIES),
        help="Install package-manager tools from one Ktool category.",
    )
    install_parser.add_argument(
        "--tools",
        help="Comma-separated tool names. Overrides --category.",
    )
    install_parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually run the install command. Without this, Ktool prints a dry-run plan.",
    )
    install_parser.add_argument("--timeout", type=float, default=1800.0, help="Install timeout in seconds.")
    install_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    scope_parser = subparsers.add_parser("scope", help="Manage authorized assessment scope targets.")
    scope_parser.add_argument("action", choices=["add", "list", "check", "remove", "clear"], help="Scope action.")
    scope_parser.add_argument("--target", help="Target, wildcard, domain, IP, or URL.")
    scope_parser.add_argument("--note", help="Optional scope note.")
    scope_parser.add_argument("--scope-file", help="Scope JSON path. Defaults to .ktool/scope.json.")
    scope_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    evidence_parser = subparsers.add_parser("evidence-init", help="Create a pentest evidence workspace.")
    evidence_parser.add_argument("target", help="Target name/domain/IP for the workspace.")
    evidence_parser.add_argument("--base-dir", default="engagements", help="Base directory for engagement folders.")
    evidence_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    checklist_parser = subparsers.add_parser("checklist", help="Print a pentest checklist.")
    checklist_parser.add_argument("category", choices=sorted(CHECKLISTS), help="Checklist category.")
    checklist_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    plate_parser = subparsers.add_parser("myanmar-plate-check", help="Review a Myanmar vehicle plate format and verification checklist.")
    plate_parser.add_argument("plate", nargs="?", help="Plate text, for example 'YGN 1A-2345'.")
    plate_parser.add_argument("--region", help="Optional region/state code, for example YGN or MDY.")
    plate_parser.add_argument("--vehicle-type", help="Optional vehicle class note, for example car, motorcycle, taxi, or truck.")
    plate_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    vehicle_checklist_parser = subparsers.add_parser("myanmar-vehicle-checklist", help="Show safe Myanmar vehicle verification steps.")
    vehicle_checklist_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    finding_parser = subparsers.add_parser("finding-new", help="Create a finding JSON template.")
    finding_parser.add_argument("--title", required=True, help="Finding title.")
    finding_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default="medium")
    finding_parser.add_argument("--asset", required=True, help="Affected asset.")
    finding_parser.add_argument("--evidence", default="", help="Evidence summary or file reference.")
    finding_parser.add_argument("--impact", default="", help="Impact summary.")
    finding_parser.add_argument("--remediation", default="", help="Remediation guidance.")
    finding_parser.add_argument("--references", default="", help="Comma-separated references.")
    finding_parser.add_argument("--output-dir", default="findings", help="Directory for finding JSON files.")
    finding_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    report_init_parser = subparsers.add_parser("report-init", help="Create a Markdown pentest report template.")
    report_init_parser.add_argument("--client", required=True, help="Client or engagement name.")
    report_init_parser.add_argument("--target", required=True, help="Assessment target or scope summary.")
    report_init_parser.add_argument("--output", default="reports/ktool-report.md", help="Report path.")
    report_init_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    report_export_parser = subparsers.add_parser("report-export", help="Export finding JSON files to a Markdown report.")
    report_export_parser.add_argument("--client", required=True, help="Client or engagement name.")
    report_export_parser.add_argument("--target", required=True, help="Assessment target or scope summary.")
    report_export_parser.add_argument("--findings-dir", default="findings", help="Directory containing finding JSON files.")
    report_export_parser.add_argument("--output", default="reports/ktool-report.md", help="Output Markdown report path.")
    report_export_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    engagement_parser = subparsers.add_parser("engagement-init", help="Create scope, evidence folders, and a report template together.")
    engagement_parser.add_argument("--client", required=True, help="Client or engagement name.")
    engagement_parser.add_argument("--target", required=True, help="Assessment target.")
    engagement_parser.add_argument("--base-dir", default="engagements", help="Base directory for engagement folders.")
    engagement_parser.add_argument("--scope-file", help="Scope JSON path. Defaults to .ktool/scope.json.")
    engagement_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    snapshot_parser = subparsers.add_parser("evidence-snapshot", help="Run a local command and save timestamped output plus SHA256.")
    snapshot_parser.add_argument("--output-dir", default="evidence", help="Directory for snapshot files.")
    snapshot_parser.add_argument("--timeout", type=float, default=120.0, help="Command timeout in seconds.")
    snapshot_parser.add_argument("command_args", nargs=argparse.REMAINDER, help="Command after --, for example -- date")
    snapshot_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    html_report_parser = subparsers.add_parser("export-html-report", help="Convert a Ktool JSON/text report into a simple HTML report.")
    html_report_parser.add_argument("input", help="Input report path.")
    html_report_parser.add_argument("--output", default="reports/ktool-report.html", help="Output HTML path.")
    html_report_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    recon_workflow_parser = subparsers.add_parser("recon-workflow", help="Run a safe reconnaissance workflow.")
    add_common_run_options(recon_workflow_parser)
    recon_workflow_parser.add_argument("domain", help="Domain to assess.")
    recon_workflow_parser.add_argument("--timeout", type=float, default=30.0, help="Per-step timeout in seconds.")
    recon_workflow_parser.add_argument("--scope-file", help="Scope JSON path. Defaults to .ktool/scope.json.")

    web_workflow_parser = subparsers.add_parser("web-workflow", help="Run a safe web assessment workflow.")
    add_common_run_options(web_workflow_parser)
    web_workflow_parser.add_argument("url", help="Base URL to assess.")
    web_workflow_parser.add_argument("--timeout", type=float, default=15.0, help="Per-step timeout in seconds.")
    web_workflow_parser.add_argument("--delay", type=float, default=0.2, help="Delay between path requests.")
    web_workflow_parser.add_argument("--scope-file", help="Scope JSON path. Defaults to .ktool/scope.json.")

    dns_parser = subparsers.add_parser("dns", help="Resolve DNS information for a host.")
    add_common_run_options(dns_parser)
    dns_parser.add_argument("domain", help="Domain or hostname to resolve.")

    email_check_parser = subparsers.add_parser("email-check", help="Check email format and domain mail security posture.")
    add_common_run_options(email_check_parser)
    email_check_parser.add_argument("address", help="Email address to check.")
    email_check_parser.add_argument("--dkim-selector", help="Optional DKIM selector to query.")
    email_check_parser.add_argument("--checkdmarc", action="store_true", help="Run checkdmarc if installed.")
    email_check_parser.add_argument("--timeout", type=float, default=10.0, help="DNS/tool timeout in seconds.")

    email_domain_parser = subparsers.add_parser("email-domain", help="Check MX, SPF, DMARC, and optional DKIM records.")
    add_common_run_options(email_domain_parser)
    email_domain_parser.add_argument("domain", help="Email domain to check.")
    email_domain_parser.add_argument("--dkim-selector", help="Optional DKIM selector to query.")
    email_domain_parser.add_argument("--checkdmarc", action="store_true", help="Run checkdmarc if installed.")
    email_domain_parser.add_argument("--timeout", type=float, default=10.0, help="DNS/tool timeout in seconds.")

    smtp_parser = subparsers.add_parser("smtp-check", help="Check SMTP banner, EHLO capabilities, and STARTTLS support.")
    add_common_run_options(smtp_parser)
    smtp_parser.add_argument("target", help="SMTP server hostname or IP.")
    smtp_parser.add_argument("--port", type=int, default=25, choices=[25, 465, 587], help="SMTP port.")
    smtp_parser.add_argument("--starttls", action="store_true", help="Attempt STARTTLS if the server advertises it.")
    smtp_parser.add_argument("--timeout", type=float, default=10.0, help="Socket timeout in seconds.")

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

    ssl_cert_parser = subparsers.add_parser("ssl-cert-check", help="Check HTTPS certificate expiry, issuer, SANs, and TLS version.")
    add_common_run_options(ssl_cert_parser)
    ssl_cert_parser.add_argument("target", help="HTTPS URL or host.")
    ssl_cert_parser.add_argument("--port", type=int, default=443, help="TLS port.")
    ssl_cert_parser.add_argument("--timeout", type=float, default=8.0, help="Socket timeout in seconds.")

    methods_parser = subparsers.add_parser("http-methods", help="Check advertised HTTP methods with OPTIONS.")
    add_common_run_options(methods_parser)
    methods_parser.add_argument("url", help="URL to check.")
    methods_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds.")

    robots_parser = subparsers.add_parser("robots-check", help="Fetch robots.txt and security.txt.")
    add_common_run_options(robots_parser)
    robots_parser.add_argument("url", help="Base URL to check.")
    robots_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds.")

    backup_parser = subparsers.add_parser("backup-file-check", help="Check common accidental backup/config file exposure paths.")
    add_common_run_options(backup_parser)
    backup_parser.add_argument("url", help="Base URL to check.")
    backup_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds.")
    backup_parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests.")
    backup_parser.add_argument("--show-all", action="store_true", help="Print all statuses, including 404s.")

    redirect_parser = subparsers.add_parser("redirect-check", help="Follow and report HTTP redirect chains.")
    add_common_run_options(redirect_parser)
    redirect_parser.add_argument("url", help="URL to check.")
    redirect_parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds.")

    cookie_parser = subparsers.add_parser("cookie-audit", help="Check cookie Secure, HttpOnly, and SameSite flags.")
    add_common_run_options(cookie_parser)
    cookie_parser.add_argument("url", help="URL to check.")
    cookie_parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds.")

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

    js_parser = subparsers.add_parser("js-audit", help="Audit frontend JavaScript, source maps, and browser console errors.")
    add_common_run_options(js_parser)
    js_parser.add_argument("url", help="Target URL.")
    js_parser.add_argument(
        "--tools",
        default="",
        help="Comma-separated optional external tools: retire,trufflehog,semgrep,linkfinder,secretfinder,sourcemapper.",
    )
    js_parser.add_argument(
        "--browser",
        action="store_true",
        help="Use Playwright to record console errors, page errors, and failed requests.",
    )
    js_parser.add_argument(
        "--output",
        help="Optional directory to keep downloaded JavaScript files. Without this, Ktool uses a temporary directory.",
    )
    js_parser.add_argument("--timeout", type=float, default=120.0, help="Per-request or per-tool timeout in seconds.")

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

    wifi_check_parser = subparsers.add_parser("wifi-check", help="Run a read-only WiFi security posture check.")
    wifi_check_parser.add_argument("--interface", help="Optional wireless interface, for example wlan0.")
    wifi_check_parser.add_argument("--scan", action="store_true", help="Include a read-only visible network scan with nmcli.")
    wifi_check_parser.add_argument("--timeout", type=float, default=10.0, help="Command timeout in seconds.")
    wifi_check_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    wifi_scan_parser = subparsers.add_parser("wifi-scan", help="List visible WiFi networks and highlight weak encryption.")
    wifi_scan_parser.add_argument("--no-rescan", action="store_true", help="Use cached NetworkManager results.")
    wifi_scan_parser.add_argument("--timeout", type=float, default=15.0, help="Command timeout in seconds.")
    wifi_scan_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    wifi_users_parser = subparsers.add_parser("wifi-device-users", help="Show local WiFi/LAN device and hostname/user hints.")
    wifi_users_parser.add_argument("--interface", help="Optional wireless interface, for example wlan0.")
    wifi_users_parser.add_argument("--active", action="store_true", help="Run arp-scan local discovery if installed and authorized.")
    wifi_users_parser.add_argument("--resolve-names", action="store_true", help="Try reverse DNS for local device hostname hints.")
    wifi_users_parser.add_argument("--timeout", type=float, default=8.0, help="Command/request timeout in seconds.")
    wifi_users_parser.add_argument(
        "--yes-i-am-authorized",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Confirm you have permission for active local discovery.",
    )
    wifi_users_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    iphone_parser = subparsers.add_parser("iphone-check", help="Check iPhone WiFi reachability and optional device health signals.")
    iphone_parser.add_argument("--ip", help="iPhone IP address on your trusted LAN.")
    iphone_parser.add_argument("--name", help="Optional iPhone name to look for in Bonjour/mDNS output.")
    iphone_parser.add_argument("--count", type=int, default=4, help="Ping packet count.")
    iphone_parser.add_argument("--timeout", type=float, default=5.0, help="Per-command timeout in seconds.")
    iphone_parser.add_argument("--mdns", action="store_true", help="Search local Bonjour/mDNS records for Apple device services.")
    iphone_parser.add_argument("--usb", action="store_true", help="Also query trusted USB iPhone info with libimobiledevice.")
    iphone_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    iphone_usb_parser = subparsers.add_parser("iphone-usb-info", help="Show trusted USB iPhone device and battery info.")
    iphone_usb_parser.add_argument("--timeout", type=float, default=8.0, help="Command timeout in seconds.")
    iphone_usb_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    iphone_guide_parser = subparsers.add_parser("iphone-health-guide", help="Show iPhone WiFi and health checklist.")
    iphone_guide_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    privacy_parser = subparsers.add_parser("privacy-methods", help="Show lawful IP privacy methods and boundaries.")
    privacy_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    ip_privacy_parser = subparsers.add_parser("ip-privacy-check", help="Review local egress, proxy, VPN, and DNS privacy indicators.")
    ip_privacy_parser.add_argument("--public", action="store_true", help="Query the public egress IP endpoint.")
    ip_privacy_parser.add_argument("--endpoint", default="https://api.ipify.org", help="Public egress IP endpoint.")
    ip_privacy_parser.add_argument("--timeout", type=float, default=8.0, help="Command/request timeout in seconds.")
    ip_privacy_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    firewall_parser = subparsers.add_parser("firewall-check", help="Show local firewall status from ufw/nft/iptables.")
    firewall_parser.add_argument("--timeout", type=float, default=10.0, help="Command timeout in seconds.")
    firewall_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    service_parser = subparsers.add_parser("service-audit", help="List local listening services with ss/netstat.")
    service_parser.add_argument("--timeout", type=float, default=10.0, help="Command timeout in seconds.")
    service_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    update_parser = subparsers.add_parser("update-check", help="Show available package updates without installing them.")
    update_parser.add_argument("--timeout", type=float, default=60.0, help="Command timeout in seconds.")
    update_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    ssh_parser = subparsers.add_parser("ssh-audit-local", help="Review local SSH client/server config for risky options.")
    ssh_parser.add_argument("--timeout", type=float, default=10.0, help="Command timeout in seconds.")
    ssh_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    router_parser = subparsers.add_parser("router-checklist", help="Show router hardening checklist.")
    router_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    dns_leak_parser = subparsers.add_parser("dns-leak-check", help="Review DNS resolver configuration and optional public egress.")
    dns_leak_parser.add_argument("--public", action="store_true", help="Query the public egress IP endpoint.")
    dns_leak_parser.add_argument("--endpoint", default="https://api.ipify.org", help="Public egress IP endpoint.")
    dns_leak_parser.add_argument("--timeout", type=float, default=8.0, help="Command/request timeout in seconds.")
    dns_leak_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

    lan_parser = subparsers.add_parser("lan-device-list", help="Show local neighbor/ARP table without scanning.")
    lan_parser.add_argument("--timeout", type=float, default=8.0, help="Command timeout in seconds.")
    lan_parser.add_argument("--report", default=argparse.SUPPRESS, help="Write JSON report to this path.")

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


def interactive_more_checks() -> object:
    print("\n[+] Ktool more safety checks")
    items = [
        ("1", "SSL Certificate Check"),
        ("2", "HTTP Methods"),
        ("3", "Robots/Security.txt"),
        ("4", "Backup File Check"),
        ("5", "Redirect Check"),
        ("6", "Cookie Audit"),
        ("7", "Firewall Check"),
        ("8", "Service Audit"),
        ("9", "Package Update Check"),
        ("10", "Local SSH Audit"),
        ("11", "Router Checklist"),
        ("12", "DNS Leak Check"),
        ("13", "LAN Device List"),
        ("14", "WiFi Device/User Check"),
    ]
    for number, label in items:
        print(f" [{number.rjust(2)}] {label}")
    choice = input(color("ktool/more> ", "1;32")).strip()

    if choice == "1":
        target = input("HTTPS URL or host: ").strip()
        return ssl_cert_check(target, port=443, timeout=8.0)
    if choice == "2":
        url = input("URL: ").strip()
        return http_methods_check(url, timeout=5.0)
    if choice == "3":
        url = input("Base URL: ").strip()
        return robots_check(url, timeout=5.0)
    if choice == "4":
        url = input("Base URL: ").strip()
        return backup_file_check(url, timeout=5.0, delay=0.2, show_all=False)
    if choice == "5":
        url = input("URL: ").strip()
        return redirect_check(url, timeout=8.0)
    if choice == "6":
        url = input("URL: ").strip()
        return cookie_audit(url, timeout=5.0)
    if choice == "7":
        return firewall_check(timeout=10.0)
    if choice == "8":
        return service_audit(timeout=10.0)
    if choice == "9":
        return update_check(timeout=60.0)
    if choice == "10":
        return ssh_audit_local(timeout=10.0)
    if choice == "11":
        return router_checklist()
    if choice == "12":
        include_public = input("Query public egress IP? [y/N]: ").strip().lower() in {"y", "yes"}
        return dns_leak_check(include_public=include_public, endpoint="https://api.ipify.org", timeout=8.0)
    if choice == "13":
        return lan_device_list(timeout=8.0)
    if choice == "14":
        interface = input("Wireless interface [optional]: ").strip() or None
        active = input("Run active arp-scan discovery on your own network? [y/N]: ").strip().lower() in {"y", "yes"}
        resolve_names = input("Try reverse DNS hostname hints? [y/N]: ").strip().lower() in {"y", "yes"}
        return wifi_device_user_check(
            interface=interface,
            active=active,
            resolve_names=resolve_names,
            timeout=8.0,
            assume_authorized=False,
        )
    print("Invalid choice.")
    return None


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
                interface = input("Wireless interface [optional]: ").strip() or None
                include_scan = input("Include visible network scan? [y/N]: ").strip().lower() in {"y", "yes"}
                wifi_security_check(interface=interface, scan=include_scan, timeout=10.0)
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
                address_or_domain = input("Email address or domain: ").strip()
                selector = input("DKIM selector [optional]: ").strip() or None
                if "@" in address_or_domain:
                    email_address_check(address_or_domain, dkim_selector=selector, timeout=10.0, use_checkdmarc=False)
                else:
                    email_domain_audit(address_or_domain, dkim_selector=selector, timeout=10.0, use_checkdmarc=False)
            elif choice == "20":
                setoolkit_info()
            elif choice == "21":
                clear_screen()
                print_startup_banner()
            elif choice == "22":
                clear_screen()
                print_startup_banner()
                print(color("[restarted] Ktool console restarted.", "1;32"))
            elif choice == "23":
                interactive_external_runner()
            elif choice == "24":
                include_public = input("Query public egress IP? [y/N]: ").strip().lower() in {"y", "yes"}
                ip_privacy_check(include_public=include_public, endpoint="https://api.ipify.org", timeout=8.0)
            elif choice == "25":
                plate = input("Plate text: ").strip()
                region = input("Region code [optional]: ").strip() or None
                vehicle_type = input("Vehicle type [optional]: ").strip() or None
                myanmar_plate_check(plate=plate, region=region, vehicle_type=vehicle_type)
            elif choice == "26":
                interactive_more_checks()
            elif choice == "27":
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
        elif args.command == "install-tools":
            selected_tools = split_tool_list(args.tools, []) if args.tools else tools_from_category(args.category)
            results = install_tools(
                manager=args.manager,
                tools=selected_tools,
                execute=args.execute,
                timeout=args.timeout,
            )
        elif args.command == "scope":
            results = scope_manager(args.action, target=args.target, note=args.note, path=args.scope_file)
        elif args.command == "evidence-init":
            results = evidence_init(args.target, base_dir=args.base_dir)
        elif args.command == "checklist":
            results = checklist(args.category)
        elif args.command == "myanmar-plate-check":
            results = myanmar_plate_check(args.plate, region=args.region, vehicle_type=args.vehicle_type)
        elif args.command == "myanmar-vehicle-checklist":
            results = myanmar_vehicle_checklist()
        elif args.command == "finding-new":
            results = finding_new(
                title=args.title,
                severity=args.severity,
                asset=args.asset,
                evidence=args.evidence,
                impact=args.impact,
                remediation=args.remediation,
                references=args.references,
                output_dir=args.output_dir,
            )
        elif args.command == "report-init":
            results = report_init(args.client, target=args.target, output=args.output)
        elif args.command == "report-export":
            results = report_export(
                args.client,
                target=args.target,
                findings_dir=args.findings_dir,
                output=args.output,
            )
        elif args.command == "engagement-init":
            results = engagement_init(args.client, target=args.target, base_dir=args.base_dir, scope_file=args.scope_file)
        elif args.command == "evidence-snapshot":
            results = evidence_snapshot(args.command_args, output_dir=args.output_dir, timeout=args.timeout)
        elif args.command == "export-html-report":
            results = export_html_report(args.input, output_path=args.output)
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
        elif args.command == "wifi-check":
            results = wifi_security_check(interface=args.interface, scan=args.scan, timeout=args.timeout)
        elif args.command == "wifi-scan":
            results = wifi_scan(rescan=not args.no_rescan, timeout=args.timeout)
        elif args.command == "wifi-device-users":
            results = wifi_device_user_check(
                interface=args.interface,
                active=args.active,
                resolve_names=args.resolve_names,
                timeout=args.timeout,
                assume_authorized=getattr(args, "yes_i_am_authorized", False),
            )
        elif args.command == "iphone-check":
            results = iphone_wifi_check(
                ip_address=args.ip,
                name=args.name,
                count=args.count,
                timeout=args.timeout,
                mdns=args.mdns,
                usb=args.usb,
            )
        elif args.command == "iphone-usb-info":
            results = iphone_usb_info(timeout=args.timeout)
        elif args.command == "iphone-health-guide":
            results = iphone_health_guide()
        elif args.command == "privacy-methods":
            results = privacy_methods()
        elif args.command == "ip-privacy-check":
            results = ip_privacy_check(include_public=args.public, endpoint=args.endpoint, timeout=args.timeout)
        elif args.command == "firewall-check":
            results = firewall_check(timeout=args.timeout)
        elif args.command == "service-audit":
            results = service_audit(timeout=args.timeout)
        elif args.command == "update-check":
            results = update_check(timeout=args.timeout)
        elif args.command == "ssh-audit-local":
            results = ssh_audit_local(timeout=args.timeout)
        elif args.command == "router-checklist":
            results = router_checklist()
        elif args.command == "dns-leak-check":
            results = dns_leak_check(include_public=args.public, endpoint=args.endpoint, timeout=args.timeout)
        elif args.command == "lan-device-list":
            results = lan_device_list(timeout=args.timeout)
        elif args.command == "external-examples":
            results = print_external_tool_examples()
        else:
            require_authorization(args.yes_i_am_authorized)

        if args.command == "dns":
            results = resolve_dns(args.domain)
        elif args.command == "recon-workflow":
            results = recon_workflow(args.domain, timeout=args.timeout, scope_path=args.scope_file)
        elif args.command == "web-workflow":
            results = web_workflow(args.url, timeout=args.timeout, delay=args.delay, scope_path=args.scope_file)
        elif args.command == "email-check":
            results = email_address_check(
                args.address,
                dkim_selector=args.dkim_selector,
                timeout=args.timeout,
                use_checkdmarc=args.checkdmarc,
            )
        elif args.command == "email-domain":
            results = email_domain_audit(
                args.domain,
                dkim_selector=args.dkim_selector,
                timeout=args.timeout,
                use_checkdmarc=args.checkdmarc,
            )
        elif args.command == "smtp-check":
            results = smtp_check(args.target, port=args.port, timeout=args.timeout, starttls=args.starttls)
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
        elif args.command == "ssl-cert-check":
            results = ssl_cert_check(args.target, port=args.port, timeout=args.timeout)
        elif args.command == "http-methods":
            results = http_methods_check(args.url, timeout=args.timeout)
        elif args.command == "robots-check":
            results = robots_check(args.url, timeout=args.timeout)
        elif args.command == "backup-file-check":
            results = backup_file_check(args.url, timeout=args.timeout, delay=args.delay, show_all=args.show_all)
        elif args.command == "redirect-check":
            results = redirect_check(args.url, timeout=args.timeout)
        elif args.command == "cookie-audit":
            results = cookie_audit(args.url, timeout=args.timeout)
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
        elif args.command == "js-audit":
            results = run_javascript_audit(
                args.url,
                tools=split_tool_list(args.tools, []),
                timeout=args.timeout,
                browser=args.browser,
                output=args.output,
            )
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
            "install-tools",
            "scope",
            "evidence-init",
            "checklist",
            "myanmar-plate-check",
            "myanmar-vehicle-checklist",
            "finding-new",
            "report-init",
            "report-export",
            "engagement-init",
            "evidence-snapshot",
            "export-html-report",
            "password-audit",
            "awareness-plan",
            "setoolkit-info",
            "local-posture",
            "linux-audit",
            "wifi-check",
            "wifi-scan",
            "wifi-device-users",
            "iphone-check",
            "iphone-usb-info",
            "iphone-health-guide",
            "privacy-methods",
            "ip-privacy-check",
            "firewall-check",
            "service-audit",
            "update-check",
            "ssh-audit-local",
            "router-checklist",
            "dns-leak-check",
            "lan-device-list",
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
