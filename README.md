# Ktool

Ktool 2.1.1 is a Linux-friendly ethical security assessment tool for authorized testing.

## Quick Start

```bash
chmod +x tool.py ktool deploy.sh update-ktool.sh install-commands.sh
ktool
```

Install the commands so you can type `ktool` and `update-ktool.sh` from anywhere:

```bash
./install-commands.sh
```

If your shell cannot find `ktool` after installing, add this to `~/.bashrc` or `~/.zshrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Run command help:

```bash
ktool --help
ktool version
ktool doctor
```

Enable automatic GitHub deploys after normal `ktool` runs:

```bash
./ktool-auto-deploy.sh install
```

This runs from your Terminal session, so it works even when macOS blocks background agents from accessing a repo under `Desktop`. For background scheduling on macOS, use:

```bash
./ktool-auto-deploy.sh schedule
./ktool-auto-deploy.sh schedule 120
```

Manage it:

```bash
./ktool-auto-deploy.sh status
./ktool-auto-deploy.sh unschedule
./ktool-auto-deploy.sh uninstall
```

Example authorized checks:

```bash
ktool dns example.com --yes-i-am-authorized
ktool web-vuln-search https://example.com --yes-i-am-authorized
ktool web-vuln-search https://example.com --yes-i-am-authorized --nikto --nikto-timeout 900
ktool ssl-cert-check https://example.com --yes-i-am-authorized
ktool http-methods https://example.com --yes-i-am-authorized
ktool robots-check https://example.com --yes-i-am-authorized
ktool backup-file-check https://example.com --yes-i-am-authorized
ktool redirect-check http://example.com --yes-i-am-authorized
ktool cookie-audit https://example.com --yes-i-am-authorized
ktool link-check "https://example.com/login?token=test"
ktool link-check "https://bit.ly/example" --fetch
ktool ports 127.0.0.1 --ports 22,80,443 --yes-i-am-authorized
ktool lan-scan 192.168.1.0/24 --yes-i-am-authorized
ktool lan-scan 192.168.1.0/24 --resolve-names --install-missing --yes-i-am-authorized
ktool scapy-sniff --interface en0 --duration 20 --count 100 --filter "tcp port 443" --install-missing --yes-i-am-authorized
ktool scapy-sniff --interface en0 --traffic dns --duration 20 --count 100 --yes-i-am-authorized
ktool scapy-sniff --interface en0 --traffic http-dns --suspicious-only --yes-i-am-authorized
ktool sudo-su --dry-run -- scapy-sniff --interface en0 --duration 20 --count 100 --yes-i-am-authorized
ktool sudo-su -- capture en0 --duration 20 --count 100 --output capture.pcap --yes-i-am-authorized
ktool capture en0 --duration 20 --count 100 --output capture.pcap --install-missing --yes-i-am-authorized
ktool ncat-chat listen --port 4444 --install-missing --yes-i-am-authorized
ktool ncat-chat send --host 192.168.1.50 --port 4444 --message "hello from ktool" --yes-i-am-authorized
ktool password-check
ktool password-generate --length 24 --count 5 --no-ambiguous
ktool admin-password --username admin --length 28 --output secrets/admin-password.env
ktool conn-watch --show-all
ktool conn-watch --iterations 5 --interval 3
ktool log-watch /var/log/auth.log --alerts-only
ktool ioc-triage 8.8.8.8 https://secure-login-account.top d41d8cd98f00b204e9800998ecf8427e
ktool live-workflow example.com --url https://example.com --ports common --yes-i-am-authorized
ktool defang https://secure-login-account.top admin@example.com
ktool defang --refang hxxps://secure-login-account[.]top
ktool threat-site-triage https://secure-login-account.top --fetch-body --output-markdown reports/threat-site.md --yes-i-am-authorized
ktool shodan 8.8.8.8 --yes-i-am-authorized
ktool shodan example.com --minify --yes-i-am-authorized
ktool cve-lookup CVE-2024-3094
ktool cve-lookup "nginx 1.18" --severity HIGH --limit 5
ktool virustotal 8.8.8.8
ktool vt d41d8cd98f00b204e9800998ecf8427e
ktool mobile-artifact-audit ./sample.apk --report reports/mobile-audit.json
ktool apk-audit ./decompiled-apk --all-iocs
ktool hatch --dry-run -- --version
ktool hatch --install-missing -- --version
ktool hatch -- env show
ktool permission-guide
ktool permission-guide scapy-sniff
ktool email-check admin@example.com --yes-i-am-authorized
ktool email-domain example.com --dkim-selector default --yes-i-am-authorized
ktool smtp-check mail.example.com --port 587 --starttls --yes-i-am-authorized
ktool wifi-check
ktool wifi-check --interface wlan0 --scan
ktool wifi-scan
ktool wifi-device-users
ktool wifi-device-users --resolve-names
ktool wifi-device-users --active --yes-i-am-authorized
ktool router-checklist
ktool dns-leak-check
ktool lan-device-list
ktool firewall-check
ktool service-audit
ktool update-check
ktool ssh-audit-local
ktool iphone-health-guide
ktool iphone-check --ip 192.168.1.23 --mdns
ktool iphone-check --usb
ktool iphone-usb-info
ktool privacy-methods
ktool ip-privacy-check
ktool ip-privacy-check --public
ktool myanmar-plate-check "YGN 1A-2345"
ktool myanmar-vehicle-checklist
ktool setoolkit-info
```

Pentester workflow:

```bash
ktool scope add --target example.com --note "authorized target"
ktool scope check --target https://example.com
ktool engagement-init --client "Client Name" --target example.com
ktool evidence-init example.com
ktool evidence-snapshot --output-dir engagements/example.com/evidence -- date
ktool checklist web
ktool finding-new --title "Missing DMARC" --severity medium --asset example.com --evidence "No DMARC record" --impact "Email spoofing risk" --remediation "Publish DMARC and move toward enforcement"
ktool report-init --client "Client Name" --target example.com --output engagements/example.com/reports/report.md
ktool report-export --client "Client Name" --target example.com --findings-dir findings --output reports/ktool-report.md
ktool export-html-report reports/ktool-report.json --output reports/ktool-report.html
ktool recon-workflow example.com --yes-i-am-authorized
ktool web-workflow https://example.com --yes-i-am-authorized
```

External tool wrappers:

```bash
ktool external-examples
ktool install-hints hatch
ktool install-tool ncat
ktool install-tool ncat --execute
ktool install-tools --category web --manager apt
ktool install-tools --category web --manager apt --execute
ktool fingerprint https://example.com --tools whatweb,wafw00f,httpx --yes-i-am-authorized
ktool tls-audit https://example.com --tools testssl.sh,sslscan --yes-i-am-authorized
ktool dns-enum example.com --tools dnsrecon,subfinder,amass --yes-i-am-authorized
ktool url-discovery https://example.com --tools waybackurls,gau,katana --yes-i-am-authorized
ktool web-scan https://example.com --tool nuclei --rate 20 --yes-i-am-authorized
ktool js-audit https://example.com --browser --yes-i-am-authorized
ktool js-audit https://example.com --tools retire,semgrep,trufflehog --output js-downloads --yes-i-am-authorized
```

The external wrappers run the real Linux tools when they are installed. Use `install-tools` for package-manager tools and `install-hints` for tools that need Go, Python, npm, GitHub releases, or manual setup.
For the single-file CLI commands in `tool.py`, `--install-missing` can install supported dependencies such as `nmap`, `ncat`, `tcpdump`, `whois`, or Python `scapy` with the detected package manager.
Ktool does not bypass operating-system permissions. If packet capture or raw socket tools return `Operation not permitted`, use `ktool permission-guide` for approved fixes such as sudo, Linux capabilities, or macOS packet-capture setup.
Use `ktool sudo-su -- <command args>` to relaunch one Ktool command through the operating system's approved sudo policy, or `ktool sudo-su` to open the interactive menu as root.
Password commands use Python `secrets`; sensitive reports and admin password output files are written with mode `0600`.
API-backed intelligence commands use environment variables by default: `SHODAN_API_KEY`, `NVD_API_KEY`, and `VIRUSTOTAL_API_KEY`. You can also pass `--api-key` per command.

Use Ktool only on systems you own, lab environments, or targets where you have explicit written permission.

## Deploy Updates

Push local Ktool changes to GitHub:

```bash
./deploy.sh
```

Use a custom commit message:

```bash
./deploy.sh "Update Ktool features"
```

Pull the latest Ktool from GitHub:

```bash
update-ktool.sh
```

If you copied the launcher scripts instead of installing symlinks, set the repo path:

```bash
export KTOOL_HOME="$HOME/Ktool"
```

By default, starting `ktool` does not run Git commands. Use `update-ktool.sh` when you want to pull updates, and `./deploy.sh` only when you want to commit and push local changes.
If auto-deploy is enabled, `ktool-auto-deploy.sh` runs `./deploy.sh` after normal `ktool` runs. Background scheduling is optional.
