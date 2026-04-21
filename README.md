# Ktool

Ktool is a Linux-friendly ethical security assessment tool for authorized testing.

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
ktool ports 127.0.0.1 --ports 22,80,443 --yes-i-am-authorized
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

Starting `ktool` does not run Git commands. Use `update-ktool.sh` when you want to pull updates, and `./deploy.sh` only when you want to commit and push local changes.
