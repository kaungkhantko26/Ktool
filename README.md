# KTOOL FieldOps

KTOOL FieldOps is a terminal-first security operations console for authorized work: labs, owned systems, and written-scope security testing. It focuses on recon, web hygiene, defensive triage, workflow readiness, reporting, and operator productivity without crossing into brute force, phishing, persistence, or exploit automation.

## Principles

- Use it only on assets you own, labs you control, or targets with explicit written scope.
- Treat it as an operator workflow tool, not a magic scanner.
- Save evidence, notes, and reports as you work.

## Install

Make the launchers executable:

```bash
chmod +x tool.py ktool deploy.sh update-ktool.sh install-commands.sh
```

Install the launcher symlinks:

```bash
./install-commands.sh
```

If your shell still cannot find `ktool`, add:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## First Run

Check the CLI surface:

```bash
ktool --help
ktool --version
```

Check operator readiness:

```bash
ktool doctor
ktool doctor --category web
ktool workflow-ready
```

`doctor` verifies:

- package-manager detection
- Python package state
- API key presence for `SHODAN_API_KEY`, `NVD_API_KEY`, and `VIRUSTOTAL_API_KEY`
- SecLists availability
- installed external tools by category

## Interactive Menu

Launch the interactive console:

```bash
ktool
```

Useful shortcuts inside the menu:

- `?` or `help`: show shortcut guidance
- `q`, `quit`, or `exit`: leave the console
- `1`: run `doctor`
- `39`: run `workflow-ready`
- `47`: run the `target-brief` workflow
- `48`: run the `recon-workflow`
- `49`: run the `web-workflow`
- `50`: build a workspace-level aggregated report

## Core Workflows

### 1. Target Brief

Use this for a practical first pass on an authorized target. It creates a workspace, runs DNS and port checks, optionally runs WHOIS and web checks, and writes structured output.

```bash
ktool target-brief example.com --yes-i-am-authorized
ktool brief 10.10.10.10 --skip-web --yes-i-am-authorized
```

The workflow writes:

- workspace folders under `engagements/<name>` by default
- JSON results under `scans/` and `reports/`
- a Markdown summary under `notes/target-brief.md`

### 2. Workflow Readiness

Use this before relying on wrappers or external tools in a real engagement:

```bash
ktool workflow-ready
ktool ready --workflow web-workflow --workflow vps-check
```

### 3. Lab Workspace

Create a repeatable workspace before deeper testing:

```bash
ktool lab-init acme-external --client "ACME" --target example.com
```

### 4. TryHackMe Workflow

Use the built-in room workflow for first-pass lab setup and safe enumeration:

```bash
ktool thm --room steel-mountain --target 10.10.10.10 --yes-i-am-authorized
ktool tryhackme --room steel-mountain --target 10.10.10.10 --content-scan --yes-i-am-authorized
```

### 5. Recon Workflow

Use this when you want a real first-pass host workflow with saved artifacts and a client-ready report:

```bash
ktool recon-workflow example.com --yes-i-am-authorized
```

### 6. Web Workflow

Use this when a web app is in scope and you want baseline, findings, and reporting in one run:

```bash
ktool web-workflow https://example.com --fingerprint --tls-audit --js-audit --yes-i-am-authorized
```

## Common Commands

### Recoon Tool Index

Use `recoon` when you want a quick table of practical recon commands grouped by kind. CVE research is separated from DNS, web, network, workflow, and passive intel commands.

```bash
ktool recoon
ktool recoon --kind cve
ktool recoon --kind web --commands-only
```

### Recon

```bash
ktool dns example.com --yes-i-am-authorized
ktool whois example.com --yes-i-am-authorized
ktool osint example.com
ktool ip-intel 8.8.8.8
ktool ports example.com --ports common --yes-i-am-authorized
ktool subs example.com --yes-i-am-authorized
ktool nmap example.com --top-ports 1000 --yes-i-am-authorized
```

### Web

```bash
ktool headers https://example.com --yes-i-am-authorized
ktool dirs https://example.com --yes-i-am-authorized
ktool web https://example.com --yes-i-am-authorized
ktool web-vuln-search https://example.com --yes-i-am-authorized
ktool content-discovery https://example.com --tool gobuster --wordlist-kind directory-small --yes-i-am-authorized
```

### Threat / Defensive Triage

```bash
ktool ioc-triage 8.8.8.8 https://secure-login-account.top d41d8cd98f00b204e9800998ecf8427e
ktool defang https://secure-login-account.top admin@example.com
ktool threat-site-triage https://secure-login-account.top --fetch-body --output-markdown reports/threat-site.md --yes-i-am-authorized
ktool vt 8.8.8.8
ktool cve-lookup CVE-2024-3094
```

### Passive Intel

Use these for low-risk enrichment of public infrastructure metadata:

```bash
ktool osint example.com --shodan --virustotal
ktool osint https://portal.example.com --no-crtsh
ktool ip-intel 1.1.1.1 --shodan
ktool osint example.com --output-dir engagements/osint-example
ktool ip-intel 8.8.8.8 --output-dir engagements/ip-intel-google
```

### Local / Network

```bash
ktool lan-scan 192.168.1.0/24 --yes-i-am-authorized
ktool capture en0 --duration 20 --count 100 --output capture.pcap --yes-i-am-authorized
ktool scapy-sniff --interface en0 --traffic dns --duration 20 --count 100 --yes-i-am-authorized
ktool conn-watch --iterations 5 --interval 3
ktool log-watch /var/log/auth.log --alerts-only
```

### Local Triage Workspaces

`conn-watch`, `log-watch`, and `mobile-artifact-audit` now write a workspace, normalized findings, and a client-ready Markdown report:

```bash
ktool conn-watch --iterations 3 --output-dir engagements/conn-review
ktool log-watch /var/log/auth.log --alerts-only --output-dir engagements/authlog-review
ktool mobile-artifact-audit ./sample-apk-src --output-dir engagements/mobile-review
```

### VPS Operations

```bash
ktool vps-check
ktool vps-check --only storage --only usage
ktool vps-logs --host root@203.0.113.10 --dry-run
```

### Local Posture

`local-posture` now writes a workspace, normalized findings, and a client-ready report:

```bash
ktool local-posture
ktool local-posture --output-dir engagements/local-posture-review
```

### VPS Reporting

`vps-check` and the focused VPS subcommands now write a workspace, normalized findings, and a client-ready report:

```bash
ktool vps-check --host root@203.0.113.10
ktool vps-check --host root@203.0.113.10 --output-dir engagements/vps-review
```

### Utilities

```bash
ktool password-check
ktool password-generate --length 24 --count 5 --no-ambiguous
ktool admin-password --username admin --length 28 --output secrets/admin-password.env
ktool hatch -- --version
ktool permission-guide
```

## Reports

Most commands support `--report`:

```bash
ktool web https://example.com --yes-i-am-authorized --report reports/web.json
```

Report behavior:

- JSON output is normalized for nested objects and dataclasses
- parent directories are created automatically
- sensitive outputs such as generated passwords are written with mode `0600`
- `target-brief`, `recon-workflow`, and `web-workflow` also write normalized findings under `findings/`
- workflow runs also generate client-ready Markdown reports under `reports/`
- `local-posture`, `vps-check`, `conn-watch`, `log-watch`, and `mobile-artifact-audit` now follow the same workspace/reporting pattern
- `osint`, `ip-intel`, `content-discovery`, `threat-site-triage`, `js-audit`, and the wrapper commands can also save workspace artifacts with `--output-dir`

Aggregate one workspace into a single rolled-up report:

```bash
ktool report engagements/mobile-review
ktool report engagements/acme-external --title "ACME External Assessment Report"
```

## External Tool Wrappers

KTOOL can drive installed external tools such as:

- `gobuster`
- `ffuf`
- `dirb`
- `whatweb`
- `wafw00f`
- `nikto`
- `dnsrecon`
- `amass`
- `sslscan`
- `testssl.sh`

Find supporting wordlists and wrappers:

```bash
ktool seclists-find
ktool install-hints seclists
ktool install-tools --category web --manager apt
```

## Permissions

KTOOL does not bypass operating-system restrictions. If raw sockets or packet capture fail with permission errors, use:

```bash
ktool permission-guide
ktool sudo-su -- capture en0 --duration 20 --count 100 --output capture.pcap --yes-i-am-authorized
```

## Deploying Updates

Commit and push local changes:

```bash
./deploy.sh
./deploy.sh "Update operator workflows"
```

Pull the latest version:

```bash
update-ktool.sh
```

Optional auto-deploy helper:

```bash
./ktool-auto-deploy.sh install
./ktool-auto-deploy.sh status
./ktool-auto-deploy.sh unschedule
./ktool-auto-deploy.sh uninstall
```
