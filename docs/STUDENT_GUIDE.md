# Student Guide

A path through KTOOL FieldOps if you are learning security. Everything here is
safe to run against **lab machines you control** or targets with written scope.

## 0. Learn the concept first

```bash
ktool learn                 # list all topics
ktool learn authorization   # scope, permission, ethics
ktool learn recon
ktool learn web
ktool learn vulns
ktool learn defense
ktool learn reporting
```

Each topic prints what the concept is, the mistakes to avoid, the KTOOL
commands that apply, and where to read more (OWASP WSTG, PTES, MITRE ATT&CK).

## 1. Check your toolbox

```bash
ktool doctor
ktool workflow-ready
```

## 2. Set up a workspace

```bash
ktool lab-init hackthebox-lame --target 10.10.10.3
```

Everything you run then has a home: `engagements/hackthebox-lame/` with
`scans/`, `findings/`, `notes/`, and `reports/`.

## 3. Passive first

```bash
ktool osint example.com
ktool dns example.com
ktool ip-intel 8.8.8.8
```

No packets touch the target. Good habit: always know what is public before you
send a single probe.

## 4. Light active recon (authorization required)

```bash
ktool ports 10.10.10.3 --ports common --yes-i-am-authorized
ktool nmap 10.10.10.3 --top-ports 1000 --yes-i-am-authorized
ktool recon-workflow 10.10.10.3 --yes-i-am-authorized
```

## 5. Web baseline

```bash
ktool headers https://target.lab --yes-i-am-authorized
ktool web https://target.lab --yes-i-am-authorized
ktool web-workflow https://target.lab --tls-audit --fingerprint --yes-i-am-authorized
```

## 6. Turn versions into vulnerabilities

```bash
ktool cve-lookup CVE-2024-3094
ktool vuln-lookup "vsftpd 2.3.4"
```

Always confirm the exact product/version before you trust a match.

## 7. Blue-team side

```bash
ktool ioc-triage 8.8.8.8 http://secure-login-account.top d41d8cd98f00b204e9800998ecf8427e
ktool defang http://secure-login-account.top
ktool log-watch /var/log/auth.log --alerts-only
ktool local-posture
```

## 8. Write it up

```bash
ktool report engagements/hackthebox-lame --title "Lame - Practice Report"
```

A finding needs: **what**, **where**, **impact**, **evidence**, **fix**.

## Rules you do not break

1. Only touch assets you own or have written permission to test.
2. `--yes-i-am-authorized` is you promising that is true. It is not permission.
3. Save evidence as you go.
4. If you find signs of a real prior compromise, stop and escalate.
