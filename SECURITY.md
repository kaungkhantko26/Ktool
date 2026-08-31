# Security Policy

## Scope and intended use

KTOOL FieldOps is a defensive / authorized-testing console. It is meant for:

- systems you own,
- lab environments you control (TryHackMe, Hack The Box, local VMs),
- engagements with **explicit written authorization and scope**.

It deliberately does **not** include exploitation, authentication bypass,
phishing, credential brute force, persistence, or detection-evasion features.
Please do not open feature requests for those.

## Reporting a vulnerability

If you find a security issue **in this tool itself** (for example a command
injection, path traversal, or a way to make a wrapped tool act outside its
intended scope):

1. Do **not** open a public issue.
2. Use GitHub's **Report a vulnerability** button on the Security tab, or
   email the maintainer listed on the GitHub profile.
3. Include a minimal reproduction and the affected command.

You can expect an acknowledgement within about 7 days.

## Hardening built into the tool

- All external tools are invoked with argument lists (`subprocess.run([...])`).
  There is no `shell=True` and no `os.system` anywhere in the codebase.
- `validate_host()` rejects whitespace, control/NUL bytes, CRLF, leading `-`
  (argument injection) and anything that is not a valid hostname or IP literal.
- `normalize_url()` enforces `http`/`https` only and rejects embedded
  credentials and control characters.
- Generated secrets and sensitive reports are written with mode `0600`.
- Active checks require the explicit `--yes-i-am-authorized` flag.

## Automated checks

Every push and pull request runs, via `.github/workflows/ci.yml`:

- `ruff` lint (includes the `flake8-bandit` `S` ruleset),
- `bandit` static security analysis,
- `pytest` unit tests, including input-validation abuse cases,
- a CLI smoke test on Python 3.10 / 3.12 / 3.13.
