# CTF Guide

`ktool ctf` bundles four helpers for capture-the-flag and lab work. All of it is
enumeration, organization, and note-taking — there is no exploitation or brute
force. Use it only on boxes tied to a platform account you own (TryHackMe,
Hack The Box, picoCTF, ...) or a range you were explicitly given.

## `ktool ctf box <target>` — guided box workflow

```bash
ktool ctf box 10.10.11.42 --yes-i-am-authorized
ktool ctf box target.thm --ports 1-10000 --yes-i-am-authorized
```

What it does:

1. Creates a workspace at `engagements/ctf-<target>/`.
2. Resolves DNS, scans TCP ports, and runs a safe web baseline on any HTTP(S)
   port it finds.
3. Sweeps the web root for flag strings (skip with `--no-flag-hunt`).
4. Writes `notes/ctf-playbook.md` — a **per-service checklist** of the next
   enumeration moves (e.g. port 445 → `smbclient -L`, port 6379 → `redis-cli`),
   plus normalized findings and a Markdown report.

The playbook is a study aid: it tells you *what to try next and why*, it does
not run those steps for you.

## `ktool ctf flag` — flag hunter

```bash
ktool ctf flag --path ./loot                 # recurse a directory
ktool ctf flag suspicious.bin                 # single file
cat response.html | ktool ctf flag --stdin    # from a pipe
ktool ctf flag --url http://10.10.11.42/ --yes-i-am-authorized
ktool ctf flag --path . --broad --pattern 'KEY_[0-9a-f]{16}'
```

Default formats: `flag{...}`, `HTB{...}`, `THM{...}`, `picoCTF{...}`.
`--broad` also matches any `word{...}` token. `--pattern` adds your own regex
(repeatable). Binaries are scanned too.

## `ktool ctf triage <file-or-dir>` — challenge triage (offline)

```bash
ktool ctf triage ./downloads/chal
ktool ctf triage mystery_file
```

For each file it reports size, Shannon entropy, magic-byte type, data embedded
after the header, interesting strings (URLs, base64 blobs, key headers), a
category guess (stego / rev / pwn / crypto / archive), and the tools to reach
for (`binwalk`, `steghide`, `ghidra`, `openssl`, ...).

## `ktool ctf fetch --url <ctfd>` — pull a challenge list

```bash
export CTFD_TOKEN=ctfd_xxx
ktool ctf fetch --url https://ctf.example.com --details
```

Reads the CTFd API (`/api/v1/challenges`) and writes `notes/challenges.md`
grouped by category with points and solve state. It only organizes — it does
not submit or solve anything. The token is read from `--token` or `CTFD_TOKEN`
and is never written to disk.
