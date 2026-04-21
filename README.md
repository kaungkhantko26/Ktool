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
ktool ports 127.0.0.1 --ports 22,80,443 --yes-i-am-authorized
ktool setoolkit-info
```

External tool wrappers:

```bash
ktool external-examples
ktool fingerprint https://example.com --tools whatweb,wafw00f,httpx --yes-i-am-authorized
ktool tls-audit https://example.com --tools testssl.sh,sslscan --yes-i-am-authorized
ktool dns-enum example.com --tools dnsrecon,subfinder,amass --yes-i-am-authorized
ktool url-discovery https://example.com --tools waybackurls,gau,katana --yes-i-am-authorized
ktool web-scan https://example.com --tool nuclei --rate 20 --yes-i-am-authorized
```

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

Optional auto-deploy before launch:

```bash
KTOOL_AUTO_DEPLOY=1 ktool
```

Auto-deploy is off by default so normal Ktool runs do not create commits unexpectedly.
