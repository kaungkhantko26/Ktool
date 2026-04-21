# Ktool

Ktool is a Linux-friendly ethical security assessment tool for authorized testing.

## Quick Start

```bash
chmod +x tool.py Ktool
./tool.py
```

Or start the console with the local launcher:

```bash
./Ktool
```

Run command help:

```bash
./tool.py --help
```

Example authorized checks:

```bash
./tool.py dns example.com --yes-i-am-authorized
./tool.py web-vuln-search https://example.com --yes-i-am-authorized
./tool.py web-vuln-search https://example.com --yes-i-am-authorized --nikto --nikto-timeout 900
./tool.py ports 127.0.0.1 --ports 22,80,443 --yes-i-am-authorized
./tool.py setoolkit-info
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

Optional auto-deploy before launch:

```bash
KTOOL_AUTO_DEPLOY=1 ./Ktool
```

Auto-deploy is off by default so normal Ktool runs do not create commits unexpectedly.
