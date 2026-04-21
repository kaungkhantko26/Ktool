# Ktool

Ktool is a Linux-friendly ethical security assessment tool for authorized testing.

## Quick Start

```bash
chmod +x tool.py
./tool.py
```

Run command help:

```bash
./tool.py --help
```

Example authorized checks:

```bash
./tool.py dns example.com --yes-i-am-authorized
./tool.py web-vuln-search https://example.com --yes-i-am-authorized
./tool.py ports 127.0.0.1 --ports 22,80,443 --yes-i-am-authorized
```

Use Ktool only on systems you own, lab environments, or targets where you have explicit written permission.
