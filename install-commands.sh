#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR="${HOME}/.local/bin"

mkdir -p "$BIN_DIR"
chmod +x "$SCRIPT_DIR/tool.py" "$SCRIPT_DIR/ktool" "$SCRIPT_DIR/update-ktool.sh" "$SCRIPT_DIR/deploy.sh"

ln -sf "$SCRIPT_DIR/ktool" "$BIN_DIR/ktool"
ln -sf "$SCRIPT_DIR/update-ktool.sh" "$BIN_DIR/update-ktool.sh"

echo "[+] Installed Ktool commands:"
echo "    $BIN_DIR/ktool"
echo "    $BIN_DIR/update-ktool.sh"
echo
echo "If your shell cannot find them, add this to ~/.bashrc or ~/.zshrc:"
echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
