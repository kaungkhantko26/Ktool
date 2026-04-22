#!/usr/bin/env sh
set -eu

if [ -n "${KTOOL_HOME:-}" ]; then
  SCRIPT_DIR=$(CDPATH= cd -- "$KTOOL_HOME" && pwd)
else
  SOURCE=$0
  while [ -h "$SOURCE" ]; do
    DIR=$(CDPATH= cd -- "$(dirname -- "$SOURCE")" && pwd)
    LINK=$(readlink "$SOURCE")
    case "$LINK" in
      /*) SOURCE=$LINK ;;
      *) SOURCE=$DIR/$LINK ;;
    esac
  done
  SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$SOURCE")" && pwd)
fi
BIN_DIR="${HOME}/.local/bin"

mkdir -p "$BIN_DIR"
chmod +x "$SCRIPT_DIR/tool.py" "$SCRIPT_DIR/ktool" "$SCRIPT_DIR/update-ktool.sh" "$SCRIPT_DIR/deploy.sh" "$SCRIPT_DIR/ktool-auto-deploy.sh"

ln -sf "$SCRIPT_DIR/ktool" "$BIN_DIR/ktool"
ln -sf "$SCRIPT_DIR/update-ktool.sh" "$BIN_DIR/update-ktool.sh"
ln -sf "$SCRIPT_DIR/ktool-auto-deploy.sh" "$BIN_DIR/ktool-auto-deploy.sh"

echo "[+] Installed Ktool commands:"
echo "    $BIN_DIR/ktool"
echo "    $BIN_DIR/update-ktool.sh"
echo "    $BIN_DIR/ktool-auto-deploy.sh"
echo
echo "If your shell cannot find them, add this to ~/.bashrc or ~/.zshrc:"
echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
