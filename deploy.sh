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
cd "$SCRIPT_DIR"

MESSAGE="${1:-Deploy KTOOL FieldOps updates}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[ERROR] KTOOL FieldOps folder is not a Git repository."
  exit 1
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  echo "[ERROR] Git remote 'origin' is not configured."
  exit 1
fi

chmod +x tool.py ktool deploy.sh update-ktool.sh install-commands.sh ktool-auto-deploy.sh 2>/dev/null || true

if [ "${1:-}" = "--update" ]; then
  exec ./update-ktool.sh
fi

if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
  echo "[+] No KTOOL FieldOps changes to deploy."
  exit 0
fi

echo "[+] Staging KTOOL FieldOps changes..."
git add .gitignore README.md tool.py ktool deploy.sh update-ktool.sh install-commands.sh ktool-auto-deploy.sh

echo "[+] Committing: $MESSAGE"
git commit -m "$MESSAGE"

echo "[+] Pushing to GitHub..."
git push origin HEAD:main

echo "[+] KTOOL FieldOps deployed to GitHub."
