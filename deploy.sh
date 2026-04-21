#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

MESSAGE="${1:-Auto deploy Ktool updates}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[ERROR] Ktool folder is not a Git repository."
  exit 1
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  echo "[ERROR] Git remote 'origin' is not configured."
  exit 1
fi

chmod +x tool.py Ktool deploy.sh 2>/dev/null || true

if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
  echo "[+] No Ktool changes to deploy."
  exit 0
fi

echo "[+] Staging Ktool changes..."
git add .gitignore README.md tool.py Ktool deploy.sh

echo "[+] Committing: $MESSAGE"
git commit -m "$MESSAGE"

echo "[+] Pushing to GitHub..."
git push origin HEAD:main

echo "[+] Ktool deployed to GitHub."
