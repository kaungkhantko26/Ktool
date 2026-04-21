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

echo "[+] Updating Ktool ..."

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[ERROR] This folder is not a Git repository: $SCRIPT_DIR"
  echo "        If you copied update-ktool.sh, set KTOOL_HOME to your repo path."
  echo "        Example: export KTOOL_HOME=\"\$HOME/Ktool\""
  exit 1
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  echo "[ERROR] Git remote 'origin' is not configured."
  exit 1
fi

# Older Ktool installs created update-ktool.sh locally before Git tracked it.
# Move that untracked file out of the way so git pull can complete.
for path in update-ktool.sh ktool install-commands.sh; do
  if [ -e "$path" ] && ! git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
    backup="$path.local-backup.$(date +%Y%m%d%H%M%S)"
    echo "[i] Moving untracked $path to $backup before pull."
    mv "$path" "$backup"
  fi
done

git fetch origin main
git pull --ff-only origin main

chmod +x tool.py ktool deploy.sh update-ktool.sh install-commands.sh 2>/dev/null || true

echo "[+] Ktool updated."
