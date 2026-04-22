#!/usr/bin/env sh
set -eu

LABEL="com.ktool.autodeploy"
DEFAULT_INTERVAL=300

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

PLIST_PATH="${HOME}/Library/LaunchAgents/${LABEL}.plist"
LOG_DIR="${HOME}/Library/Logs/Ktool"
LOCK_DIR="${TMPDIR:-/tmp}/ktool-auto-deploy.lock"

usage() {
  cat <<EOF
Usage:
  ktool-auto-deploy.sh install [interval_seconds]
  ktool-auto-deploy.sh uninstall
  ktool-auto-deploy.sh status
  ktool-auto-deploy.sh run

The install command enables auto-deploy after normal ktool runs and creates a
macOS LaunchAgent that also tries to deploy in the background.
EOF
}

write_plist() {
  interval="${1:-$DEFAULT_INTERVAL}"
  case "$interval" in
    *[!0-9]*|"") echo "[ERROR] interval must be a positive integer."; exit 1 ;;
  esac
  if [ "$interval" -lt 60 ]; then
    echo "[ERROR] interval must be at least 60 seconds."
    exit 1
  fi

  mkdir -p "$(dirname "$PLIST_PATH")" "$LOG_DIR"
  cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${SCRIPT_DIR}/ktool-auto-deploy.sh</string>
    <string>run</string>
  </array>
  <key>StartInterval</key>
  <integer>${interval}</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>${SCRIPT_DIR}</string>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/auto-deploy.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/auto-deploy.err</string>
</dict>
</plist>
EOF
}

install_agent() {
  touch "$SCRIPT_DIR/.ktool-auto-deploy"

  if [ "$(uname -s)" != "Darwin" ]; then
    echo "[+] Ktool auto-deploy enabled after normal ktool runs."
    echo "[i] Background scheduling currently supports macOS launchd only."
    exit 0
  fi
  interval="${1:-$DEFAULT_INTERVAL}"
  chmod +x "$SCRIPT_DIR/ktool-auto-deploy.sh" "$SCRIPT_DIR/deploy.sh" 2>/dev/null || true
  write_plist "$interval"
  launchctl bootout "gui/$(id -u)" "$PLIST_PATH" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"
  launchctl enable "gui/$(id -u)/${LABEL}" >/dev/null 2>&1 || true
  echo "[+] Ktool auto-deploy enabled after normal ktool runs."
  echo "[+] Ktool auto-deploy enabled every ${interval}s."
  echo "[i] Logs: ${LOG_DIR}/auto-deploy.log and ${LOG_DIR}/auto-deploy.err"
}

uninstall_agent() {
  if [ "$(uname -s)" = "Darwin" ]; then
    launchctl bootout "gui/$(id -u)" "$PLIST_PATH" >/dev/null 2>&1 || true
  fi
  rm -f "$PLIST_PATH"
  rm -f "$SCRIPT_DIR/.ktool-auto-deploy"
  echo "[+] Ktool auto-deploy disabled."
}

status_agent() {
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "[i] Auto-deploy status is only available through launchd on macOS."
    exit 0
  fi
  if [ -f "$PLIST_PATH" ]; then
    echo "[+] LaunchAgent exists: $PLIST_PATH"
  else
    echo "[i] LaunchAgent is not installed."
  fi
  if [ -f "$SCRIPT_DIR/.ktool-auto-deploy" ]; then
    echo "[+] Auto-deploy after normal ktool runs is enabled."
  else
    echo "[i] Auto-deploy after normal ktool runs is disabled."
  fi
  launchctl print "gui/$(id -u)/${LABEL}" 2>/dev/null || true
}

run_once() {
  cd "$SCRIPT_DIR"

  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "[ERROR] Ktool folder is not a Git repository: $SCRIPT_DIR"
    exit 1
  fi
  if ! git remote get-url origin >/dev/null 2>&1; then
    echo "[ERROR] Git remote 'origin' is not configured."
    exit 1
  fi

  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "[i] Auto-deploy is already running; skipping this cycle."
    exit 0
  fi
  trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT INT TERM

  if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
    echo "[i] No Ktool changes to auto-deploy."
    exit 0
  fi

  message="Auto deploy Ktool updates $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  "$SCRIPT_DIR/deploy.sh" "$message"
}

case "${1:-}" in
  install) shift; install_agent "${1:-$DEFAULT_INTERVAL}" ;;
  uninstall) uninstall_agent ;;
  status) status_agent ;;
  run) run_once ;;
  -h|--help|help|"") usage ;;
  *) echo "[ERROR] Unknown command: $1"; usage; exit 2 ;;
esac
