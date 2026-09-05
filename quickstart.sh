#!/usr/bin/env bash
# One command to get JARVIS fully online and keep it there.
#
#   ./quickstart.sh                install, seal (watchdog + self-check +
#                                  Windows wake task), enable linger, verify
#   ./quickstart.sh --no-priority  skip the sudo hardening; run under the
#                                  user manager only
#   ./quickstart.sh --check        do nothing but print the health summary
#
# Safe to re-run. It calls install.sh, removes the pre-rename `sentry-*`
# units if they are still around, reloads systemd, and blocks until the
# dashboard answers.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${JARVIS_PORT:-8787}"
cd "$HERE"

mode=seal
for a in "$@"; do
  case "$a" in
    --no-priority) mode=service ;;
    --check) mode=check ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

remove_legacy_units() {
  # The rename left sentry-selfcheck.{service,timer} enabled; the service
  # fails every run with "No module named sentry" and the backdoor collector
  # keeps flagging it. Nothing depends on it.
  local changed=0
  for unit in sentry-selfcheck.timer sentry-selfcheck.service sentry.service; do
    if systemctl --user list-unit-files "$unit" >/dev/null 2>&1; then
      systemctl --user disable --now "$unit" >/dev/null 2>&1 || true
      changed=1
    fi
  done
  for f in "$HOME/.config/systemd/user/sentry-selfcheck.service" \
           "$HOME/.config/systemd/user/sentry-selfcheck.timer" \
           "$HOME/.config/systemd/user/sentry.service"; do
    [ -e "$f" ] && { rm -f "$f"; changed=1; }
  done
  if [ -e /etc/systemd/system/sentry.service ]; then
    sudo systemctl disable --now sentry.service >/dev/null 2>&1 || true
    sudo rm -rf /etc/systemd/system/sentry.service /etc/systemd/system/sentry.service.d
    changed=1
  fi
  if [ "$changed" = 1 ]; then
    systemctl --user daemon-reload || true
    sudo systemctl daemon-reload 2>/dev/null || true
    echo "removed pre-rename sentry-* units"
  fi
}

HEALTH_PY='
import json, sys, time
d = json.load(sys.stdin)
jobs = d.get("jobs", [])
now = time.time()
stale = [j["name"] for j in jobs if j.get("stale")]
err = [j["name"] for j in jobs if j.get("error")]
never = [j["name"] for j in jobs if not j.get("ts")]
print("collectors:  %d registered" % len(jobs))
print("stale:       %s" % (", ".join(stale) if stale else "none"))
print("errored:     %s" % (", ".join(err) if err else "none"))
print("never run:   %s" % (", ".join(never) if never else "none"))
oldest = max((now - j["ts"] for j in jobs if j.get("ts")), default=0)
print("oldest pass: %.1f min ago" % (oldest / 60))
'

health() {
  local out
  if ! out="$(curl -fsS "http://127.0.0.1:$PORT/api/state" 2>/dev/null)"; then
    echo "dashboard not answering on :$PORT"
    return 1
  fi
  printf '%s' "$out" | python3 -c "$HEALTH_PY"
}

if [ "$mode" = check ]; then
  say "JARVIS health"
  health
  echo "dashboard:   http://127.0.0.1:$PORT"
  exit 0
fi

say "1/4  Installing"
if [ "$mode" = seal ]; then ./install.sh --seal; else ./install.sh --service; fi

say "2/4  Clearing pre-rename units"
remove_legacy_units

say "3/4  Enabling linger (survives logout)"
if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
  sudo loginctl enable-linger "$USER" && echo "linger enabled for $USER"
else
  echo "linger already on"
fi

say "4/4  Waiting for the dashboard"
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/api/state" >/dev/null 2>&1; then
    echo "up after ${i}s"
    break
  fi
  sleep 1
done

say "Health"
health || true

cat <<EOF

dashboard:   http://127.0.0.1:$PORT   (open the "ops & setup" tab for commands)
service:     sudo systemctl status jarvis.service
logs:        journalctl -u jarvis.service -f -o cat
self-check:  systemctl --user list-timers jarvis-selfcheck.timer
EOF
