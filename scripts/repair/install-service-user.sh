#!/usr/bin/env bash
# Move the JARVIS daemon to its own system user (PROTECTION-REVIEW-2026-10-21 F2).
#
#   sudo scripts/repair/install-service-user.sh --preflight   check only, change nothing
#   sudo scripts/repair/install-service-user.sh                migrate and switch
#   sudo scripts/repair/install-service-user.sh --rollback     restore the previous unit and state
#
# Order of operations, each step reversible:
#   1. create user/group `jarvis` and group `jarvis-readers` (the owner joins it so
#      `jarvis status` and the other read-only CLI commands can still open the store);
#   2. PREFLIGHT: as `jarvis`, run powershell.exe through WSL interop and read /mnt/c.
#      If either fails the script stops here: a daemon that cannot reach Windows
#      protects nothing, and the old unit keeps running;
#   3. copy ~chris/.jarvis to /var/lib/jarvis (owner jarvis, 0750; store 0640 for
#      the readers group) and config.json to /etc/jarvis/config.json (root:jarvis 0640,
#      so the daemon reads it and the user cannot rewrite alert settings);
#   4. install the drop-in, daemon-reload, restart, and read /api/health back.
# The previous state stays in place untouched; --rollback removes the drop-in and
# restarts on the old unit. Nothing here deletes the user's copy.
#
# Known limits, stated: CLI commands that write to the store (ack, privacy seal,
# defend approve, fix) must run as the jarvis user (`sudo -u jarvis jarvis ...`) or
# through the authenticated API once the CLI is moved onto it; the Windows-side
# supervisors still run as the user (a separate, elevated step); the daemon still
# reads the Windows disk with the same rights as before.
set -euo pipefail
[[ $(id -u) = 0 ]] || { echo 'Run as root (sudo).' >&2; exit 1; }
OWNER=chris
SRC_HOME=/home/$OWNER/.jarvis
DST=/var/lib/jarvis
CONF_DIR=/etc/jarvis
DROPIN_DIR=/etc/systemd/system/jarvis.service.d
DROPIN=$DROPIN_DIR/service-user.conf
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
mode=${1:-apply}

if [[ $mode == --rollback ]]; then
  rm -f "$DROPIN"
  systemctl daemon-reload
  systemctl restart jarvis.service
  sleep 3; systemctl is-active jarvis.service
  echo "rolled back: unit runs as before; /var/lib/jarvis and /etc/jarvis left in place"
  exit 0
fi

getent group jarvis >/dev/null || groupadd --system jarvis
getent group jarvis-readers >/dev/null || groupadd --system jarvis-readers
id jarvis >/dev/null 2>&1 || useradd --system --gid jarvis --home-dir "$DST" --shell /usr/sbin/nologin jarvis
usermod -a -G jarvis-readers "$OWNER"

echo "[preflight] Windows interop as jarvis"
if ! sudo -u jarvis -H env -i PATH=/usr/bin:/bin WSL_INTEROP="${WSL_INTEROP:-}" \
      /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -NonInteractive -Command 'Write-Output ok' 2>/dev/null | tr -d '\r' | grep -qx ok; then
  echo "PREFLIGHT FAILED: powershell.exe does not run for the jarvis user through interop; nothing changed." >&2
  echo "This is the known risk of F2 on WSL; the daemon stays on the current unit." >&2
  exit 2
fi
sudo -u jarvis test -r /mnt/c/ProgramData/Jarvis/Sensor/health.json || { echo "PREFLIGHT FAILED: jarvis cannot read the sensor spool" >&2; exit 2; }
echo "[preflight] ok"
[[ $mode == --preflight ]] && exit 0

install -d -o jarvis -g jarvis -m 0750 "$DST"
rsync -a --chown=jarvis:jarvis "$SRC_HOME/" "$DST/"
chmod 0640 "$DST"/*.db 2>/dev/null || true
chgrp jarvis-readers "$DST"/*.db 2>/dev/null || true
install -d -o root -g jarvis -m 0750 "$CONF_DIR"
install -o root -g jarvis -m 0640 "$SRC_HOME/config.json" "$CONF_DIR/config.json"
install -d -m 0755 "$DROPIN_DIR"
install -o root -g root -m 0644 "$repo/systemd/service-user.conf" "$DROPIN"
systemctl daemon-reload
systemctl restart jarvis.service
sleep 5
systemctl show jarvis.service -p User -p ActiveState
curl -s -m 10 http://127.0.0.1:8787/api/live || { echo "daemon not answering; rolling back" >&2; "$0" --rollback; exit 3; }
echo
echo "switched. Verify over the next 15 minutes: every collector FRESH, native complete, broker results accepted."
echo "If anything regresses: sudo $0 --rollback"
