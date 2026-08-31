#!/usr/bin/env bash
# Install sentry, and optionally run it 24/7.
#
#   ./install.sh              put `sentry` on PATH
#   ./install.sh --service    ...and run the daemon under systemd, always on
#   ./install.sh --priority   ...and give it top CPU/IO priority + OOM immunity
#                             (writes a system drop-in; needs sudo once)
#   ./install.sh --windows    ...and print the one Windows command that keeps
#                             WSL itself alive across reboots
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HOME/.local/bin"
PORT="${SENTRY_PORT:-8787}"
mkdir -p "$BIN"

cat > "$BIN/sentry" <<EOF
#!/usr/bin/env bash
cd "$HERE" && exec python3 -m sentry "\$@"
EOF
chmod +x "$BIN/sentry"
echo "installed: $BIN/sentry"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "note: add $BIN to PATH — echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
esac

want_service=false; want_windows=false; want_priority=false
for arg in "$@"; do
  case "$arg" in
    --service) want_service=true ;;
    --priority) want_service=true; want_priority=true ;;
    --windows) want_windows=true ;;
  esac
done

if $want_service; then
  UNIT="$HOME/.config/systemd/user"
  mkdir -p "$UNIT"
  cat > "$UNIT/sentry.service" <<EOF
[Unit]
Description=sentry — continuous process, network and control-surface monitoring
After=network.target

[Service]
Type=simple
WorkingDirectory=$HERE
ExecStart=/usr/bin/python3 -m sentry serve --port $PORT
Restart=always
RestartSec=15

# This monitor is meant to win contention for the machine, not lose it.
# CPUWeight/IOWeight are relative cgroup shares (max 10000) and need no
# privilege. Nice and a negative OOMScoreAdjust require a privileged manager;
# the user manager will log and ignore them — run \`./install.sh --priority\`
# for a system drop-in that makes them stick.
CPUWeight=10000
IOWeight=10000
Nice=-10
OOMScoreAdjust=-800
# A security monitor that gets OOM-killed is the failure it exists to prevent.
MemoryHigh=1536M
MemoryMax=2G
TasksMax=4096

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now sentry.service
  echo "service:   systemctl --user status sentry"
  echo "logs:      journalctl --user -u sentry -f"
  echo "dashboard: http://127.0.0.1:$PORT"

  # Without linger, systemd tears down the user manager when the last shell
  # exits — which is exactly what happens when you close your terminal.
  if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
    echo
    echo "IMPORTANT — the daemon will stop when you close your last shell."
    echo "To keep it running without a login session:"
    echo "    sudo loginctl enable-linger $USER"
  fi
fi

if $want_priority; then
  # The user manager cannot grant a negative nice or a negative OOM score.
  # Moving the unit to the system manager (still running as this user) can.
  SYS="/etc/systemd/system/sentry.service"
  echo
  echo "Installing $SYS (system manager, runs as $USER) for real priority."
  echo "This needs sudo once."
  sudo tee "$SYS" >/dev/null <<EOF
[Unit]
Description=sentry — continuous monitoring (top priority)
After=network.target

[Service]
Type=simple
User=$USER
Group=$(id -gn)
WorkingDirectory=$HERE
ExecStart=/usr/bin/python3 -m sentry serve --port $PORT
Restart=always
RestartSec=15

# Win CPU and IO contention, and do not get OOM-killed. A privileged manager
# is required for the last two, which is the whole reason this unit exists.
CPUWeight=10000
IOWeight=10000
IOSchedulingClass=best-effort
IOSchedulingPriority=0
Nice=-10
OOMScoreAdjust=-800
MemoryHigh=1536M
MemoryMax=2G
TasksMax=4096

[Install]
WantedBy=multi-user.target
EOF
  systemctl --user disable --now sentry.service 2>/dev/null || true
  sudo systemctl daemon-reload
  sudo systemctl enable --now sentry.service
  echo "now managed by:  sudo systemctl status sentry"
  echo "verify:          systemctl show sentry -p Nice -p OOMScoreAdjust -p CPUWeight"
fi

if $want_windows; then
  cat <<'EOF'

--------------------------------------------------------------------
Keeping it running across Windows reboots
--------------------------------------------------------------------
WSL only runs while Windows keeps it running. Enabling linger (above)
keeps sentry alive inside WSL; this task makes sure WSL itself starts
at logon, with no visible window.

Run this ONCE in Windows PowerShell (no elevation needed):

  $a = New-ScheduledTaskAction -Execute "wsl.exe" `
       -Argument "-d Ubuntu --exec /bin/true"
  $t = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
  $p = New-ScheduledTaskPrincipal -UserId $env:USERNAME `
       -LogonType Interactive -RunLevel Limited
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
       -DontStopIfGoingOnBatteries -StartWhenAvailable `
       -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask -TaskName "WSL sentry 24x7" -Action $a `
       -Trigger $t -Principal $p -Settings $s `
       -Description "Starts WSL so sentry keeps running"

RunLevel Limited is load-bearing: asking for -RunLevel Highest makes
registration itself require an elevated shell and fails with 0x80070005.
The task does not need admin — it only has to start WSL.

Starting WSL is enough: systemd then starts sentry.service on its own,
and linger keeps it up with no session attached.

To undo:  Unregister-ScheduledTask -TaskName "WSL sentry 24x7"
--------------------------------------------------------------------
EOF
fi
