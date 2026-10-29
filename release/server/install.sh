#!/usr/bin/env bash
# Install Argus on a Linux server.
#
#   sudo ./install.sh                 install (or upgrade) and start Argus
#   sudo ./install.sh --port 8790     another dashboard port (default 8787)
#   sudo ./install.sh --no-start      install without starting the service
#   sudo ./install.sh --skip-verify   do not refuse a copy that fails its own verification
#   sudo ./install.sh --net-sensor    also watch inbound packets (headers only) and read the
#                                     firewall ruleset, each in its own minimal unit
#   sudo ./install.sh --linux-only    inside WSL: watch only the Linux guest, like a server
#                                     (no Windows domain, no PowerShell over interop)
#
# Argus is one native program: no Python or other runtime is installed or used.
# Before the service starts, the installed copy verifies itself: the property
# checks and model checks compiled into it run over the installed program
# (argus -m argus.verify). A copy that fails is not installed; the report is kept
# at /opt/argus/verification.json.
#
# Layout:
#   /opt/argus/bin        the program and its libraries, root-owned and read-only
#   /var/lib/argus        what Argus records (baseline, findings, history)
#   /etc/argus/argus.env  settings the service reads (port)
#   argus.service         systemd unit, runs as the `argus` account
#   /usr/local/bin/argus  the command line
#
# The service is not root. It runs as `argus` with three read-only
# capabilities (see the unit) and can read, not change, the machine. The code it
# runs is owned by root, so the account it runs as cannot rewrite it.
# The download is checked before this runs: compare SHA256SUMS and its
# signature (https://www.archymedes.xyz/en/docs/argus/ explains how).
set -euo pipefail

PORT=8787
START=true
VERIFY=true
NETSENSOR=false
PORT_SET=false
LINUX_ONLY=false
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; PORT_SET=true; shift 2 ;;
    --no-start) START=false; shift ;;
    --skip-verify) VERIFY=false; shift ;;
    --net-sensor) NETSENSOR=true; shift ;;
    --linux-only) LINUX_ONLY=true; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '  %s\n' "$*"; }
die() { printf 'argus: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root: sudo $0 $*"
[ "$(uname -s)" = Linux ] || die "this is the Linux server edition"
command -v systemctl >/dev/null && [ -d /run/systemd/system ] || die "systemd is required"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -x "$HERE/bin/argus-server" ] || die "bin/argus-server is missing; extract the whole archive first"
case "$(uname -m)" in x86_64|amd64) ;; *) die "this download is for x86-64; $(uname -m) is not supported yet" ;; esac
PREFIX=/opt/argus
STATE=/var/lib/argus

# --- account and files --------------------------------------------------------
if ! id argus >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin \
          --comment "Argus security monitor" argus
  say "created system account: argus"
fi
# Read the auth log and the journal (brute-force and login audits).
for g in adm systemd-journal; do
  getent group "$g" >/dev/null && usermod -aG "$g" argus
done

if systemctl is-active --quiet argus.service; then systemctl stop argus.service; fi
# Root-owned and closed to others: the launcher refuses its capabilities otherwise.
install -d -m 0755 -o root -g root "$PREFIX"
rm -rf "$PREFIX/bin.new"
cp -a "$HERE/bin" "$PREFIX/bin.new"
cp "$HERE/VERSION" "$PREFIX/VERSION" 2>/dev/null || true
chown -R root:root "$PREFIX/bin.new"
chmod -R u=rwX,go=rX "$PREFIX/bin.new"
rm -rf "$PREFIX/bin.old"
[ -d "$PREFIX/bin" ] && mv "$PREFIX/bin" "$PREFIX/bin.old"
mv "$PREFIX/bin.new" "$PREFIX/bin"

# --- the copy proves itself -----------------------------------------------------
# Property checks and exhaustive model checks over the files just installed.
# A copy that fails them is damaged or altered and must not score this server.
say "verifying the installed code (property checks and model checks)"
if (cd / && ARGUS_QUIET_SEAL=1 "$PREFIX/bin/argus-server" -m argus.verify --json "$PREFIX/verification.json" > "$PREFIX/verification.txt" 2>&1); then
  say "$(head -n 1 "$PREFIX/verification.txt")"
else
  cat "$PREFIX/verification.txt" >&2
  if $VERIFY; then
    if [ -d "$PREFIX/bin.old" ]; then rm -rf "$PREFIX/bin"; mv "$PREFIX/bin.old" "$PREFIX/bin"; fi
    die "the installed code failed its own verification; the previous installation was kept. Re-download Argus, or use --skip-verify to override."
  fi
  say "WARNING: verification failed; continuing on request (--skip-verify)"
fi
chmod 644 "$PREFIX/verification.json" "$PREFIX/verification.txt" 2>/dev/null || true
rm -rf "$PREFIX/bin.old"
# Earlier editions ran Python bytecode from app/ with a private Python; removed
# only once the native copy has passed its verification.
rm -rf "$PREFIX/app" "$PREFIX/python"
cp "$HERE/uninstall.sh" "$PREFIX/uninstall.sh"; chmod 755 "$PREFIX/uninstall.sh"

install -d -m 0750 -o argus -g argus "$STATE"
install -d -m 0755 /etc/argus
# Read at startup by the platform seam (root-owned, 0644): inside WSL, watch only
# the Linux guest. Kept on upgrade once set.
if $LINUX_ONLY; then
  printf 'linux\n' > /etc/argus/host-kind
  chown root:root /etc/argus/host-kind; chmod 0644 /etc/argus/host-kind
  say "Linux-only: this install watches the Linux guest, not Windows"
fi
# An upgrade keeps the configured port unless --port names a new one: a re-run
# (or a package upgrade, which passes no options) must not move the dashboard.
if [ -f /etc/argus/argus.env ] && ! $PORT_SET; then
  kept="$(sed -n 's/^ARGUS_PORT=\([0-9]\{1,5\}\)$/\1/p' /etc/argus/argus.env | tail -n 1)"
  [ -n "$kept" ] && PORT="$kept"
fi
case "$PORT" in ''|*[!0-9]*) die "--port must be a number" ;; esac
# The port must be free (any earlier Argus was stopped above). Without this, a
# port held by another dashboard (JARVIS on 8787, found 2026-10-29) made Argus
# fail to bind while the readiness check below was answered by the other one.
port_busy() { [ -n "$(ss -Hltn "sport = :$1" 2>/dev/null)" ]; }
if port_busy "$PORT"; then
  $PORT_SET && die "port $PORT is in use by another program; choose another with --port"
  requested=$PORT
  for p in $(seq $((PORT + 1)) $((PORT + 20))); do
    if ! port_busy "$p"; then PORT=$p; break; fi
  done
  [ "$PORT" != "$requested" ] || die "ports $requested to $((requested + 20)) are all in use; choose one with --port"
  say "port $requested is in use; the dashboard uses port $PORT instead"
fi
[ -f /etc/argus/argus.env ] || printf 'ARGUS_PORT=%s\n' "$PORT" > /etc/argus/argus.env
if grep -q '^ARGUS_PORT=' /etc/argus/argus.env; then
  sed -i "s/^ARGUS_PORT=.*/ARGUS_PORT=$PORT/" /etc/argus/argus.env
else
  printf 'ARGUS_PORT=%s\n' "$PORT" >> /etc/argus/argus.env
fi

# --- service ------------------------------------------------------------------
install -m 644 "$HERE/units/argus.service" /etc/systemd/system/argus.service
chmod 644 /etc/systemd/system/argus.service

# --- network sensors (opt-in) ---------------------------------------------------
# Two units under their own account, never the daemon: the packet sensor holds
# only CAP_NET_RAW (and drops it once its socket is open), the firewall reader
# only CAP_NET_ADMIN for fixed listing commands. They write into
# /var/lib/argus-net, which the daemon reads through the argus group; the
# sensor account cannot read /var/lib/argus.
# Opt-in once: an upgrade refreshes the sensor units if they are installed.
[ -e /etc/systemd/system/argus-netsensor.service ] && NETSENSOR=true
if $NETSENSOR; then
  if ! id argus-net >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/argus-net --no-create-home --shell /usr/sbin/nologin \
            --user-group --comment "Argus network sensor" argus-net
    say "created system account: argus-net"
  fi
  # setgid: files the sensor writes belong to group argus, readable by the daemon.
  install -d -m 2750 -o argus-net -g argus /var/lib/argus-net
  for unit in argus-netsensor.service argus-netstate.service argus-netstate.timer; do
    install -m 644 "$HERE/units/$unit" "/etc/systemd/system/$unit"
    chmod 644 "/etc/systemd/system/$unit"
  done
  command -v nft >/dev/null || say "note: nft is not installed; the firewall view will read ufw/firewalld only"
fi

# --- command line -------------------------------------------------------------
# Runs as `argus` with the service's capabilities, so a one-off audit sees what
# the daemon sees and writes to the same history without leaving root-owned
# files behind for the daemon to trip over.
cat > /usr/local/bin/argus <<EOF
#!/bin/sh
# Argus command line (installed by argus-server install.sh)
if [ "\$(id -u)" != 0 ]; then exec sudo "\$0" "\$@"; fi
cd / || exit 1
exec setpriv --reuid=argus --regid=argus --init-groups \\
  --inh-caps=+sys_ptrace,+dac_read_search,+syslog \\
  --ambient-caps=+sys_ptrace,+dac_read_search,+syslog \\
  env -i HOME=$STATE PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \\
      LANG=C.UTF-8 TERM="\${TERM:-dumb}" \\
  $PREFIX/bin/argus-server "\$@"
EOF
chmod 755 /usr/local/bin/argus

# What this server is meant to expose: written once, every line commented out,
# for the owner to uncomment. Until then Argus says the services are undeclared
# rather than guessing (a listener present at install could be a backdoor).
if [ ! -e /etc/argus/services.conf ]; then
  /usr/local/bin/argus services --suggest > /etc/argus/services.conf 2>/dev/null \
    || printf '# port/proto [source networks ...], e.g. 22/tcp\n' > /etc/argus/services.conf
  chmod 644 /etc/argus/services.conf
  say "wrote /etc/argus/services.conf (all commented: uncomment the services this server provides)"
fi

systemctl daemon-reload
systemctl enable argus.service >/dev/null 2>&1
if $NETSENSOR; then
  systemctl enable argus-netsensor.service argus-netstate.timer >/dev/null 2>&1
fi
if $START; then
  # Learn this server as it is now, so the first scans report drift from it.
  if [ ! -e "$STATE/.argus/argus.db" ]; then
    say "recording the baseline (this server as it is now)"
    /usr/local/bin/argus baseline >/dev/null 2>&1 || say "baseline did not finish; run: argus baseline"
  fi
  systemctl restart argus.service
  if $NETSENSOR; then
    systemctl restart argus-netsensor.service
    systemctl start argus-netstate.service || say "firewall snapshot failed: journalctl -u argus-netstate"
  fi
  # Ready means Argus itself answers: its health names the service, so another
  # program on the port cannot pass for it. 503 (degraded while it starts) still
  # carries the body.
  answered=false
  for _ in $(seq 1 60); do
    # No -f: a 503 while starting still carries the body that names the service.
    body="$( (curl -sS --max-time 3 "http://127.0.0.1:$PORT/api/health" \
              || wget -q -T 3 -O - "http://127.0.0.1:$PORT/api/health") 2>/dev/null || true)"
    if printf '%s' "$body" | grep -q '"service": *"ARGUS"'; then
      say "running: dashboard answering on 127.0.0.1:$PORT"; answered=true; break
    fi
    sleep 1
  done
  $answered || say "Argus is starting but its dashboard is not answering yet: check later with systemctl status argus"
fi

cat <<EOF

  Argus is installed and starts with the server.

  status:      systemctl status argus        logs: journalctl -u argus -f
  first look:  argus investigate
  dashboard:   bound to 127.0.0.1 only. From your own machine:
                 ssh -L $PORT:127.0.0.1:$PORT $(hostname -f 2>/dev/null || hostname)
               then open http://127.0.0.1:$PORT
  alerts:      argus alert --help        (email, webhook, ntfy or syslog)
  services:    edit /etc/argus/services.conf, then: argus services
  uninstall:   sudo /opt/argus/uninstall.sh

EOF
