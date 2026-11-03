Argus server edition
====================

Argus watches a Linux server for the ways something could take or keep control
of it: SSH keys and logins, sudo, accounts, systemd and cron persistence,
hidden processes, web shells, exposure and package integrity. It is one native
program (bin/argus-server) and needs no Python or other runtime.

Before installing, check the download (see the documentation for the commands):
SHA256SUMS lists every file's SHA-256, and SHA256SUMS.sig is the release
signature, made with a release key whose fingerprint is published on the site.

Install, upgrade:   sudo ./install.sh [--port 8790] [--net-sensor] [--no-start]
Uninstall:          sudo /opt/argus/uninstall.sh [--purge]
Status and logs:    systemctl status argus ; journalctl -u argus -f
First run:          argus welcome server   (what it looks at, and its limits)
First report:       argus investigate
Dashboard:          loopback only; ssh -L 8787:127.0.0.1:8787 your-server

Documentation: https://www.archymedes.xyz/en/docs/argus/
