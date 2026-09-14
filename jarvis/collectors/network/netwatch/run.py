"""The netwatch audit: what the recorded transitions mean."""

from jarvis.core.finding import win_finding as _finding
from jarvis.core.util import iso, now

from .sample import _rank

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def audit(store, hours=24):
    """Report what the recorded history says about the last day."""
    since = now() - hours * 3600
    out = []

    rows = store.db.execute(
        "SELECT kind, severity, COUNT(*) n, MAX(ts) last, "
        "       MAX(detail) detail, MAX(prev) prev, MAX(curr) curr "
        "FROM net_events WHERE ts>=? GROUP BY kind, severity "
        "ORDER BY COUNT(*) DESC", (since,)).fetchall()
    for r in rows:
        if r["kind"] in ("link-up", "wlan-connected", "wlan-auth",
                         "wlan-assoc", "wlan-auth-done", "wlan-auth-started",
                         "wlan-assoc-started", "ap-roam"):
            continue
        detail = r["detail"] or ""
        if r["prev"] or r["curr"]:
            detail += f"  ({r['prev']} → {r['curr']})"
        out.append(_finding(
            "network", r["severity"],
            f"{r['kind'].replace('-', ' ')} ×{r['n']}"
            if r["n"] > 1 else r["kind"].replace("-", " "),
            f"{detail} — last at {iso(r['last'])}", "net_events"))

    blocked = store.get_meta("netwatch_wlan_blocked", "") == "1"
    if blocked:
        out.append(_finding(
            "network", "medium",
            "SSID and access point are invisible to this audit",
            "netsh needs Location permission to report SSID, BSSID, "
            "authentication and cipher. Without it, evil-twin and encryption-"
            "downgrade detection cannot run — adapter state, gateway MAC, DNS "
            "and the connect/disconnect log still work. Enable Location under "
            "Settings > Privacy & security > Location, or run elevated.",
            "netsh wlan"))

    latest = store.db.execute(
        "SELECT * FROM net_samples ORDER BY ts DESC LIMIT 1").fetchone()
    if latest:
        if latest["state"] == "disabled":
            out.append(_finding(
                "network", "critical", "the wireless adapter is disabled now",
                f"last seen in this state at {iso(latest['ts'])}", latest["iface"]))
        elif latest["state"] == "connected-opaque":
            out.append(_finding(
                "network", "ok", f"link is up on {latest['iface']}",
                f"gateway {latest['gateway'] or '?'} "
                f"({latest['gw_mac'] or 'no arp entry'}) · "
                f"dns {latest['dns'] or '?'} — SSID hidden by permissions",
                latest["iface"]))
        elif latest["state"] == "connected":
            open_net = _rank(latest["auth"]) <= 1
            out.append(_finding(
                "network", "high" if open_net else "ok",
                f"connected to {latest['ssid']}"
                + (" over an unencrypted network" if open_net else ""),
                f"{latest['auth'] or 'unknown auth'} / "
                f"{latest['cipher'] or 'unknown cipher'} · "
                f"AP {latest['bssid'] or '?'} · gateway {latest['gateway'] or '?'}"
                f" ({latest['gw_mac'] or 'no arp entry'})",
                latest["iface"]))
        gap = now() - latest["ts"]
        if gap > 3600:
            out.append(_finding(
                "network", "medium", "network state has not been sampled recently",
                f"last sample {iso(latest['ts'])} — coverage of the timeline has "
                f"a {gap // 60} minute hole", "netwatch"))
    else:
        out.append(_finding(
            "network", "medium", "no network history recorded yet",
            "run `jarvis netwatch` or start the daemon to begin the timeline",
            "netwatch"))
    return sort_findings(out)


def timeline(store, hours=24, limit=200):
    return [dict(r) for r in store.db.execute(
        "SELECT * FROM net_events WHERE ts>=? ORDER BY ts DESC LIMIT ?",
        (now() - hours * 3600, limit))]


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))
