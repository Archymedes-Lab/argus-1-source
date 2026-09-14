"""Continuous network-state logging, and what changes in it mean.

Most of this repo answers questions about the present. This module exists
because the useful network questions are all about the past: when did the link
drop, did the adapter go down on its own, has this network always been on this
hardware, did the gateway's MAC change while the SSID stayed the same.

None of those can be answered by looking now. They need a record that was
already being kept, so `sample()` runs on a short interval and every sample is
stored — not just the interesting ones. Storage is trivial (a few hundred bytes
a minute) and the alternative is discovering that the one moment you needed is
the one you did not keep.

What the transitions mean:

  adapter disabled      Nothing disables a working adapter by accident. On a
                        machine whose owner says they never turn it off, this
                        is the highest-signal event here.
  link lost             Ordinary on its own, and the reason the log exists:
                        a drop that lines up with something else in the
                        timeline is the thing worth seeing.
  same SSID, new BSSID  Roaming between access points looks exactly like an
                        evil twin. The difference is whether the new BSSID has
                        ever been seen before and whether the encryption held.
  encryption weakened   A network that was WPA3 yesterday and open today is
                        not the same network, whatever it calls itself.
  gateway MAC changed   The address the traffic leaves through is now different
                        hardware. That is what ARP spoofing looks like.
"""

import time

from jarvis.platform.windows import aslist, ps_json
from jarvis.core.util import iso, now
from jarvis.core.finding import win_finding as _finding

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

PS_NET = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.adapters = @(Get-NetAdapter | ForEach-Object {
  [pscustomobject]@{ name=[string]$_.Name; status=[string]$_.Status
                     mac=[string]$_.MacAddress; type=[string]$_.MediaType
                     up=[bool]($_.Status -eq 'Up') }})

# netsh is the only place BSSID, channel, authentication and cipher are all
# exposed together, so it is parsed as text rather than reinvented.
$o.wlan = [string](netsh wlan show interfaces 2>$null | Out-String)

$o.ipcfg = @(Get-NetIPConfiguration | ForEach-Object {
  [pscustomobject]@{
    iface=[string]$_.InterfaceAlias
    ipv4=[string]($_.IPv4Address.IPAddress -join ',')
    gw=[string]($_.IPv4DefaultGateway.NextHop -join ',')
    dns=[string](($_.DNSServer | Where-Object {$_.AddressFamily -eq 2}).ServerAddresses -join ',')
  }})

$o.neighbors = @(Get-NetNeighbor -AddressFamily IPv4 |
  Where-Object { $_.State -in 'Reachable','Stale','Permanent' } |
  ForEach-Object { [pscustomobject]@{ ip=[string]$_.IPAddress
                                      mac=[string]$_.LinkLayerAddress }})

# Windows' own record of every wireless transition. Read incrementally — only
# what has appeared since the last fetch — which makes it cheap enough to take
# on every sample instead of every half hour.
#
# No event-ID filter. The previous version kept a hand-picked subset and capped
# at 300 events, and in a twelve-hour window that silently dropped most of the
# record: ten disconnects and seven failed connects had been reduced to two
# entries. A monitor whose whole purpose is a complete timeline cannot decide
# in advance which transitions matter.
$o.wlanlog = @(Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'
    StartTime=__SINCE__} -MaxEvents 4000 -EA SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ id=$_.Id
                                      time=$_.TimeCreated.ToString('o')
                                      msg=($_.Message -replace "`r`n",' ') }})

# The profile service sees every adapter, wired included, so a link that drops
# outside the wireless stack still lands in the timeline.
$o.netprofile = @(Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-NetworkProfile/Operational'
    StartTime=__SINCE__} -MaxEvents 1000 -EA SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ id=$_.Id
                                      time=$_.TimeCreated.ToString('o')
                                      msg=($_.Message -replace "`r`n",' ') }})

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
"""

# Ordered weakest to strongest, so a downgrade is a decrease.
AUTH_RANK = {
    "open": 0, "none": 0, "wep": 1, "shared": 1,
    "wpa-personal": 2, "wpa2-personal": 3, "wpa2-enterprise": 3,
    "wpa3-personal": 4, "wpa3-enterprise": 4, "wpa3-sae": 4,
}


def _rank(auth):
    a = (auth or "").strip().lower()
    for key, val in AUTH_RANK.items():
        if key in a:
            return val
    return 3 if a else -1


def _parse_wlan(text):
    """Pull the fields netsh prints for the connected interface."""
    out = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if not v:
            continue
        if k == "name":
            out["iface"] = v
        elif k == "state":
            out["state"] = v.lower()
        elif k == "ssid" and "bssid" not in k:
            out["ssid"] = v
        elif k == "bssid":
            out["bssid"] = v.lower()
        elif k == "channel":
            out["channel"] = int(v) if v.isdigit() else 0
        elif k in ("authentication",):
            out["auth"] = v
        elif k in ("cipher",):
            out["cipher"] = v
        elif k in ("signal",):
            out["signal"] = int(v.rstrip("%")) if v.rstrip("%").isdigit() else 0
        elif k in ("radio type", "band"):
            out.setdefault("band", v)
    return out


def sample(since_ts=None):
    """One reading of current network state plus every log entry since `since_ts`.

    Reading the Windows logs incrementally is what makes complete coverage
    affordable: a full week costs seconds, five minutes of new entries costs
    almost nothing, and nothing is skipped either way.
    """
    if since_ts:
        # A minute of overlap so an entry written between the query and the
        # bookmark is seen twice rather than lost.
        secs = max(120, int(time.time() - since_ts) + 60)
        since = f"(Get-Date).AddSeconds(-{secs})"
    else:
        since = "(Get-Date).AddDays(-7)"
    script = PS_NET.replace("__SINCE__", since)
    data = ps_json(script, timeout=180)
    if not data:
        return None
    wlan = _parse_wlan(data.get("wlan"))
    iface = wlan.get("iface") or ""

    adapters = aslist(data.get("adapters"))
    wifi_ad = None
    for a in adapters:
        if iface and a.get("name") == iface:
            wifi_ad = a
            break
    if wifi_ad is None:
        for a in adapters:
            if "802.11" in (a.get("type") or "") or "Wi-Fi" in (a.get("name") or ""):
                wifi_ad = a
                iface = iface or a.get("name") or "Wi-Fi"
                break

    ipcfg = {}
    for c in aslist(data.get("ipcfg")):
        if c.get("iface") == iface:
            ipcfg = c
            break

    gw = (ipcfg.get("gw") or "").split(",")[0].strip()
    gw_mac = ""
    if gw:
        for n in aslist(data.get("neighbors")):
            if n.get("ip") == gw:
                gw_mac = (n.get("mac") or "").lower()
                break

    status = (wifi_ad or {}).get("status") or ""
    if status.lower() in ("disabled", "not present"):
        state = "disabled"
    elif wlan.get("state") == "connected":
        state = "connected"
    elif status.lower() == "up":
        state = "up"
    else:
        state = wlan.get("state") or status.lower() or "unknown"

    # netsh needs Location permission (or elevation) to reveal SSID/BSSID.
    # Without it the field is simply absent, which would look exactly like a
    # disconnected adapter — so the blocker is recorded explicitly instead.
    raw = data.get("wlan") or ""
    blocked = ("location permission" in raw.lower()
               or "requires elevation" in raw.lower()
               or "error 5" in raw.lower())
    if blocked and state == "up":
        state = "connected-opaque"

    return {
        "ts": now(), "iface": iface or "Wi-Fi", "state": state,
        "wlan_blocked": blocked,
        "ssid": wlan.get("ssid", ""), "bssid": wlan.get("bssid", ""),
        "channel": wlan.get("channel", 0), "band": wlan.get("band", ""),
        "auth": wlan.get("auth", ""), "cipher": wlan.get("cipher", ""),
        "signal": wlan.get("signal", 0),
        "ipv4": ipcfg.get("ipv4", ""), "gateway": gw, "gw_mac": gw_mac,
        "dns": ipcfg.get("dns", ""),
        "_wlanlog": aslist(data.get("wlanlog")),
        "_netprofile": aslist(data.get("netprofile")),
        "_adapters": adapters,
    }


def _last_sample(store, iface):
    return store.db.execute(
        "SELECT * FROM net_samples WHERE iface=? ORDER BY ts DESC LIMIT 1",
        (iface,)).fetchone()


def _event(store, ts, iface, kind, severity, detail, prev="", curr=""):
    store.db.execute(
        """INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr)
           VALUES(?,?,?,?,?,?,?)""",
        (ts, iface, kind, severity, detail[:500], str(prev)[:200], str(curr)[:200]))


def record(store, s=None):
    """Store one sample and raise events for anything that changed."""
    if s is None:
        # The WLAN history is re-read every half hour, not every sample: it
        # covers a week and cannot change meaningfully in five minutes, and
        # fetching it was most of this collector's cost.
        # Every sample now carries the log delta, so the timeline has no
        # holes between passes.
        try:
            last = int(float(store.get_meta("netwatch_log_at", 0) or 0))
        except (TypeError, ValueError):
            last = 0
        s = sample(since_ts=last or None)
        if s:
            store.set_meta("netwatch_log_at", now())
    if not s:
        return []
    iface = s["iface"]
    prev = _last_sample(store, iface)
    events = []

    def fire(kind, sev, detail, p="", c=""):
        _event(store, s["ts"], iface, kind, sev, detail, p, c)
        events.append({"kind": kind, "severity": sev, "detail": detail})

    if prev:
        # -- adapter turned off ---------------------------------------------
        if s["state"] == "disabled" and prev["state"] != "disabled":
            fire("adapter-disabled", "critical",
                 "the wireless adapter was disabled — nothing disables a "
                 "working adapter by accident",
                 prev["state"], s["state"])
        elif prev["state"] == "disabled" and s["state"] != "disabled":
            fire("adapter-enabled", "medium",
                 "the wireless adapter was re-enabled",
                 prev["state"], s["state"])

        # -- link lost -------------------------------------------------------
        if (prev["state"] in ("connected", "connected-opaque")
                and s["state"] not in ("connected", "connected-opaque", "disabled")):
            fire("link-lost", "medium",
                 f"connection to {prev['ssid'] or 'the network'} was lost",
                 prev["state"], s["state"])
        elif (prev["state"] not in ("connected", "connected-opaque")
              and s["state"] in ("connected", "connected-opaque")):
            fire("link-up", "low", f"connected to {s['ssid']}",
                 prev["state"], s["state"])

        if s["state"] == "connected" and prev["state"] == "connected":
            # -- access point swap -------------------------------------------
            if prev["bssid"] and s["bssid"] and prev["bssid"] != s["bssid"]:
                known = store.db.execute(
                    "SELECT seen_count FROM known_aps WHERE ssid=? AND bssid=?",
                    (s["ssid"], s["bssid"])).fetchone()
                if known:
                    fire("ap-roam", "low",
                         f"roamed to a known access point for {s['ssid']}",
                         prev["bssid"], s["bssid"])
                else:
                    fire("ap-unknown", "high",
                         f"{s['ssid']} is now served by hardware this machine "
                         f"has never seen — the SSID is the same but the access "
                         f"point is not, which is what an evil twin looks like",
                         prev["bssid"], s["bssid"])

            # -- encryption weakened -----------------------------------------
            if _rank(s["auth"]) < _rank(prev["auth"]):
                fire("crypto-downgrade", "critical",
                     f"encryption on {s['ssid']} weakened from "
                     f"{prev['auth']} to {s['auth']}",
                     prev["auth"], s["auth"])

            # -- gateway hardware changed -------------------------------------
            if prev["gw_mac"] and s["gw_mac"] and prev["gw_mac"] != s["gw_mac"]:
                fire("gateway-changed", "high",
                     f"the default gateway {s['gateway']} is answering from a "
                     f"different MAC address — this is what ARP spoofing looks "
                     f"like", prev["gw_mac"], s["gw_mac"])

            # -- resolver changed ---------------------------------------------
            if prev["dns"] and s["dns"] and prev["dns"] != s["dns"]:
                fire("dns-changed", "high",
                     f"DNS servers for {iface} changed",
                     prev["dns"], s["dns"])

    if s["state"] == "connected" and s["ssid"] and s["bssid"]:
        store.db.execute(
            """INSERT INTO known_aps(ssid,bssid,auth,first_seen,last_seen)
               VALUES(?,?,?,?,?)
               ON CONFLICT(ssid,bssid) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   seen_count=known_aps.seen_count+1""",
            (s["ssid"], s["bssid"], s["auth"], s["ts"], s["ts"]))

    store.db.execute(
        """INSERT OR REPLACE INTO net_samples
           (ts,iface,state,ssid,bssid,channel,band,auth,cipher,signal,
            ipv4,gateway,gw_mac,dns)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (s["ts"], iface, s["state"], s["ssid"], s["bssid"], s["channel"],
         s["band"], s["auth"], s["cipher"], s["signal"], s["ipv4"],
         s["gateway"], s["gw_mac"], s["dns"]))

    store.set_meta("netwatch_wlan_blocked", "1" if s.get("wlan_blocked") else "0")
    _ingest_wlanlog(store, s.get("_wlanlog") or [], _WLAN_KIND)
    _ingest_wlanlog(store, s.get("_netprofile") or [], _PROFILE_KIND)
    store.commit()
    return events


# The real WLAN-AutoConfig identifiers. The previous map had 11004 and 11010
# the wrong way round, so "security stopped" was reported as an authentication
# *start* — which reads as the opposite of what happened.
_WLAN_KIND = {
    8000:  ("wlan-connect-start", "low"),
    8001:  ("wlan-connected", "low"),
    8002:  ("wlan-connect-failed", "medium"),
    8003:  ("wlan-disconnected", "medium"),
    8011:  ("wlan-roaming", "low"),
    11000: ("wlan-assoc-start", "low"),
    11001: ("wlan-assoc-ok", "low"),
    11002: ("wlan-assoc-failed", "medium"),
    11004: ("wlan-security-stopped", "low"),
    11005: ("wlan-security-ok", "low"),
    11006: ("wlan-security-failed", "high"),
    11010: ("wlan-security-start", "low"),
    11013: ("wlan-security-restart", "low"),
    12011: ("wlan-msm-assoc", "low"),
    12012: ("wlan-msm-auth", "low"),
    12013: ("wlan-msm-done", "low"),
}

# NetworkProfile: 10000 connected, 10001 disconnected — any adapter.
_PROFILE_KIND = {
    10000: ("net-profile-connected", "low"),
    10001: ("net-profile-disconnected", "medium"),
}


def _ingest_wlanlog(store, rows, kindmap):
    """Fold a Windows log into the timeline, de-duplicating by event time."""
    seen = {r["curr"] for r in store.db.execute(
        "SELECT curr FROM net_events WHERE curr != '' "
        "ORDER BY ts DESC LIMIT 3000")}
    for r in rows:
        raw = (r.get("time") or "")
        stamp = raw[:19]
        if not stamp or stamp in seen:
            continue
        kind, sev = kindmap.get(int(r.get("id") or 0), ("wlan-event", "low"))
        # PowerShell emits ISO-8601 *with* an offset. Slicing to 19 characters
        # throws that away, and treating the remainder as UTC skewed every
        # Windows-side event by the offset — three hours here, because Windows
        # runs +02:00 while this WSL install runs +03:00. A forensic timeline
        # that is silently three hours wrong correlates the wrong events, which
        # is worse than having no timeline.
        try:
            from datetime import datetime
            ts = int(datetime.fromisoformat(raw).timestamp())
        except (ValueError, TypeError):
            try:
                import calendar
                import time as _t
                ts = int(calendar.timegm(_t.strptime(stamp, "%Y-%m-%dT%H:%M:%S")))
            except Exception:
                continue
        store.db.execute(
            """INSERT INTO net_events(ts,iface,kind,severity,detail,prev,curr)
               VALUES(?,?,?,?,?,?,?)""",
            (ts, "", kind, sev, (r.get("msg") or "")[:400], "", stamp))
        seen.add(stamp)


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
