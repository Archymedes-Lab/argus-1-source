"""Where this device is — as a security signal, honestly or not at all.

Location is evidence, and evidence JARVIS cannot obtain is reported as absent,
never invented. The primary source is the native Windows locator
(`Windows.Devices.Geolocation.Geolocator`), used only with the user's standing
consent; IP geolocation is not used as a position, because it locates a network,
not a device. When consent is off — the common case — this says so and stops.

Privacy is built in. No coordinate history is kept: `geo_current` in the store
is a single row overwritten each run, holding the last fix and its accuracy for
a short time. What persists as history is the reduced zone ("HOME", "outside"),
not a track. Trusted zones are user-asserted ground truth (`jarvis geo zone`),
which is legitimate to store; a raw GPS trail is not.
"""

import json
import math

from jarvis.core import collection
from jarvis.core.finding import win_finding as _finding
from jarvis.core.util import now
from jarvis.platform.windows import ps_json

CONSENT_KEY = (r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
               r"\CapabilityAccessManager\ConsentStore\location")


def consent():
    """Windows location consent, read from the registry with no prompt."""
    d = ps_json(
        "$o=[ordered]@{}; "
        f"$c=(Get-ItemProperty '{CONSENT_KEY}' -EA SilentlyContinue).Value; "
        "$o.consent=[string]$c; "
        "$o.service=[string](Get-Service lfsvc -EA SilentlyContinue).Status; "
        "$json=[pscustomobject]$o|ConvertTo-Json -Compress; "
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))")
    return d or {}


def locate():
    """A one-shot position, or a status explaining why there isn't one.

    -> {status: 'ok'|'denied'|'unavailable', ...}. Never returns a guessed
    position; 'denied' and 'unavailable' carry no coordinates.
    """
    c = consent()
    if (c.get("consent") or "").lower() == "deny":
        return {"status": "denied", "reason": "Windows location permission is off"}
    if (c.get("service") or "").lower() not in ("running", "startpending"):
        return {"status": "unavailable", "reason": "the Windows location service is not running"}
    # Consent is present: ask the native locator once, with a timeout.
    d = ps_json(r"""
$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{status='unavailable'}
try {
  [Windows.Devices.Geolocation.Geolocator,Windows.Devices.Geolocation,ContentType=WindowsRuntime] | Out-Null
  $g = New-Object Windows.Devices.Geolocation.Geolocator
  $g.DesiredAccuracy = [Windows.Devices.Geolocation.PositionAccuracy]::Default
  $op = $g.GetGeopositionAsync()
  $t = [DateTime]::Now
  while ($op.Status -eq [Windows.Foundation.AsyncStatus]::Started -and ([DateTime]::Now-$t).TotalSeconds -lt 12) {
    Start-Sleep -Milliseconds 200
  }
  if ($op.Status -eq [Windows.Foundation.AsyncStatus]::Completed) {
    $p = $op.GetResults().Coordinate
    $o.status='ok'; $o.lat=[double]$p.Point.Position.Latitude
    $o.lon=[double]$p.Point.Position.Longitude
    $o.accuracy_m=[double]$p.Accuracy; $o.source='windows-gnss'
  } else { $o.reason='locator did not return a fix' }
} catch { $o.reason=$_.Exception.Message }
$json=[pscustomobject]$o|ConvertTo-Json -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
""", timeout=30)
    return d or {"status": "unavailable", "reason": "no response from the location bridge"}


def haversine_m(lat1, lon1, lat2, lon2):
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def get_zones(store):
    try:
        return json.loads(store.get_meta("geo_zones", "[]") or "[]")
    except (ValueError, AttributeError):
        return []


def classify(lat, lon, zones):
    """The trusted zone a fix falls in, nearest first, or 'outside'."""
    best = None
    for z in zones:
        d = haversine_m(lat, lon, z["lat"], z["lon"])
        if d <= z.get("radius_m", 200) and (best is None or d < best[1]):
            best = (z["name"], d)
    return best[0] if best else "outside"


def current(store):
    try:
        return json.loads(store.get_meta("geo_current", "") or "null")
    except (ValueError, AttributeError):
        return None


def audit(store=None, hosts=("win",)):
    if "win" not in hosts or store is None:
        return []
    fix = locate()
    zones = get_zones(store)
    ts = now()
    record = {"ts": ts, "status": fix.get("status")}
    out = []
    if fix.get("status") == "ok":
        zone = classify(fix["lat"], fix["lon"], zones)
        # Overwrite-only: keep the current fix, not a track.
        record.update({"lat": fix["lat"], "lon": fix["lon"],
                       "accuracy_m": fix.get("accuracy_m"), "source": fix.get("source"),
                       "zone": zone})
        collection.succeeded("geo")
        if zones and zone == "outside":
            out.append(_finding(
                "geo", "low", "This device is outside every trusted zone",
                f"located to ~{int(fix.get('accuracy_m') or 0)} m accuracy, in none of "
                f"the {len(zones)} zones you marked trusted.", "geo"))
        else:
            out.append(_finding("geo", "ok", f"This device is in {zone}"
                                if zones else "Device location is available",
                                f"~{int(fix.get('accuracy_m') or 0)} m accuracy "
                                f"via {fix.get('source')}", "geo"))
    elif fix.get("status") == "denied":
        collection.failed("geo", "location permission off")
        record["zone"] = None
        out.append(_finding(
            "geo", "low", "JARVIS cannot verify this device's location",
            "Windows location permission is off, so GeoSecurity has no device "
            "position to reason about. Turn it on in Settings > Privacy & "
            "security > Location if you want geofencing and device-separation "
            "detection. JARVIS never guesses a position from your IP address.", "geo"))
    else:
        collection.failed("geo", fix.get("reason", "unavailable"))
        record["zone"] = None
        out.append(_finding("geo", "low", "Device location is unavailable",
                            str(fix.get("reason", ""))[:200], "geo"))
    store.set_meta("geo_current", json.dumps(record))
    store.commit()
    return out
