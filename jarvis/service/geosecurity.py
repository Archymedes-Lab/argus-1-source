"""GeoSecurity state: fuse location signals, hold trusted zones, feed the globe.

The browser view (`/geo`) is the face of this, but the security value is the
fusion: a position is trusted only as far as the independent signals agree, so
spoofing one source does not convince JARVIS. Confidence is built only from
signals JARVIS actually has — a native fix and its accuracy, whether it lands
in a user-declared zone, and how fresh it is. There is no paired-phone or
BLE-proximity input yet, so that part of the design contributes nothing rather
than a fabricated 0.98.

Anomalies follow the same honesty: device-separation needs a second trusted
device JARVIS does not have, so it is not raised. What can be raised truthfully
is raised — being geo-blind, or sitting outside every trusted zone while
high-severity security findings are active.

Imagery is environmental context, labelled for what it is (NASA GIBS daily
true-color), never called "live". No position marker is shown unless there is a
real fix or a user-asserted home zone to center on.
"""

import json

from jarvis.collectors.host import geo
from jarvis.core.util import now

# NASA GIBS: public, no token, global. Daily true-color; honest about cadence.
IMAGERY = {
    "provider": "NASA GIBS",
    "layer": "MODIS_Terra_CorrectedReflectance_TrueColor",
    "tile_matrix_set": "GoogleMapsCompatible_Level9",
    "format": "image/jpeg",
    "max_level": 9,
    "endpoint": "https://gibs.earthdata.nasa.gov/wmts/epsg3857/best/wmts.cgi",
    "attribution": "Imagery courtesy NASA EOSDIS GIBS",
    "cadence": "daily true-color, not live",
}


def get_zones(store):
    return geo.get_zones(store)


def set_zones(store, zones):
    store.set_meta("geo_zones", json.dumps(zones))
    store.commit()


def add_zone(store, name, lat, lon, radius_m=200):
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise ValueError("latitude/longitude out of range")
    zones = [z for z in get_zones(store) if z["name"] != name]
    zones.append({"name": name, "lat": float(lat), "lon": float(lon),
                  "radius_m": max(20, int(radius_m))})
    set_zones(store, zones)
    return zones


def remove_zone(store, name):
    set_zones(store, [z for z in get_zones(store) if z["name"] != name])


def fusion(store, geo_current):
    """Position confidence from the signals actually available. -> {score, signals}."""
    signals = []
    status = (geo_current or {}).get("status")
    if status == "ok":
        acc = geo_current.get("accuracy_m") or 9999
        # A tight native fix is strong evidence; a loose one much less.
        w = 0.9 if acc <= 50 else 0.75 if acc <= 500 else 0.5 if acc <= 5000 else 0.3
        signals.append(("native GNSS/Wi-Fi fix", round(w, 2)))
        if geo_current.get("zone") and geo_current["zone"] != "outside":
            signals.append(("inside a user-declared trusted zone", 0.85))
        age = now() - (geo_current.get("ts") or 0)
        if age > 3600:
            signals.append(("fix is stale", 0.3))
    elif status == "denied":
        signals.append(("location permission off — no position", 0.0))
    else:
        signals.append(("no position available", 0.0))
    # Combine as noisy-OR over independent signals (weak signals still can't
    # manufacture certainty; one strong signal dominates honestly).
    product = 1.0
    for _, w in signals:
        product *= (1 - max(0.0, min(1.0, w)))
    score = round(1 - product, 2) if signals else 0.0
    return {"score": score, "signals": [{"name": n, "weight": w} for n, w in signals]}


def _devices(store, geo_current, health_state):
    """Only devices JARVIS actually knows. This machine; no fabricated phone/watch."""
    trusted = bool((health_state or {}).get("healthy"))
    this = {"name": "this device", "kind": "workstation",
            "trust": "trusted" if trusted else "degraded",
            "located": (geo_current or {}).get("status") == "ok",
            "zone": (geo_current or {}).get("zone")}
    return [this]


def anomalies(store, geo_current, recent_findings):
    """Truthfully raisable geo anomalies only."""
    out = []
    status = (geo_current or {}).get("status")
    zones = get_zones(store)
    if status == "denied":
        out.append({"kind": "geo_blind", "severity": "low",
                    "detail": "Location is off; JARVIS cannot detect device movement or theft."})
    hot = [f for f in (recent_findings or []) if f.get("severity") in ("critical", "high")]
    if status == "ok" and zones and geo_current.get("zone") == "outside" and hot:
        out.append({"kind": "outside_zone_with_activity", "severity": "high",
                    "detail": f"This device is outside every trusted zone while "
                              f"{len(hot)} high-severity finding(s) are active — review "
                              f"whether it is where you expect."})
    return out


def imagery(geo_current):
    """Imagery config for the globe, and where to center it (honestly)."""
    center = None
    if (geo_current or {}).get("status") == "ok":
        center = {"lat": geo_current["lat"], "lon": geo_current["lon"],
                  "source": "device fix"}
    return {**IMAGERY, "center": center}


def state(store, health_state=None, recent_findings=None):
    """The full payload the /geo view renders."""
    geo_current = geo.current(store)
    zones = get_zones(store)
    # If there is no fix but a home zone exists, center there — user-asserted,
    # not a guessed position, and marked as such.
    img = imagery(geo_current)
    if img["center"] is None and zones:
        home = next((z for z in zones if z["name"].upper() == "HOME"), zones[0])
        img["center"] = {"lat": home["lat"], "lon": home["lon"], "source": "home zone"}
    return {
        "location": geo_current or {"status": "unknown"},
        "confidence": fusion(store, geo_current),
        "zones": zones,
        "devices": _devices(store, geo_current, health_state),
        "anomalies": anomalies(store, geo_current, recent_findings),
        "imagery": img,
        "generated_at": now(),
    }
