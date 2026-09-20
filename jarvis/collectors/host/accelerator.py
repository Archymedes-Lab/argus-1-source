"""Read-only Windows accelerator and resident-model capability probe.

This inventories hardware and runtimes; it never installs packages, loads a
model, changes Ollama configuration, or treats a GPU as security authority.
The expensive native probe is cached for an hour and rides the existing
resource collector rather than adding another scheduler obligation.
"""

import json
import time

from jarvis.platform.windows import ps_json

META = "accelerator_probe_v1"
TTL = 3600

PS_PROBE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = @{gpus=@(); openvino=@{installed=$false; devices=@(); error=''}; ollama=@{reachable=$false; models=@()}; processes=@()}
$o.gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object {
  @{name=[string]$_.Name; driver=[string]$_.DriverVersion; adapter_ram=[long]$_.AdapterRAM;
    status=[string]$_.Status; pnp_id=[string]$_.PNPDeviceID}
})
$o.processes = @(Get-Process -Name ollama,msedge,chrome,brave -ErrorAction SilentlyContinue | ForEach-Object {
  @{name=[string]$_.ProcessName; pid=[int]$_.Id; rss_bytes=[long]$_.WorkingSet64;
    cpu_seconds=if ($null -eq $_.CPU) { 0 } else { [double]$_.CPU }}
})
try {
  $models = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/ps' -Method Get -TimeoutSec 3 -NoProxy
  $o.ollama = @{reachable=$true; models=@($models.models | ForEach-Object {
    @{name=[string]$_.name; size=[long]$_.size; size_vram=[long]$_.size_vram; expires_at=[string]$_.expires_at}
  })}
} catch {}
$py = Get-Command py.exe -ErrorAction SilentlyContinue
if ($py) {
  $code = "import json`ntry:`n from openvino import Core`n c=Core()`n print(json.dumps({'installed':True,'devices':list(c.available_devices),'error':''}))`nexcept ModuleNotFoundError:`n print(json.dumps({'installed':False,'devices':[],'error':''}))`nexcept Exception as e:`n print(json.dumps({'installed':True,'devices':[],'error':type(e).__name__+': '+str(e)[:160]}))"
  try { $o.openvino = (& $py.Source -3 -c $code 2>$null | Select-Object -Last 1 | ConvertFrom-Json) } catch {}
}
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 6 -Compress)))
"""


def latest(store):
    try:
        value = json.loads(store.get_meta(META, "{}") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def audit(store, hosts=("wsl", "win"), now=None):
    now = time.time() if now is None else now
    prior = latest(store)
    if prior and now - float(prior.get("at") or 0) < TTL:
        return [_finding(prior)]
    if "win" not in hosts:
        return []
    data = ps_json(PS_PROBE, timeout=20)
    if not isinstance(data, dict):
        return []
    state = {"at": now,
             "gpus": data.get("gpus") if isinstance(data.get("gpus"), list) else [],
             "openvino": data.get("openvino") if isinstance(data.get("openvino"), dict) else {},
             "ollama": data.get("ollama") if isinstance(data.get("ollama"), dict) else {},
             "processes": data.get("processes") if isinstance(data.get("processes"), list) else []}
    store.set_meta(META, json.dumps(state))
    store.commit()
    return [_finding(state)]


def _finding(state):
    gpus = state.get("gpus") or []
    ov = state.get("openvino") or {}
    names = ", ".join(str(g.get("name") or "unknown") for g in gpus) or "none detected"
    devices = [str(d) for d in (ov.get("devices") or [])]
    ready = any(d == "GPU" or d.startswith("GPU.") for d in devices)
    detail = (f"GPU: {names}. OpenVINO installed={bool(ov.get('installed'))}; "
              f"devices={', '.join(devices) or 'none'}. "
              f"Ollama reachable={bool((state.get('ollama') or {}).get('reachable'))}. "
              "Inventory only; no model was loaded and no backend was changed.")
    return {"host": "win", "category": "performance", "severity": "ok",
            "title": ("Intel GPU inference path is available" if ready else
                      "GPU inference capability inventoried"),
            "detail": detail, "where": "Windows accelerator probe"}
