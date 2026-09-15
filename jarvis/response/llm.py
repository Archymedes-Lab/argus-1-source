"""The one door to the local language model.

Everything that asks Ollama for text — the dashboard assistant, the email
narrator — goes through `chat`, so they share the transport, the loopback
bridge and a single lock. CPU inference serves one request at a time; letting
callers race only queues them inside Ollama while each holds a thread.

The model is advisory by construction: this returns text, never a tool call,
and callers decide what that text is allowed to become.
"""

import base64
import json
import threading
import urllib.error
import urllib.request

from jarvis.platform.windows import ps_json

DEFAULT_MODEL = "llama3.2:1b"
DEFAULT_URL = "http://127.0.0.1:11434"
BUSY = "busy"

LOCK = threading.Lock()


def model_name(conf):
    return (conf.get("ollama_model") or DEFAULT_MODEL).strip()


def _bridge(body, timeout):
    """POST through Windows PowerShell when Ollama is on Windows loopback.

    WSL's loopback is separate on NAT-based installs, and Ollama deliberately
    listens only on Windows loopback, so cross that boundary through the
    existing PowerShell bridge instead of exposing Ollama to the LAN.
    """
    blob = base64.b64encode(body).decode("ascii")
    script = (
        "$ErrorActionPreference='Stop';"
        f"$b=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{blob}'));"
        "try{$r=Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/chat' "
        f"-Method Post -ContentType 'application/json' -Body $b -TimeoutSec {int(timeout)};"
        "$j=$r|ConvertTo-Json -Depth 10 -Compress}"
        "catch{$j=@{_jarvis_error=[string]$_.Exception.Message}|ConvertTo-Json -Compress};"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))")
    return ps_json(script, timeout=timeout + 10)


def _request(conf, body, timeout):
    base = (conf.get("ollama_url") or DEFAULT_URL).rstrip("/")
    req = urllib.request.Request(base + "/api/chat", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace")), None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        if base not in ("http://127.0.0.1:11434", "http://localhost:11434"):
            return None, exc
        data = _bridge(body, timeout)
        if isinstance(data, dict) and data.get("_jarvis_error"):
            return None, data["_jarvis_error"]
        return data, (None if data is not None else exc)


def chat(conf, system, user, *, examples=(), model="", num_predict=110, temperature=0.2,
         timeout=90, wait=0.0):
    """-> (text, error). `error` is "" on success, BUSY when the model is taken.

    `examples` are (user, assistant) turns shown before the real request; small
    models imitate a demonstrated exchange far more faithfully than a described
    one. `wait` is how long to queue for the model: 0 for interactive callers
    that should answer "busy" at once, longer for background work.
    """
    messages = [{"role": "system", "content": system}]
    for asked, answered in examples:
        messages += [{"role": "user", "content": asked},
                     {"role": "assistant", "content": answered}]
    messages.append({"role": "user", "content": user})
    acquired = LOCK.acquire(timeout=wait) if wait > 0 else LOCK.acquire(blocking=False)
    if not acquired:
        return "", BUSY
    try:
        body = json.dumps({
            "model": model or model_name(conf), "stream": False, "keep_alive": "5m",
            "options": {"temperature": temperature, "num_ctx": 2048,
                        "num_predict": num_predict},
            "messages": messages,
        }).encode()
        data, error = _request(conf, body, timeout)
    finally:
        LOCK.release()
    if isinstance(data, dict):
        text = str((data.get("message") or {}).get("content") or "").strip()
        return (text, "") if text else ("", "the local model returned no answer")
    return "", str(error or "the local model returned an invalid response")
