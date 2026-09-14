"""Bounded local connection history and application exposure monitoring.

Socket samples miss short connections. Listener matching suggests inbound
direction; it does not prove it. No packet payloads or command lines persist.
"""

import ipaddress
import json
import re
import time

from . import collect_linux
from .control import _ps_json

PS_SAMPLE = r"""
$ErrorActionPreference = 'Stop'
$o = @{errors=@(); connections=@(); apps=@(); profiles=@(); logs=@(); browserPolicies=@()}
try {
  $o.connections = @(Get-NetTCPConnection | Where-Object { $_.State -in 'Listen','Established' } |
    ForEach-Object { @{pid=[int]$_.OwningProcess; proto='tcp'; local_ip=[string]$_.LocalAddress;
      local_port=[int]$_.LocalPort; remote_ip=[string]$_.RemoteAddress;
      remote_port=[int]$_.RemotePort; state=([string]$_.State).ToUpperInvariant()} })
} catch { $o.errors += 'TCP socket inventory unavailable' }
try {
  $o.connections += @(Get-NetUDPEndpoint | ForEach-Object {
    @{pid=[int]$_.OwningProcess; proto='udp'; local_ip=[string]$_.LocalAddress;
      local_port=[int]$_.LocalPort; remote_ip=''; remote_port=0; state='BOUND'} })
} catch { $o.errors += 'UDP endpoint inventory unavailable' }
try {
  $ids = @($o.connections | ForEach-Object { $_.pid } | Sort-Object -Unique)
  $o.apps = @(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -in $ids } |
    ForEach-Object {
      $flags = @([regex]::Matches([string]$_.CommandLine,
        '(?i)(?:^|\s)(--(?:no-sandbox|disable-web-security|ignore-certificate-errors|remote-debugging-port)(?:=\S+)?)') |
        ForEach-Object { ($_.Groups[1].Value -split '=')[0] } | Sort-Object -Unique)
      @{pid=[int]$_.ProcessId; name=[string]$_.Name; exe=[string]$_.ExecutablePath; flags=$flags}
    })
} catch { $o.errors += 'Application attribution unavailable' }
$specs = @(
  @{app='chrome.exe'; path='Software\Policies\Google\Chrome'; keys=@('SafeBrowsingProtectionLevel','PasswordLeakDetectionEnabled')},
  @{app='brave.exe'; path='Software\Policies\BraveSoftware\Brave'; keys=@('SafeBrowsingProtectionLevel','PasswordLeakDetectionEnabled')},
  @{app='msedge.exe'; path='Software\Policies\Microsoft\Edge'; keys=@('SmartScreenEnabled','SmartScreenPuaEnabled')}
)
foreach ($spec in $specs) {
  if (@($o.apps | Where-Object { $_.name -eq $spec.app }).Count -eq 0) { continue }
  foreach ($hive in @('HKLM:', 'HKCU:')) {
    foreach ($suffix in @('', '\Recommended')) {
      $path = $hive + '\' + $spec.path + $suffix
      foreach ($key in $spec.keys) {
        $value = Get-ItemProperty -LiteralPath $path -Name $key -ErrorAction SilentlyContinue
        if ($null -ne $value) {
          $o.browserPolicies += @{app=$spec.app; key=$key; value=$value.$key; source=$path}
        }
      }
    }
  }
}
try {
  $profiles = @(Get-NetFirewallProfile)
  $o.profiles = @($profiles | ForEach-Object {
    @{name=[string]$_.Name; enabled=[bool]$_.Enabled; blocked=[bool]$_.LogBlocked; allowed=[bool]$_.LogAllowed}
  })
  foreach ($path in @($profiles.LogFileName | Sort-Object -Unique)) {
    try {
      $path = [Environment]::ExpandEnvironmentVariables($path)
      $head = @(Get-Content -LiteralPath $path -TotalCount 30 | ForEach-Object { $_.ToString() })
      $fields = @($head | Where-Object { $_ -like '#Fields:*' } | Select-Object -Last 1)
      $tail = @(Get-Content -LiteralPath $path -Tail 1000 | ForEach-Object { $_.ToString() })
      $o.logs += @{fields=($fields -join ''); lines=$tail; capped=($tail.Count -ge 1000)}
    } catch { $o.errors += 'Firewall traffic log unreadable' }
  }
} catch { $o.errors += 'Firewall logging configuration unavailable' }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 6 -Compress)))
"""


def finding(host, severity, title, detail, where='', category='internet'):
    return dict(host=host, severity=severity, title=title, detail=detail,
                where=where, category=category)


def scope(address):
    try:
        ip = ipaddress.ip_address(address.split('%')[0])
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped
        if ip.is_loopback:
            return 'loopback'
        if ip.is_unspecified:
            return 'wildcard'
        return 'public' if ip.is_global else 'local'
    except (ValueError, AttributeError):
        return 'unknown'


def firewall_summary(log):
    """Summarize a bounded tail, not a cumulative or interval packet count."""
    def log_text(value):
        # Windows PowerShell may serialize Get-Content's extended strings as
        # objects with a value property and provider metadata.
        if isinstance(value, dict):
            value = value.get('value')
        if not isinstance(value, str):
            raise ValueError('Firewall traffic log contains non-text data')
        return value

    fields = log_text(log.get('fields', '')).removeprefix('#Fields:').split()
    if not {'action', 'path'}.issubset(fields):
        raise ValueError('Firewall traffic log field header is missing or invalid')
    totals = {'allow': 0, 'drop': 0, 'inbound': 0}
    lines = log.get('lines', [])
    if not isinstance(lines, list):
        raise ValueError('Firewall traffic log lines are not an array')
    for line in lines:
        line = log_text(line)
        if line.startswith('#'):
            continue
        row = dict(zip(fields, line.split()))
        action = row.get('action', '').lower()
        if action in ('allow', 'drop'):
            totals[action] += 1
            if row.get('path', '').upper() == 'RECEIVE':
                totals['inbound'] += 1
    return totals


def analyze(host, data):
    out, records = [], []
    apps = {p['pid']: p for p in data.get('apps', [])}
    listeners = [c for c in data.get('connections', []) if c.get('state') == 'LISTEN']
    for c in data.get('connections', []):
        app = apps.get(c.get('pid'), {})
        row = {k: c.get(k) for k in ('pid', 'proto', 'local_ip', 'local_port',
                                     'remote_ip', 'remote_port', 'state')}
        row.update(name=app.get('name', 'unknown'), exe=app.get('exe', ''))
        inbound = c.get('proto') == 'tcp' and c.get('state') == 'ESTABLISHED' and any(
            l.get('proto') == 'tcp' and l.get('pid') == c.get('pid') and l.get('local_port') == c.get('local_port')
            and (scope(l.get('local_ip', '')) == 'wildcard'
                 or l.get('local_ip') == c.get('local_ip')) for l in listeners)
        row['direction'] = 'likely inbound' if inbound else 'unknown'
        records.append(row)
        exposed = c.get('state') == 'LISTEN' and scope(c.get('local_ip', '')) not in ('loopback', 'unknown')
        if exposed or (inbound and scope(c.get('remote_ip', '')) not in ('loopback', 'unknown')):
            out.append(finding(host, 'high' if inbound and scope(c['remote_ip']) == 'public' else 'medium',
                'likely inbound connection' if inbound else 'application listening beyond loopback',
                f"{row['name']} PID {c.get('pid')}: {c.get('local_ip')}:{c.get('local_port')}"
                + (f" from {c.get('remote_ip')}:{c.get('remote_port')}; direction inferred from matching listener" if inbound
                   else '; reachability still depends on firewall and network routing'), row['exe']))
    for app in apps.values():
        for flag in app.get('flags', []):
            out.append(finding(host, 'medium' if flag == '--remote-debugging-port' else 'high',
                'application security bypass flag', f"{app.get('name')} uses {flag}; review its launch configuration",
                app.get('exe', '')))
    for policy in data.get('browserPolicies', []):
        if policy.get('value') == 0:
            out.append(finding(host, 'high', 'browser policy requests disabled protection',
                f"{policy['app']}: {policy['key']}=0; registry value observed, effective policy precedence must be checked in the browser",
                policy.get('source', '')))
    for error in data.get('errors', []):
        out.append(finding(host, 'medium', 'traffic monitoring visibility limited', error, category='visibility'))
    for p in data.get('profiles', []):
        if not p.get('enabled') or not p.get('blocked') or not p.get('allowed'):
            out.append(finding(host, 'high' if not p.get('enabled') else 'medium',
                'firewall protection or traffic logging incomplete',
                f"{p['name']}: enabled={p.get('enabled')}, log blocked={p.get('blocked')}, log allowed={p.get('allowed')}",
                category='visibility'))
    for log in data.get('logs', []):
        try:
            totals = firewall_summary(log)
        except ValueError as exc:
            error = str(exc)
            data.setdefault('errors', []).append(error)
            out.append(finding(host, 'medium', 'traffic monitoring visibility limited',
                               error, category='visibility'))
            continue
        out.append(finding(host, 'low', 'firewall traffic log tail',
            f"{totals['allow']} allowed, {totals['drop']} dropped, {totals['inbound']} marked inbound; "
            f"last up to 1000 lines, overlapping samples; tail limit reached={bool(log.get('capped'))}"))
    attributed = {r['pid'] for r in records if r['pid'] in apps}
    out.append(finding(host, 'low', 'network application inventory',
        f"{len(attributed)} attributed network apps, {len(records)} sampled TCP connections and UDP endpoints; "
        'short-lived traffic can be missed; UDP direction is not inferred'))
    return out, records


def audit(store, hosts=('wsl', 'win')):
    out = []
    for host in hosts:
        attempted = time.time()
        if host == 'win':
            data = _ps_json(PS_SAMPLE, timeout=30)
            if not data:
                out.append(finding(host, 'high', 'Windows traffic collector is failing',
                    'Windows query unavailable; no fresh traffic or browser state collected', category='collectors'))
                store.set_meta(f'internetwatch_status_v1_{host}', json.dumps({
                    'attempted': attempted, 'status': 'unavailable', 'errors': ['Windows query unavailable']}))
                continue
        else:
            procs = collect_linux.collect()
            data = {'apps': [], 'connections': []}
            for p in procs:
                flags = sorted(set(re.findall(
                    r'(?:^|\s)(--(?:no-sandbox|disable-web-security|ignore-certificate-errors|remote-debugging-port))(?==|\s|$)',
                    p.get('cmdline', ''))))
                data['apps'].append(dict(pid=p['pid'], name=p['name'], exe=p['exe'], flags=flags))
                data['connections'].extend(dict(c, pid=p['pid']) for c in p['conns'])
        findings, rows = analyze(host, data)
        out.extend(findings)
        errors = data.get('errors', [])
        status = 'partial' if errors else 'sampled'
        socket_failure = 'TCP socket inventory unavailable' in errors
        store.set_meta(f'internetwatch_status_v1_{host}', json.dumps({
            'attempted': attempted, 'status': 'unavailable' if socket_failure else status, 'errors': errors}))
        if socket_failure:
            # An empty failed query must not erase the last known socket view.
            continue
        key = f'internetwatch_history_v1_{host}'
        try:
            history = json.loads(store.get_meta(key, '[]'))
            if not isinstance(history, list):
                history = []
        except (ValueError, TypeError):
            history = []
        history.append({'ts': attempted, 'connections': rows[:2000], 'truncated': len(rows) > 2000,
                        'status': status})
        store.set_meta(key, json.dumps(history[-60:]))
    return out


def latest(store):
    result = {}
    for host in ('wsl', 'win'):
        try:
            history = json.loads(store.get_meta(f'internetwatch_history_v1_{host}', '[]'))
            if isinstance(history, list) and history:
                result[host] = history[-1]
            status = json.loads(store.get_meta(f'internetwatch_status_v1_{host}', '{}'))
            if isinstance(status, dict) and status:
                result.setdefault(host, {}).update(status)
        except (ValueError, TypeError):
            pass
    return result
