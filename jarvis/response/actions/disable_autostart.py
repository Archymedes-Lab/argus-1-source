"""Disable one suspicious Windows autostart entry and retain its undo data."""

import base64
import json

from jarvis.platform.windows import ps_json

from .base import AUTO, Action, register


def _blob(target):
    return base64.b64encode(json.dumps(target).encode("utf-8")).decode("ascii")


@register
class DisableAutostart(Action):
    id = "disable_autostart"
    title = "Disable a suspicious autostart entry"
    autonomy = AUTO
    reversible = True
    host = "win"
    enable_flag = "auto_disable_autostart"

    def match(self, finding, job):
        if job != "control" or (finding or {}).get("host") != "win":
            return None
        target = (finding or {}).get("response_target")
        if not isinstance(target, dict) or target.get("kind") not in ("task", "runkey"):
            return None
        if not target.get("name"):
            return None
        if target["kind"] == "task" and not target.get("path"):
            return None
        if target["kind"] == "runkey" and not str(target.get("key") or "").startswith(
                ("HKCU:\\", "HKLM:\\")):
            return None
        return target

    def auto_eligible(self, finding, job, target):
        return finding.get("severity") == "critical"

    def preview(self, target):
        if target["kind"] == "task":
            return (f"Disable scheduled task {target['path']}{target['name']} without deleting "
                    "its definition. Reversible.")
        return (f"Remove Run entry {target['name']} from {target['key']} after recording its "
                "value. Reversible.")

    def _run(self, script):
        return ps_json(script, timeout=30)

    def apply(self, target, case):
        blob = _blob(target)
        script = (
            "$ErrorActionPreference='Stop';"
            f"$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{blob}'))|ConvertFrom-Json;"
            "$ok=$false;$record=@{};$detail='';try{"
            "if($t.kind -eq 'task'){"
            "$x=Get-ScheduledTask -TaskPath $t.path -TaskName $t.name -ErrorAction Stop;"
            "$record=@{kind='task';name=$t.name;path=$t.path;wasEnabled=($x.State -ne 'Disabled')};"
            "Disable-ScheduledTask -TaskPath $t.path -TaskName $t.name|Out-Null;"
            "$ok=((Get-ScheduledTask -TaskPath $t.path -TaskName $t.name).State -eq 'Disabled');"
            "$detail='scheduled task disabled'"
            "}else{"
            "$item=Get-Item -LiteralPath $t.key -ErrorAction Stop;"
            "$value=$item.GetValue($t.name,$null,'DoNotExpandEnvironmentNames');"
            "if($null -eq $value){throw 'Run entry no longer exists'};"
            "$kind=[string]$item.GetValueKind($t.name);"
            "$record=@{kind='runkey';name=$t.name;key=$t.key;value=[string]$value;valueKind=$kind};"
            "Remove-ItemProperty -LiteralPath $t.key -Name $t.name -ErrorAction Stop;"
            "$ok=$null -eq (Get-Item -LiteralPath $t.key).GetValue($t.name,$null);"
            "$detail='Run entry disabled'"
            "}}catch{$detail=[string]$_;$ok=$false};"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
            "(@{ok=$ok;record=$record;detail=$detail}|ConvertTo-Json -Depth 5 -Compress)))")
        result = self._run(script)
        if isinstance(result, dict) and result.get("ok"):
            return True, result.get("record") or {}, str(result.get("detail") or "disabled")
        return False, {}, str((result or {}).get("detail") or "autostart could not be disabled")

    def undo(self, target, record):
        if not isinstance(record, dict) or record.get("kind") not in ("task", "runkey"):
            return False, "no valid undo record"
        blob = _blob(record)
        script = (
            "$ErrorActionPreference='Stop';"
            f"$r=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{blob}'))|ConvertFrom-Json;"
            "$ok=$false;$detail='';try{"
            "if($r.kind -eq 'task'){"
            "if($r.wasEnabled){Enable-ScheduledTask -TaskPath $r.path -TaskName $r.name|Out-Null};"
            "$ok=$true;$detail='scheduled task restored'"
            "}else{"
            "$pt=if($r.valueKind -eq 'ExpandString'){'ExpandString'}else{'String'};"
            "New-ItemProperty -LiteralPath $r.key -Name $r.name -Value $r.value "
            "-PropertyType $pt -Force|Out-Null;$ok=$true;$detail='Run entry restored'"
            "}}catch{$detail=[string]$_;$ok=$false};"
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
            "(@{ok=$ok;detail=$detail}|ConvertTo-Json -Compress)))")
        result = self._run(script)
        if isinstance(result, dict) and result.get("ok"):
            return True, str(result.get("detail") or "restored")
        return False, str((result or {}).get("detail") or "autostart could not be restored")
