"""Install and elevated-path hardening (ARGUS-2026-003, 2026-10-30).

Every script that runs with administrator or root rights is checked for the
rules in ARCHYMEDES-SECURITY-STANDARD DEV-10 (command injection, path
traversal) and the install checklist: protected locations, verify-then-run
the same copy, no data in code, absolute tool paths, private temporary files,
and guarded removal. The checks parse the shipped scripts; the elevated
bootstrap is exercised through the real CLI code with the Windows side mocked,
and parsed by Windows PowerShell when it is reachable (parse only, nothing runs).
"""
import base64
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.cli.commands import broker as cli
from jarvis.core.paths import REPO_ROOT

WIN = REPO_ROOT / "jarvis" / "platform" / "win"
BROKER = REPO_ROOT / "jarvis-elevated-broker.ps1"
VAULT = WIN / "vault.ps1"
SENSOR = REPO_ROOT / "windows-sensor" / "install.ps1"
ISOLATED = REPO_ROOT / "windows-sensor" / "install-isolated.ps1"
SYSMON_APPLY = REPO_ROOT / "scripts" / "repair" / "apply-jarvis-sysmon-policy.ps1"
BROKER_JOBS = ["posture.ps1", "memscan.ps1", "internetwatch.ps1", "sysmon_policy.ps1",
               "sysmon_pressure.ps1", "vault.ps1", "inputaudit.ps1", "hp_firmware_audit.ps1"]
ELEVATED = [BROKER, SENSOR, ISOLATED, SYSMON_APPLY] + [WIN / n for n in BROKER_JOBS]
SERVER = REPO_ROOT / "release" / "server"
STAGE = r"C:\Users\o'brien\AppData\Local\Temp\jarvis-broker-0f8c1a2e"


def code(path):
    """Script text without comment lines (comments may name what they forbid)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith("#"))


def run_elevated(args=("-Install",), files=None, entry=None):
    """Drive the real CLI path with the Windows side mocked; -> (result, outer script)."""
    seen = {}

    def fake_run(argv, **_):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "", "")

    with mock.patch.object(cli.win, "_PS", "powershell.exe"), \
            mock.patch.object(cli.win, "available", return_value=True), \
            mock.patch.object(cli, "_make_stage", return_value=(STAGE, "")), \
            mock.patch.object(cli, "_winpath", side_effect=lambda p: r"\\wsl.localhost\U" + str(p)), \
            mock.patch.object(cli.subprocess, "run", side_effect=fake_run):
        if files is None:
            result = cli._elevated(list(args))
        else:
            result = cli._elevated_verified(files, entry, list(args), "jarvis-test")
    outer = base64.b64decode(seen["argv"][-1]).decode("utf-16le") if "argv" in seen else ""
    return result, outer


def bootstrap_of(outer):
    m = re.search(r"\$b = @'\n(.*?)\n'@\n", outer, re.S)
    return m.group(1) if m else ""


class NoDataInCodeTests(unittest.TestCase):
    def test_elevated_scripts_never_evaluate_strings(self):
        for path in ELEVATED:
            text = code(path)
            for bad in (r"\bInvoke-Expression\b", r"\biex\b", r"ScriptBlock\]::Create",
                        r"\.InvokeScript\(", r"NewScriptBlock"):
                self.assertIsNone(re.search(bad, text, re.I), f"{path.name}: {bad}")

    def test_literals_escape_every_powershell_quote(self):
        for quote in ("'", "\u2018", "\u2019", "\u201a", "\u201b"):
            lit = cli._ps_literal(f"a{quote}; Start-Process calc; {quote}")
            self.assertTrue(lit.startswith("'") and lit.endswith("'"))
            body = lit[1:-1]
            # Every quote character inside is doubled, so none can close the string.
            self.assertNotRegex(body.replace(quote * 2, ""), "['\u2018\u2019\u201a\u201b]")
        for bad in ("a\nb", "a\rb", "a\0b"):
            with self.assertRaises(ValueError):
                cli._ps_literal(bad)

    def test_bootstrap_rejects_names_and_digests_that_are_not_data(self):
        ok = "0" * 64
        with self.assertRaises(ValueError):
            cli._bootstrap(STAGE, {"a'.ps1": ok}, "a'.ps1", [])
        with self.assertRaises(ValueError):
            cli._bootstrap(STAGE, {"a.ps1": "abc"}, "a.ps1", [])
        with self.assertRaises(ValueError):
            cli._bootstrap(STAGE, {"a.ps1": ok}, "b.ps1", [])   # entry must be verified
        boot = cli._bootstrap(STAGE, {"a.ps1": ok}, "a.ps1", ["-X", "it's"])
        self.assertIn("$src = 'C:\\Users\\o''brien\\", boot)
        self.assertIn("@('-X', 'it''s')", boot)


class VerifiedElevationTests(unittest.TestCase):
    def test_broker_install_runs_only_verified_protected_copies(self):
        (code_, _), outer = run_elevated(["-Install"])
        self.assertEqual(code_, 0)
        boot = bootstrap_of(outer)
        self.assertTrue(boot, "the bootstrap travels as a here-string")
        # The elevated process is started from System32 by absolute path and
        # given code, never a file in the user's TEMP stage.
        start = outer[outer.index("Start-Process"):]
        self.assertIn("[Environment]::SystemDirectory", start.split("-Verb")[0])
        self.assertIn("'-EncodedCommand',$e", start)
        self.assertNotIn("'-File'", start.split("$e")[0])
        # Every staged file is pinned to the digest of the checkout copy.
        for name in ["jarvis-elevated-broker.ps1"] + BROKER_JOBS:
            path = BROKER if name == BROKER.name else WIN / name
            digest = cli.hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertIn(f"'{name}' = '{digest}'", boot)
        # The protected folder is created with its ACL in the same call, the
        # copies are hashed there, and only those copies run.
        create = boot.index("[IO.Directory]::CreateDirectory($dst, $sec)")
        copy = boot.index("Copy-Item -LiteralPath (Join-Path $src $name) -Destination $to")
        check = boot.index("Get-FileHash -Algorithm SHA256 -LiteralPath $to")
        run = boot.index("-File (Join-Path $dst $entry)")
        self.assertLess(create, copy)
        self.assertLess(copy, check)
        self.assertLess(check, run)
        self.assertIn("SetAccessRuleProtection($true, $false)", boot)
        self.assertNotIn("S-1-5-32-545", boot)        # Users get nothing
        self.assertIn("@('-Install', '-Source', '{stage}')", boot)
        self.assertNotIn("$env:TEMP", boot)

    def test_a_changed_checkout_file_changes_the_pinned_digest(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        entry = tmp / "apply.ps1"
        entry.write_text("Write-Output 1\n")
        _, before = run_elevated(["-PolicyPath", "{stage}\\p.xml"], {"apply.ps1": entry}, "apply.ps1")
        entry.write_text("Write-Output 2\n")
        _, after = run_elevated(["-PolicyPath", "{stage}\\p.xml"], {"apply.ps1": entry}, "apply.ps1")
        self.assertNotEqual(bootstrap_of(before), bootstrap_of(after))

    def test_unsafe_names_are_refused_before_anything_runs(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        (tmp / "x").write_text("1")
        (code_, why), outer = run_elevated([], {"x'; calc; '": tmp / "x"}, "x'; calc; '")
        self.assertEqual(code_, 1)
        self.assertIn("refused", why)
        self.assertEqual(outer, "")

    def test_command_line_stays_well_under_the_windows_limit(self):
        with mock.patch.object(cli.win, "_PS", "powershell.exe"):
            _, outer = run_elevated(["-Install", "-EnableFirewallLogging"])
            argv = cli._ps_args(outer.split(";", 1)[1])
        self.assertLess(len(" ".join(argv)), 24000)


class BrokerScriptTests(unittest.TestCase):
    def setUp(self):
        self.code = code(BROKER)

    def test_paths_come_from_the_os_not_the_user_environment(self):
        self.assertIn("$Sys32 = [Environment]::SystemDirectory", self.code)
        for var in ("ProgramData", "SystemRoot", "TEMP", "LOCALAPPDATA", "windir"):
            for use in re.finditer(rf"\$env:{var}\b", self.code, re.I):
                line = self.code[self.code.rfind("\n", 0, use.start()) + 1:self.code.find("\n", use.end())]
                self.assertRegex(line.strip(), rf"^\$env:{var}\s*=", f"read of $env:{var}: {line}")

    def test_module_path_and_temp_are_reset_before_jobs_run(self):
        self.assertIn("$env:PSModulePath = (Join-Path $Sys32", self.code)
        run = self.code.index("if ($Run) {")
        self.assertLess(self.code.index("$env:TEMP = $Tmp"), self.code.index("Start-Process", run))
        self.assertLess(self.code.index("$env:TMP = $Tmp"), self.code.index("Start-Process", run))

    def test_only_the_protected_copy_runs_jobs(self):
        run = self.code[self.code.index("if ($Run) {"):]
        guard = run.index("$PSCommandPath")
        self.assertLess(guard, run.index("Start-Process"))
        self.assertIn("Find-Untrusted $dir", run[:run.index("Start-Process")])

    def test_lock_replaces_owner_and_dacl_and_parent_is_locked(self):
        lock = self.code[self.code.index("function Lock-Folder"):self.code.index("function Find-Untrusted")]
        self.assertIn("SetOwner", lock)
        self.assertIn("SetAccessRuleProtection($true, $false)", lock)
        install = self.code[self.code.index("if ($Install) {"):]
        self.assertLess(install.index("Lock-Folder $JarvisDir"), install.index("Lock-Folder $Root"))
        self.assertLess(install.index("Find-Untrusted $Root -Recurse"), install.index("Copy-Item"))

    def test_untrusted_walk_never_follows_links(self):
        walk = self.code[self.code.index("function Find-Untrusted"):]
        walk = walk[:walk.index("\n}\n")]
        self.assertLess(walk.index("ReparsePoint"), walk.index("Get-ChildItem"))
        self.assertNotIn("-Recurse -Force", walk.replace("Find-Untrusted $child.FullName -Recurse", ""))


class ToolPathTests(unittest.TestCase):
    def test_elevated_scripts_call_system_tools_by_absolute_path(self):
        bare = re.compile(r"&\s+['\"]?(icacls|sc|secedit|wevtutil|reg|logman|schtasks|netsh|cmd|powershell)\.exe\b",
                          re.I)
        for path in ELEVATED:
            self.assertIsNone(bare.search(code(path)), path.name)

    def test_scheduled_task_actions_name_their_program_absolutely(self):
        for path in [BROKER, ISOLATED]:
            for m in re.finditer(r"New-ScheduledTaskAction -Execute ([^\s]+)", code(path)):
                self.assertNotIn(m.group(1).strip("'\""), ("powershell.exe", "conhost.exe"), path.name)

    def test_elevated_installers_do_not_resolve_folders_from_environment(self):
        for path in [SENSOR, ISOLATED, SYSMON_APPLY, VAULT, WIN / "inputaudit.ps1"]:
            text = code(path)
            for var in ("ProgramData", "ProgramFiles", "WINDIR", "SystemRoot"):
                self.assertNotRegex(text, rf"\$env:{var}\b", f"{path.name}: $env:{var}")


class TempFileTests(unittest.TestCase):
    def test_policy_files_are_never_written_in_the_users_temp(self):
        for path in [SENSOR, ISOLATED]:
            text = code(path)
            rights = text[text.index("function Grant-LogonAsService"):]
            rights = rights[:rights.index("\n}\n")]
            self.assertIn("New-AdminOnlyDirectory", rights, path.name)
            self.assertNotIn("$env:TEMP", rights, path.name)
            helper = text[text.index("function New-AdminOnlyDirectory"):]
            helper = helper[:helper.index("\n}\n")]
            self.assertIn("[IO.Directory]::CreateDirectory($path, $sec)", helper)
            self.assertIn("SetAccessRuleProtection($true, $false)", helper)
            self.assertNotIn("S-1-5-32-545", helper)

    def test_spool_folders_are_owned_by_administrators(self):
        text = code(SENSOR)
        grant = text[text.index("function Grant-Folder"):]
        grant = grant[:grant.index("\n}\n")]
        self.assertLess(grant.index("/setowner '*S-1-5-32-544'"), grant.index("/inheritance:r"))
        for path in [VAULT, SYSMON_APPLY]:
            lock = code(path)
            lock = lock[lock.index("function Lock-Folder"):]
            self.assertIn("/setowner '*S-1-5-32-544'", lock[:lock.index("\n}\n")], path.name)


class VaultInboxTests(unittest.TestCase):
    def setUp(self):
        self.code = code(VAULT)

    def test_inbox_files_are_read_only_through_a_checked_handle(self):
        opener = self.code[self.code.index("function Open-InboxFile"):]
        opener = opener[:opener.index("\n}\n")]
        self.assertIn("FinalPath($fs)", opener)
        self.assertIn("Links($fs) -ne 1", opener)
        self.assertIn("GetFinalPathNameByHandleW", self.code)
        # No inbox read bypasses it.
        self.assertNotIn("ReadAllBytes($inboxChain)", self.code)
        self.assertNotIn("Get-FileSha256 $source", self.code)
        self.assertNotIn("Get-FileSha256 $file.FullName", self.code)
        install = self.code[self.code.index("function Install-Copy"):]
        install = install[:install.index("\n}\n")]
        self.assertIn("Open-InboxFile $source", install)
        self.assertNotIn("Copy-Item", install)

    def test_a_missing_handle_type_fails_the_job_rather_than_reading_unchecked(self):
        self.assertIn('if ($HandleTypeError) { throw', self.code)


class LinuxServerScriptTests(unittest.TestCase):
    def test_uninstall_removes_only_fixed_product_paths(self):
        text = (SERVER / "uninstall.sh").read_text()
        self.assertIn("set -euo pipefail", text)
        for line in text.splitlines():
            if re.search(r"\brm\s+-[a-z]*r", line):
                self.assertNotIn("$", line, f"rm -r with a variable: {line}")
                for target in line.split()[2:]:
                    self.assertTrue(target.startswith("/") and target.count("/") >= 2, line)

    def test_install_runs_root_steps_from_root_owned_copies(self):
        text = (SERVER / "install.sh").read_text()
        self.assertIn("set -euo pipefail", text)
        self.assertIn("PREFIX=/opt/argus", text)
        self.assertNotRegex(text, r"curl[^\n|]*\|\s*(ba)?sh")
        self.assertNotIn("/tmp/", text)
        # The verification run uses the root-owned installed copy, not the
        # extracted archive.
        self.assertIn('"$PREFIX/bin/argus-server" -m argus.verify', text)
        for line in text.splitlines():
            if re.search(r"\brm\s+-rf", line):
                self.assertRegex(line, r'rm -rf "\$PREFIX/[a-z.]+"( "\$PREFIX/[a-z.]+")*;?')
        # The port reaches sed only after it is proven numeric.
        self.assertLess(text.index('case "$PORT" in'), text.index('sed -i "s/^ARGUS_PORT'))


@unittest.skipUnless(shutil.which("powershell.exe") and shutil.which("wslpath"),
                     "Windows PowerShell not reachable from here")
class WindowsParseTests(unittest.TestCase):
    """Parse only: [Parser]::ParseInput/ParseFile never runs the script."""

    def parse_errors(self, text):
        b64 = base64.b64encode(text.encode("utf-16le")).decode()
        cmd = ("$s=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('%s'));"
               "$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseInput("
               "$s,[ref]$t,[ref]$e);$e|ForEach-Object{$_.Extent.StartLineNumber.ToString()+': '+$_.Message}"
               % b64)
        res = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-"],
                             input=cmd, capture_output=True, text=True, timeout=120, cwd="/mnt/c")
        return res.stdout.replace("\r", "").strip()

    def test_changed_scripts_and_the_bootstrap_parse(self):
        _, outer = run_elevated(["-Install"])
        texts = {"outer": outer, "bootstrap": bootstrap_of(outer)}
        for path in ELEVATED:
            texts[path.name] = path.read_text(encoding="utf-8")
        broken = {name: err for name, text in texts.items() if (err := self.parse_errors(text))}
        self.assertEqual(broken, {})


if __name__ == "__main__":
    unittest.main()
