"""An elevated result is used only when it is fresh and from reviewed scripts."""

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from jarvis.cli.commands import broker as broker_cli
from jarvis.core.paths import REPO_ROOT, win_script
from jarvis.platform import broker


class BrokerResultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        os.makedirs(os.path.join(self.tmp, "out"))
        shutil.copy(REPO_ROOT / "jarvis-elevated-broker.ps1", self.tmp)
        for name in broker.SCRIPTS.values():
            shutil.copy(win_script(name), self.tmp)
        for attr, value in (("ROOT", self.tmp), ("OUT", os.path.join(self.tmp, "out"))):
            p = mock.patch.object(broker, attr, value)
            p.start()
            self.addCleanup(p.stop)

    def write(self, ok=True, ts=1000, data=None):
        with open(os.path.join(self.tmp, "out", "status.json"), "w") as fh:
            json.dump({"admin": True, "finished": ts, "jobs": {"memscan": {"ok": ok, "ts": ts, "error": "boom"}}}, fh)
        with open(os.path.join(self.tmp, "out", "memscan.b64"), "w") as fh:
            fh.write(base64.b64encode(json.dumps(data or {"memory": {"opened": 9}}).encode()).decode())

    def test_fresh_reviewed_result_is_used(self):
        self.write()
        self.assertEqual(broker.result("memscan", now=1100)[0], {"memory": {"opened": 9}})

    def test_stale_failed_or_modified_results_are_refused(self):
        self.write()
        self.assertIsNone(broker.result("memscan", now=1000 + broker.MAX_AGE + 1)[0])
        self.write(ok=False)
        self.assertIsNone(broker.result("memscan", now=1100)[0])
        self.write()
        with open(os.path.join(self.tmp, "memscan.ps1"), "a") as fh:
            fh.write("\nStart-Process evil.exe\n")
        data, why = broker.result("memscan", now=1100)
        self.assertIsNone(data)
        self.assertIn("differs", why)

    def test_not_installed(self):
        os.remove(os.path.join(self.tmp, "jarvis-elevated-broker.ps1"))
        self.assertIsNone(broker.result("memscan")[0])

    def test_failed_restage_cannot_pass_because_old_broker_exists(self):
        args = SimpleNamespace(action="install", firewall_logging=False)
        with mock.patch.object(broker_cli, "_elevated",
                               return_value=(1, "staging failed")), \
                mock.patch.object(broker, "installed", return_value=True), \
                mock.patch.object(broker, "drifted", return_value=[]):
            self.assertEqual(broker_cli.cmd_broker(args), 1)

    def _launched_inner(self, call):
        """The inline code the elevated shell would receive from `call`."""
        scripts = []
        self.cmdlines = []

        def fake_run(argv, **kw):
            self.cmdlines.append(sum(len(a or "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe") + 1 for a in argv))
            if "input" in kw:           # the elevated launch: script on stdin
                self.assertEqual(base64.b64decode(argv[-1]).decode("utf-16le"),
                                 "$ProgressPreference='SilentlyContinue';" + broker_cli.STDIN_BOOTSTRAP)
                scripts.append(kw["input"].decode("utf-8"))
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            scripts.append(base64.b64decode(argv[-1]).decode("utf-16le"))
            return subprocess.CompletedProcess(argv, 0, "C:\\Users\\u\\Temp\\jarvis-x\n", "")

        with mock.patch.object(broker_cli.win, "available", return_value=True), \
                mock.patch.object(broker_cli, "_winpath", side_effect=lambda p: "C:\\src\\" + p.name), \
                mock.patch.object(broker_cli.subprocess, "run", side_effect=fake_run):
            call()
        outer = scripts[-1]
        self.assertNotIn("'-File'", outer)
        encoded = re.search(r"'-EncodedCommand','([A-Za-z0-9+/=]+)'", outer).group(1)
        return base64.b64decode(encoded).decode("utf-16le")

    def test_elevated_broker_runs_only_its_checked_copy(self):
        inner = self._launched_inner(lambda: broker_cli._elevated(["-Install"]))
        names = [broker.BROKER_SCRIPT] + list(broker.SCRIPTS.values())
        for n in names:
            src = (broker_cli.REPO_ROOT if n == broker.BROKER_SCRIPT else broker_cli.WIN_SCRIPTS_DIR) / n
            self.assertIn(hashlib.sha256(src.read_bytes()).hexdigest(), inner, n)
        call = inner[inner.index(f"& (Join-Path $t '{broker.BROKER_SCRIPT}')"):]
        self.assertIn("-Install", call)
        self.assertIn("-Source $t", call)

    def test_install_command_line_fits_windows_limit(self):
        # 2026-10-31: the inline install reached 35,309 characters and WSL
        # refused it as "Invalid argument" before any UAC prompt appeared.
        with mock.patch.object(broker_cli.win, "_PS", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"):
            self._launched_inner(lambda: broker_cli._elevated(["-Install"]))
        self.assertTrue(self.cmdlines)
        self.assertLess(max(self.cmdlines), 2000)
        self.assertLess(max(self.cmdlines), broker_cli.WINDOWS_CMDLINE_MAX)

    def test_launch_failure_is_reported_not_raised(self):
        with mock.patch.object(broker_cli.win, "available", return_value=True), \
                mock.patch.object(broker_cli, "_make_stage", return_value=("C:\\T\\s", "")), \
                mock.patch.object(broker_cli, "_winpath", side_effect=lambda p: "C:\\src\\" + p.name), \
                mock.patch.object(broker_cli.subprocess, "run", side_effect=OSError(22, "Invalid argument")):
            code, out = broker_cli._elevated(["-Install"])
        self.assertEqual(code, 1)
        self.assertIn("could not start PowerShell", out)

    def test_sysmon_baseline_points_at_the_checked_policy(self):
        inner = self._launched_inner(broker_cli._sysmon_baseline)
        self.assertIn("-PolicyPath (Join-Path $t 'baseline.xml')", inner)

    def test_powershell_commands_are_encoded_for_wsl_interop(self):
        with mock.patch.object(broker_cli.win, "_PS", "powershell.exe"):
            args = broker_cli._ps_args("$x='quoted value'; $x")
        self.assertEqual(args[:3],
                         ["powershell.exe", "-NoProfile", "-NonInteractive"])
        # The script arrives intact, after the progress-silencing preamble.
        self.assertEqual(base64.b64decode(args[-1]).decode("utf-16le"),
                         "$ProgressPreference='SilentlyContinue';$x='quoted value'; $x")
