"""The storage governor measures, names the command, and deletes only what
JARVIS reserved for deletion (docs/architecture/STORAGE-GOVERNOR.md)."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from jarvis.collectors.host import storage
from jarvis.core.store import Store

GIB = storage.GIB
NOW = 1_800_000_000.0


def host(**over):
    base = {"errors": [], "sys_drive": "C:", "sys_free": 50 * GIB, "sys_total": 474 * GIB,
            "vhdx_path": r"C:\Users\u\AppData\Local\wsl\x\ext4.vhdx", "vhdx_bytes": 246 * GIB,
            "distro": "Ubuntu", "swap_bytes": 8 * GIB, "pagefile_automatic": False,
            "pagefile": [{"name": r"C:\pagefile.sys", "allocated_mb": 8192, "used_mb": 100}],
            "ballast_path": r"C:\Users\u\AppData\Local\Jarvis\ballast.bin", "ballast_bytes": 4 * GIB}
    base.update(over)
    return base


def titles(findings):
    return {f["title"]: f for f in findings}


class JudgeTests(unittest.TestCase):
    def test_below_the_critical_line_is_critical_and_says_whether_ballast_helped(self):
        out = titles(storage.judge(host(sys_free=0.1 * GIB), (223 * GIB, 1000 * GIB), NOW, ballast_released=True))
        hit = out["system drive below the critical headroom line"]
        self.assertEqual(hit["severity"], "critical")
        self.assertIn("released this run", hit["detail"])
        out = titles(storage.judge(host(sys_free=0.1 * GIB, ballast_bytes=0), (223 * GIB, 1000 * GIB), NOW))
        self.assertIn("No ballast file was available", out["system drive below the critical headroom line"]["detail"])

    def test_low_headroom_is_high_and_comfortable_is_quiet(self):
        out = titles(storage.judge(host(sys_free=5 * GIB), (223 * GIB, 1000 * GIB), NOW))
        self.assertEqual(out["system drive headroom is low"]["severity"], "high")
        out = titles(storage.judge(host(), (223 * GIB, 1000 * GIB), NOW))
        self.assertNotIn("system drive headroom is low", out)
        self.assertNotIn("system drive below the critical headroom line", out)

    def test_image_overhang_names_sparse_mode_and_compaction(self):
        out = titles(storage.judge(host(), (200 * GIB, 1000 * GIB), NOW))
        hit = out["WSL disk image holds far less than its size on Windows"]
        self.assertEqual(hit["severity"], "high")
        self.assertIn("--set-sparse true", hit["detail"])
        self.assertIn("diskpart", hit["detail"])
        out = titles(storage.judge(host(), (240 * GIB, 1000 * GIB), NOW))
        self.assertIn("WSL disk image size", out)

    def test_automatic_page_file_and_missing_ballast_are_medium_advice(self):
        out = titles(storage.judge(host(pagefile_automatic=True, ballast_bytes=0), (223 * GIB, 1000 * GIB), NOW))
        self.assertEqual(out["page file is system-managed"]["severity"], "medium")
        self.assertEqual(out["no ballast file reserved"]["severity"], "medium")
        self.assertIn("fsutil file createnew", out["no ballast file reserved"]["detail"])

    def test_growth_rate_predicts_days_to_the_line(self):
        hist = [(NOW - 24 * 3600, 30 * GIB), (NOW - 12 * 3600, 20 * GIB)]
        out = titles(storage.judge(host(sys_free=10 * GIB), (223 * GIB, 1000 * GIB), NOW, history=hist))
        hit = out["system drive will reach the critical line soon"]
        self.assertEqual(hit["severity"], "high")        # 20 GiB/day, 0.4 days left
        self.assertIn("day(s) of headroom", hit["detail"])
        self.assertIsNone(storage.growth([(NOW - 60, 1), (NOW, 0)], NOW))   # span too short

    def test_reclaimables_are_named_with_their_commands_and_never_deleted(self):
        reclaim = [("uv package cache", 26 * GIB, True, "uv cache clean"),
                   ("pip cache", 0.2 * GIB, True, "pip cache purge")]
        out = titles(storage.judge(host(), (223 * GIB, 1000 * GIB), NOW, reclaim=reclaim, docker=7 * GIB))
        self.assertIn("reclaimable: uv package cache", out)
        self.assertIn("uv cache clean", out["reclaimable: uv package cache"]["detail"])
        self.assertNotIn("reclaimable: pip cache", out)            # under 1 GiB is not worth a row
        self.assertIn("33.0 GiB", out["reclaimable total inside WSL"]["detail"])

    def test_syslog_copies_of_the_journal_are_named_with_the_fix(self):
        out = titles(storage.judge(host(), (223 * GIB, 1000 * GIB), NOW, syslog=9.2 * GIB))
        hit = out["reclaimable: syslog copies of the Sysmon journal"]
        self.assertEqual(hit["severity"], "medium")
        self.assertIn("rsyslog-sysmon.conf", hit["detail"])
        out = titles(storage.judge(host(), (223 * GIB, 1000 * GIB), NOW, syslog=0.3 * GIB))
        self.assertNotIn("reclaimable: syslog copies of the Sysmon journal", out)

    def test_missing_host_read_is_visibility_not_silence(self):
        out = titles(storage.judge(None, None, NOW))
        self.assertEqual(out["storage headroom is unmeasured on the Windows side"]["category"], "visibility")
        self.assertEqual(out["guest filesystem usage unreadable"]["category"], "visibility")


class HousekeepingTests(unittest.TestCase):
    def test_stale_stages_keep_the_newest_three_and_the_live_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "staging"
            staging.mkdir()
            for i, name in enumerate(("a", "b", "c", "d", "e")):
                d = staging / name
                d.mkdir()
                (d / "x").write_text("1" * 10)
                (staging / (name + ".stage.json")).write_text("{}")
                os.utime(d, (NOW + i, NOW + i))
            (staging / "loose").mkdir()                       # no .stage.json: not ours to judge
            live = Path(tmp) / "live"
            live.mkdir()
            (live / "RELEASE.json").write_text(json.dumps({"source": str(staging / "a")}))
            stale = storage.stale_stages(staging=staging, live=live)
            self.assertEqual(sorted(p.name for p, _ in stale), ["b"])   # a is live, c-e newest

    def test_audit_releases_the_ballast_only_below_the_line_and_records_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "s.db"))
            try:
                calls = []

                def fake_release(path):
                    calls.append(path)
                    return True, "released"
                out = storage.audit(store, now=NOW, host=host(sys_free=1 * GIB), guest=(223 * GIB, 1000 * GIB),
                                    reclaim=[], docker=0, stages=[], release=fake_release, syslog=0)
                self.assertEqual(calls, [r"C:\Users\u\AppData\Local\Jarvis\ballast.bin"])
                log = json.loads(store.get_meta(storage.BALLAST_META))
                self.assertEqual((log[0]["released"], log[0]["bytes"]), (True, 4 * GIB))
                self.assertIn("released this run", titles(out)["system drive below the critical headroom line"]["detail"])
                calls.clear()
                storage.audit(store, now=NOW + 1800, host=host(sys_free=30 * GIB), guest=(223 * GIB, 1000 * GIB),
                              reclaim=[], docker=0, stages=[], release=fake_release, syslog=0)
                self.assertEqual(calls, [])
                hist = json.loads(store.get_meta(storage.HISTORY_META))
                self.assertEqual(len(hist), 2)
            finally:
                store.close()

    def test_docker_size_parsing_and_bounded_walk(self):
        self.assertEqual(storage._parse_size("4.323GB"), 4.323 * 1000 ** 3)
        self.assertEqual(storage._parse_size("623.7MB"), 623.7 * 1000 ** 2)
        self.assertEqual(storage._parse_size("junk"), 0)
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):
                Path(tmp, f"f{i}").write_bytes(b"x" * 4096)
            size, complete = storage.tree_bytes(tmp)
            self.assertTrue(complete)
            self.assertGreaterEqual(size, 5 * 4096)
            ticks = iter([0.0, 100.0, 200.0, 300.0])
            size, complete = storage.tree_bytes(tmp, budget_s=1.0, clock=lambda: next(ticks))
            self.assertFalse(complete)

    def test_windows_disabled_is_flagged(self):
        self.assertEqual(storage.audit(None, hosts=("wsl",))[0]["category"], "visibility")


if __name__ == "__main__":
    unittest.main()
