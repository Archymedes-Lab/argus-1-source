"""Process-creation technique rules and the coverage they are allowed to claim.

Invariants:

  * every rule's sample fires through the real detector, and no benign
    look-alike does (a map entry cannot outlive its rule);
  * a rule is keyed on the process that ran the tool, so script text that only
    names a tool reports nothing - including JARVIS's own inline scripts;
  * a discovery command alone is never reported; a burst needs distinct
    techniques from one identified parent inside one window;
  * a command line that can carry a secret is never quoted;
  * a replay through the Windows detector cannot write to the store;
  * the coverage map counts a technique as validated only when its probe fires
    AND a feeding collector is reporting, and stops counting retired techniques.
"""

import json
import os
import tempfile
import time
import unittest
from unittest import mock

from jarvis.collectors.telemetry import sysmon, sysmon_linux, techniques
from jarvis.core.store import Store
from jarvis.intel import feeds
from jarvis.service import attackmap, schedule

# Every audit JARVIS has; a release from before the per-machine schedule has only JOBS.
ALL_JOBS = getattr(schedule, "ALL_JOBS", schedule.JOBS)

WHEN = "2026-01-01T00:00:00.000Z"
GUID = "{11111111-1111-1111-1111-111111111111}"


def win(pairs, parent=r"C:\Windows\System32\cmd.exe", guid=GUID, when=WHEN):
    return sysmon.audit(events=[{"id": 1, "image": i, "cmdline": c, "time": when,
                                 "parent": parent, "parent_guid": guid} for i, c in pairs])


def linux(pairs, parent="/usr/bin/bash", guid=GUID):
    return sysmon_linux._rules([{"id": 1, "Image": i, "CommandLine": c, "ParentImage": parent,
                                 "ParentProcessGuid": guid} for i, c in pairs])


def replay(platform, pairs, **kw):
    return (win if platform == techniques.WIN else linux)(pairs, **kw)


def tagged(findings):
    return [f for f in findings if f.get("techniques")]


class RuleTableTests(unittest.TestCase):
    def test_every_sample_fires_and_no_lookalike_does(self):
        for rule in techniques.RULES:
            kw = {"parent": rule.sample_parent} if rule.sample_parent else {}
            out = tagged(replay(rule.platform, [rule.sample], **kw))
            self.assertTrue(any(set(rule.tids) <= set(f["techniques"]) for f in out), rule.title)
            for pair in rule.benign:
                hits = [f for f in tagged(replay(rule.platform, [pair]))
                        if f["title"] == techniques.finding_title(rule)]
                self.assertEqual(hits, [], f"{rule.title}: {pair[1]}")

    def test_rules_are_well_formed(self):
        for rule in techniques.RULES:
            self.assertIn(rule.platform, (techniques.WIN, techniques.LINUX))
            self.assertIn(rule.severity, ("critical", "high", "medium", "low"))
            self.assertTrue(all(t.startswith("T") and t[1:].isdigit() for t in rule.tids), rule.title)
            self.assertEqual([i for i in rule.images if i != i.lower() or i.endswith(".exe")], [])
            rule.regex()

    def test_script_text_naming_a_tool_reports_nothing(self):
        # What JARVIS's own collectors look like: a whole script on the command line.
        script = ("powershell.exe -NoProfile -NonInteractive -Command \"$o=@{}; "
                  "vssadmin list shadows; reg save HKLM\\SAM x; netsh advfirewall set allprofiles "
                  "state off; wevtutil cl Security; sc stop WinDefend; cmdkey /list; "
                  "Get-WmiObject -Namespace root\\subscription -Class __EventFilter\"")
        ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        self.assertEqual(tagged(win([(ps, script)])), [])
        shell = ("bash -c 'grep -r \"stratum+tcp://\" notes; echo GetUserSPNs.py transfer.sh; "
                 "cat <<\"EOF\"\nunset HISTFILE\nEOF\n'")
        self.assertEqual(tagged(linux([("/usr/bin/bash", shell)])), [])

    def test_secret_bearing_command_lines_are_never_quoted(self):
        cases = [(techniques.WIN, r"C:\Windows\System32\net.exe", "net user eve Hunter2! /add"),
                 (techniques.WIN, r"C:\Program Files\7-Zip\7z.exe", "7z a -pHunter2! o.7z C:\\d"),
                 (techniques.LINUX, "/usr/bin/zip", "zip -r -P Hunter2! /tmp/o.zip /home/u")]
        for platform, image, cmd in cases:
            out = tagged(replay(platform, [(image, cmd)]))
            self.assertTrue(out, cmd)
            self.assertFalse(any("Hunter2" in json.dumps(f) for f in out), cmd)

    def test_quoted_span_is_bounded(self):
        long = "wevtutil cl Security " + "A" * 5000
        f = tagged(win([(r"C:\Windows\System32\wevtutil.exe", long)]))[0]
        self.assertLess(len(f["detail"]), 400)

    def test_repeats_fold_into_one_finding(self):
        out = tagged(win([(r"C:\Windows\System32\wevtutil.exe", "wevtutil cl Security")] * 5))
        self.assertEqual(len(out), 1)
        self.assertIn("5 times", out[0]["detail"])


class ParentAndNetworkTests(unittest.TestCase):
    PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    def test_the_parent_decides_not_the_child(self):
        word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
        hit = tagged(win([(self.PS, "powershell -c calc")], parent=word))
        self.assertEqual([f["techniques"] for f in hit], [["T1203"]])
        for parent in (r"C:\Windows\explorer.exe", r"C:\Program Files\Google\Chrome\chrome.exe", ""):
            self.assertEqual(tagged(win([(self.PS, "powershell -c calc")], parent=parent)), [], parent)
        # A document application starting an ordinary program is not it either.
        self.assertEqual(tagged(win([(r"C:\Windows\System32\splwow64.exe", "splwow64 8192")],
                                    parent=word)), [])

    def test_server_and_spooler_shells_are_critical(self):
        cmd = (r"C:\Windows\System32\cmd.exe", "cmd /c whoami")
        for parent, tid in ((r"C:\Windows\System32\inetsrv\w3wp.exe", "T1190"),
                            (r"C:\Windows\System32\spoolsv.exe", "T1068")):
            out = tagged(win([cmd], parent=parent))
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["severity"], "critical")
            self.assertIn(tid, out[0]["techniques"])

    def smb(self, dest, port="445", initiated=True):
        return tagged(sysmon.audit(events=[{"id": 3, "image": r"C:\Windows\explorer.exe",
                                            "dest": dest, "dport": port, "initiated": initiated,
                                            "time": WHEN}]))

    def test_only_outbound_public_file_share_connections_are_reported(self):
        self.assertEqual([f["techniques"] for f in self.smb("8.8.4.4")], [["T1187"]])
        self.assertEqual(len(self.smb("8.8.4.4", initiated=None)), 1)     # direction unknown: kept
        for dest, port, initiated in (("192.168.1.9", "445", True), ("10.0.0.4", "139", True),
                                      ("8.8.4.4", "443", True), ("8.8.4.4", "445", False),
                                      ("8.8.4.4", "445", "false"), ("not-an-ip", "445", True),
                                      ("", "445", True)):
            self.assertEqual(self.smb(dest, port, initiated), [], (dest, port, initiated))

    def lookups(self, n, status=techniques.NXDOMAIN, guid="{9}", when=WHEN, names=None):
        return [{"id": 22, "image": r"C:\t\a.exe", "process_guid": guid, "dns_status": status,
                 "query": (names[i] if names else f"n{i}.example"), "time": when} for i in range(n)]

    def test_generated_domain_burst_needs_distinct_nonexistent_names_from_one_process(self):
        n = techniques.DGA_NAMES
        self.assertEqual(len(tagged(sysmon.audit(events=self.lookups(n)))), 1)
        self.assertEqual(tagged(sysmon.audit(events=self.lookups(n - 1))), [])
        self.assertEqual(tagged(sysmon.audit(events=self.lookups(n * 3, status="9701"))), [])
        self.assertEqual(tagged(sysmon.audit(events=self.lookups(n * 3, status="0"))), [])
        same = self.lookups(n * 3, names=["typo.example"] * (n * 3))        # one name, retried
        self.assertEqual(tagged(sysmon.audit(events=same)), [])
        split = self.lookups(n // 2, guid="{1}") + self.lookups(n // 2, guid="{2}")
        self.assertEqual(tagged(sysmon.audit(events=split)), [])


class DiscoveryTests(unittest.TestCase):
    def test_single_commands_are_silent(self):
        for platform, samples in techniques.DISCOVERY_SAMPLES.items():
            for tid, pair in samples.items():
                self.assertIn(tid, techniques.discovery(*pair, platform))
                self.assertEqual(tagged(replay(platform, [pair])), [], pair[1])

    def test_burst_needs_enough_distinct_techniques(self):
        for platform, samples in techniques.DISCOVERY_SAMPLES.items():
            pairs = list(samples.values())
            below = pairs[:techniques.BURST_TECHNIQUES - 1]
            self.assertEqual(tagged(replay(platform, below * 3)), [])   # repeats do not count
            out = tagged(replay(platform, pairs[:techniques.BURST_TECHNIQUES]))
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["severity"], "medium")
            self.assertEqual(len(out[0]["techniques"]), techniques.BURST_TECHNIQUES)

    def test_unidentified_parent_never_forms_a_burst(self):
        for platform, samples in techniques.DISCOVERY_SAMPLES.items():
            pairs = list(samples.values())
            self.assertEqual(tagged(replay(platform, pairs, guid="")), [])
        zero = "{00000000-0000-0000-0000-000000000000}"
        self.assertEqual(tagged(linux(list(techniques.DISCOVERY_SAMPLES["linux"].values()),
                                      guid=zero)), [])

    def test_commands_from_different_parents_or_windows_do_not_pool(self):
        pairs = list(techniques.DISCOVERY_SAMPLES["win"].values())[:6]
        events = [{"id": 1, "image": i, "cmdline": c, "time": WHEN, "parent": "cmd.exe",
                   "parent_guid": "{%d}" % n} for n, (i, c) in enumerate(pairs)]
        self.assertEqual(tagged(sysmon.audit(events=events)), [])
        spread = [{"id": 1, "image": i, "cmdline": c, "parent": "cmd.exe", "parent_guid": GUID,
                   "time": "2026-01-01T%02d:00:00.000Z" % n} for n, (i, c) in enumerate(pairs)]
        self.assertEqual(tagged(sysmon.audit(events=spread)), [])

    def test_linux_build_tooling_is_not_a_burst(self):
        pairs = list(techniques.DISCOVERY_SAMPLES["linux"].values())
        self.assertEqual([f for f in tagged(linux(pairs, parent="/usr/bin/make"))
                          if "burst" in f["title"]], [])


class ReplayTests(unittest.TestCase):
    def test_replay_never_reads_the_machine_or_writes_the_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "s.db"))
            try:
                with mock.patch.object(sysmon, "_fetch") as fetch, \
                        mock.patch.object(sysmon, "_native") as native, \
                        mock.patch.object(sysmon, "_query_blocked") as blocked:
                    out = sysmon.audit(store=store, incremental=True, events=[
                        {"id": 1, "image": r"C:\Windows\System32\wevtutil.exe",
                         "cmdline": "wevtutil cl Security", "time": WHEN}])
                for called in (fetch, native, blocked):
                    called.assert_not_called()
                self.assertTrue(tagged(out))
                self.assertEqual(store.db.execute("SELECT COUNT(*) FROM sysmon_hits").fetchone()[0], 0)
                self.assertEqual(store.get_meta("sysmon_last_run", ""), "")
            finally:
                store.close()

    def test_existing_rules_still_see_the_replayed_events(self):
        out = sysmon.audit(events=[{"id": 1, "image": r"C:\Windows\System32\vssadmin.exe",
                                    "cmdline": "vssadmin delete shadows /all", "time": WHEN}])
        self.assertTrue(any(f["category"] == "impact" for f in out))
        self.assertEqual(sysmon.audit(hosts=("wsl",), events=[]), [])


class CoverageMapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "s.db"))
        self.addCleanup(self.store.close)
        tids = sorted(set(attackmap.PROBES) | {"T9990"})
        self.store.db.executemany(
            "INSERT INTO attack_techniques(tid,name,tactics,platforms,updated) VALUES(?,?,?,?,?)",
            [(t, t, "execution", "Windows,Linux", 1) for t in tids])
        self.store.commit()

    def snapshot(self, job):
        self.store.db.execute(
            "INSERT OR REPLACE INTO snapshots(kind,ts,duration,error,payload) VALUES(?,?,?,?,?)",
            (job, int(time.time()), 1.0, "", "[]"))
        self.store.commit()

    def levels(self):
        return {t["tid"]: t for t in attackmap.measure(self.store)[1]["techniques"]}

    def test_every_probe_fires_and_names_real_jobs(self):
        for tid, (probe, feeding) in attackmap.PROBES.items():
            fired, what = probe()
            self.assertTrue(fired, f"{tid}: {what}")
            self.assertTrue(feeding, tid)
            self.assertLessEqual(set(feeding), set(ALL_JOBS), tid)
        for label, probe in attackmap.PRECISION.items():
            self.assertTrue(probe()[0], label)
        self.assertLessEqual(techniques.technique_ids(), set(attackmap.PROBES))

    def test_a_firing_rule_behind_a_silent_collector_is_not_validated(self):
        levels = self.levels()
        self.assertEqual({t["level"] for tid, t in levels.items() if tid != "T9990"}, {"claimed"})
        self.assertEqual(levels["T9990"]["level"], "blind")
        self.assertIn("not reporting", levels["T1047"]["evidence"])

    def test_validated_follows_the_collector_that_feeds_the_rule(self):
        self.snapshot("sysmon")
        levels = self.levels()
        self.assertEqual(levels["T1047"]["level"], "validated")      # Windows-only rule
        self.assertEqual(levels["T1611"]["level"], "claimed")        # Linux-only rule
        self.snapshot("sysmon_linux")
        self.assertEqual(self.levels()["T1611"]["level"], "validated")

    def test_burst_only_discovery_is_never_counted_as_validated(self):
        self.assertIn("T1033", attackmap.CONTEXT_ONLY)
        self.assertNotIn("T1047", attackmap.CONTEXT_ONLY)
        self.snapshot("sysmon")
        self.snapshot("sysmon_linux")
        levels = self.levels()
        for tid in attackmap.CONTEXT_ONLY:
            self.assertEqual(levels[tid]["level"], "claimed", tid)
            self.assertIn(attackmap.HELD[tid], levels[tid]["evidence"])
        self.assertIn("never by itself", levels["T1033"]["evidence"])
        with mock.patch.object(techniques, "bursts", return_value=[]):
            self.assertEqual(self.levels()["T1033"]["level"], "regressed")

    def test_a_broken_rule_is_a_regression_not_coverage(self):
        self.snapshot("sysmon")
        with mock.patch.object(techniques, "match", return_value=[]):
            findings, data = attackmap.measure(self.store)
        row = {t["tid"]: t for t in data["techniques"]}["T1047"]
        self.assertEqual(row["level"], "regressed")
        self.assertTrue(any(f["severity"] == "high" and "T1047" in f["title"] for f in findings))

    def test_mappings_to_techniques_the_catalogue_dropped_are_reported(self):
        findings, _ = attackmap.measure(self.store)
        self.assertFalse([f for f in findings if "no longer lists" in f["title"]
                          and "T1047" in f["detail"]])
        self.store.db.execute("DELETE FROM attack_techniques WHERE tid='T1047'")
        self.store.commit()
        findings, _ = attackmap.measure(self.store)
        orphan = [f for f in findings if "no longer lists" in f["title"]]
        self.assertEqual(len(orphan), 1)
        self.assertEqual(orphan[0]["severity"], "low")
        self.assertIn("T1047", orphan[0]["detail"])
        self.store.db.execute("DELETE FROM attack_techniques")
        self.store.commit()
        findings, _ = attackmap.measure(self.store)     # no catalogue: nothing to compare
        self.assertFalse([f for f in findings if "no longer lists" in f["title"]])

    def test_retired_techniques_leave_the_catalogue_only_on_a_full_load(self):
        def catalogue(n, extra=()):
            objs = [{"type": "attack-pattern", "kill_chain_phases": [{"phase_name": "execution"}],
                     "x_mitre_platforms": ["Windows"], "name": f"t{i}",
                     "external_references": [{"source_name": "mitre-attack",
                                              "external_id": f"T{2000 + i}"}]} for i in range(n)]
            return json.dumps({"objects": objs + list(extra)}).encode()
        retired = {"type": "attack-pattern", "x_mitre_deprecated": True, "name": "old",
                   "external_references": [{"source_name": "mitre-attack", "external_id": "T9990"}]}
        feeds._attack(catalogue(3, [retired]), self.store)            # truncated download
        have = {r[0] for r in self.store.db.execute("SELECT tid FROM attack_techniques")}
        self.assertIn("T9990", have)                                  # nothing removed
        self.assertIn("T1047", have)
        feeds._attack(catalogue(feeds.ATTACK_MIN_ROWS, [retired]), self.store)
        have = {r[0] for r in self.store.db.execute("SELECT tid FROM attack_techniques")}
        self.assertNotIn("T9990", have)
        self.assertEqual(len(have), feeds.ATTACK_MIN_ROWS)



class CollectorSeamTests(unittest.TestCase):
    """A probe may hand a collector its evidence; it may never make it fetch."""

    def test_firewall_payload_is_judged_without_asking_windows(self):
        from jarvis.collectors.network import firewall
        with mock.patch.object(firewall, "ps_json") as ps:
            out = firewall.audit_windows(data={"profiles": [], "secReadable": True, "logons": [
                {"type": "10", "user": "a", "ip": "198.51.100.7", "time": WHEN}]})
            ps.assert_not_called()
        self.assertTrue(any("RDP logon succeeded" in f["title"] for f in out))
        with mock.patch.object(firewall, "ps_json", return_value=None) as ps:
            unavailable = firewall.audit_windows()
            ps.assert_called_once()
        self.assertEqual(unavailable[0]["title"], "firewall audit unavailable")

    def test_bruteforce_lines_are_judged_without_reading_logs(self):
        from jarvis.collectors.identity import bruteforce
        with mock.patch.object(bruteforce, "_linux_lines") as read:
            spread = [f"sshd: Failed password for invalid user u{i} from 198.51.100.{i} port 1 ssh2"
                      for i in range(bruteforce.SPIKE_ONE_SOURCE)]
            out = bruteforce._linux(lines=spread)        # many sources, none concentrated
            read.assert_not_called()
        self.assertFalse(any(f["severity"] == "high" for f in out))
        with mock.patch.object(bruteforce, "_linux_lines", return_value=[]) as read:
            self.assertEqual(bruteforce._linux()[0]["severity"], "low")   # unreadable, said so
            read.assert_called_once()

    def test_only_modules_are_judged_in_a_pam_directory(self):
        from jarvis.collectors.persistence import implant
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("notes.txt", "pam_x.so.bak"):
                open(os.path.join(tmp, name), "wb").close()
            with mock.patch.object(implant, "_dpkg_owns", return_value=False):
                self.assertEqual(implant.unowned_pam_modules(dirs=(tmp, tmp + "-missing")), [])
                open(os.path.join(tmp, "pam_x.so"), "wb").close()
                self.assertEqual(len(implant.unowned_pam_modules(dirs=(tmp,))), 1)
            with mock.patch.object(implant, "_dpkg_owns", return_value=True):
                self.assertEqual(implant.unowned_pam_modules(dirs=(tmp,)), [])

    def test_probe_payload_fields_are_ones_the_collection_scripts_emit(self):
        # A probe hands a collector a payload it built. If the PowerShell
        # script stopped emitting a field the probe relies on, the rule would
        # be proven while the real collector fed it nothing.
        from jarvis.core.paths import load_win_script
        for script, fields in (("firewall.ps1", ("logons", "profiles", "secReadable")),
                               ("evasion.ps1", ("drivers", "dns"))):
            text = load_win_script(script)
            for field in fields:
                self.assertRegex(text, r"\b%s\b" % field, f"{script} no longer emits {field}")

    def test_valid_accounts_is_held_at_claimed_with_its_reason(self):
        self.assertIn("T1078", attackmap.CONTEXT_ONLY)
        self.assertIn("stolen credential", attackmap.HELD["T1078"])
        self.assertTrue(attackmap.PROBES["T1078"][0]()[0])      # the probe still runs

    def test_gap_report_and_coverage_map_agree_on_what_is_looked_for(self):
        from jarvis.intel import gaps
        self.assertEqual(sorted(set(attackmap.PROBES) - set(gaps.COVERAGE)), [])

    def test_a_retired_id_is_covered_through_its_successors_only(self):
        from jarvis.intel import gaps
        self.assertNotIn("T1562", gaps.COVERAGE)                 # never mapped by itself
        self.assertIn("T1685", gaps._successors("T1562"))
        self.assertIsNone(gaps._successors("T1497"))
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "g.db"))
            try:
                for tid in ("T1562.001", "T1497.001"):
                    store.db.execute(
                        """INSERT INTO indicators(kind,value,norm,confidence,topic,context,malware,
                                                  source_url,first_seen,last_seen,source,doc_count,status)
                           VALUES('attack',?,?,'high','','','','',0,0,'exa',3,'active')""", (tid, tid))
                store.db.execute("INSERT INTO attack_techniques(tid,name,tactics,platforms,updated) "
                                 "VALUES('T1497','Sandbox Evasion','stealth','Windows',1)")
                store.commit()
                findings, covered, _ = gaps.gaps(store)
            finally:
                store.close()
        self.assertIn("T1562.001", [c[0] for c in covered])
        self.assertEqual([f["title"].split()[0] for f in findings], ["T1497.001"])

    def test_claims_no_detector_backs_are_gone(self):
        from jarvis.intel import gaps
        for tid in ("T1497", "T1571"):
            self.assertNotIn(tid, gaps.COVERAGE)
            self.assertNotIn(tid, attackmap.PROBES)

    def test_an_optional_probe_is_absent_when_its_detector_is(self):
        before = dict(attackmap.PROBES)
        try:
            attackmap.PROBES.pop("T9991", None)
            attackmap._optional("T9991", lambda: (True, "x"), ("scan",),
                                lambda: attackmap._has("jarvis.no_such_module"))
            self.assertNotIn("T9991", attackmap.PROBES)
            attackmap._optional("T9991", lambda: (True, "x"), ("scan",), lambda: True)
            self.assertIn("T9991", attackmap.PROBES)
        finally:
            attackmap.PROBES.clear()
            attackmap.PROBES.update(before)


if __name__ == "__main__":
    unittest.main()