"""How serious a connection to a listed address is depends on what the list claims.

2026-10-30 quality control: Chrome reaching a Google address (142.251.37.78)
and Windows Update reaching a Microsoft address (4.247.188.233) were reported
critical "known attacker" because blocklist.de, which lists hosts seen
attacking services (often shared or reassigned cloud addresses), carried them.

Invariants:
  * a match from a malware infrastructure feed (ThreatFox, Feodo, URLhaus) is
    critical: a connection to command-and-control or a payload server;
  * a match from an attack-source reputation list (blocklist.de, CINS, Binary
    Defense, IPsum) is medium "reported attack source": still reported, never
    called a known attacker on that list's word alone;
  * collapsing per process counts only the critical matches as known attackers.
"""

import os
import tempfile
import unittest

from jarvis.core.store import Store
from jarvis.core.util import now
from jarvis.intel import hunt


class PeerSeverity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "jarvis.db"))
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.store.close)

    def listed(self, ip, feed, context="attacking host"):
        t = now()
        self.store.db.execute(
            "INSERT INTO indicators(kind,value,norm,confidence,topic,context,source_url,"
            "first_seen,last_seen,status,source) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("ipv4", ip, ip, "high", feed, context, f"https://{feed}.test/list", t, t, "active", feed))

    def connected(self, ip, pname="chrome.exe", fp=None):
        t, fp = now(), fp or f"fp-{pname}"
        self.store.db.execute("INSERT OR IGNORE INTO procs(fp,host,name,exe,first_seen,last_seen) "
                              "VALUES(?,?,?,?,?,?)", (fp, "win", pname, f"C:\\{pname}", t, t))
        self.store.db.execute("INSERT INTO peers(key,host,fp,remote_ip,remote_port,scope,rdns,"
                              "first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
                              (f"{fp}|{ip}", "win", fp, ip, 443, "public", "", t, t))

    def findings(self):
        return [f for f in hunt.check_peers(self.store) if f.get("category") == "c2 match"]

    def test_an_attack_source_list_alone_is_medium_not_known_attacker(self):
        for feed in ("blocklist-de", "cins", "binarydefense", "ipsum"):
            with self.subTest(feed=feed):
                self.setUp()
                self.listed("142.251.37.78", feed)
                self.connected("142.251.37.78")
                out = self.findings()
                self.assertEqual([f["severity"] for f in out], ["medium"], out)
                self.assertNotIn("known attacker", out[0]["title"])
                self.assertIn("reported attack source", out[0]["title"] + out[0]["detail"])

    def test_malware_infrastructure_is_critical(self):
        for feed in ("threatfox", "feodo", "urlhaus", "threatfox-full", "urlhaus-full"):
            with self.subTest(feed=feed):
                self.setUp()
                self.listed("45.155.205.7", feed, "botnet C2")
                self.connected("45.155.205.7", "evil.exe")
                out = self.findings()
                self.assertEqual([f["severity"] for f in out], ["critical"], out)
                self.assertIn("known attacker", out[0]["title"])

    def test_collapsed_counts_only_infrastructure_as_known_attacker(self):
        feeds = ["threatfox"] + ["blocklist-de", "cins"] * hunt.PEER_SINGLE_THRESHOLD   # over the threshold
        for i, feed in enumerate(feeds):
            ip = f"45.155.205.{10 + i}"
            self.listed(ip, feed)
            self.connected(ip, "btweb.exe", fp="fp-bt")
        out = self.findings()
        self.assertEqual(len(out), 1, out)
        self.assertIn("(1 known-attacker)", out[0]["title"])
        self.assertEqual(out[0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
