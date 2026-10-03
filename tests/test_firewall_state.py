"""A listener is unreachable only when every profile provably blocks it."""

import unittest
from unittest import mock

from jarvis.collectors.network.internetwatch import analyze
from jarvis.platform import firewall_state as fs


def fw(allow_rules="True", default="Block", enabled="True", rules=()):
    return {"ok": True, "rules": list(rules), "profiles": [
        {"name": n, "enabled": enabled, "defaultInbound": default,
         "allowInboundRules": allow_rules} for n in fs.PROFILES]}


def rule(port="Any", proto="TCP", program="Any", profile="Any"):
    return {"profile": profile, "protocol": proto, "localPort": [port], "program": program}


class BlockedTests(unittest.TestCase):
    def test_block_all_toggle_blocks_everything(self):
        state = fw(allow_rules="False", rules=[rule()])
        self.assertIn("blocks all incoming", fs.blocked("tcp", 445, "", state))
        self.assertTrue(fs.rule_inactive(state))

    def test_matching_allow_rule_on_any_profile_exposes(self):
        self.assertEqual(fs.blocked("tcp", 445, "", fw(rules=[rule("445", profile="Private")])), "")
        self.assertEqual(fs.blocked("tcp", 3000, "C:\\p\\node.exe",
                                    fw(rules=[rule(program="C:\\p\\node.exe")])), "")

    def test_rpc_keyword_and_unreadable_ports_count_as_open(self):
        self.assertEqual(fs.blocked("tcp", 49664, "", fw(rules=[rule("RPC")])), "")

    def test_non_matching_rules_leave_it_blocked(self):
        state = fw(rules=[rule("80"), rule("445", proto="UDP"),
                          rule(program="C:\\other.exe")])
        self.assertIn("no enabled inbound allow rule", fs.blocked("tcp", 445, "C:\\x.exe", state))

    def test_disabled_profile_or_default_allow_exposes(self):
        self.assertEqual(fs.blocked("tcp", 445, "", fw(enabled="False", allow_rules="False")), "")
        self.assertEqual(fs.blocked("tcp", 445, "", fw(default="Allow")), "")

    def test_unknown_state_proves_nothing(self):
        # None means "read the live state", so the read itself is stubbed to
        # fail; otherwise this asserts whatever the test machine's firewall is.
        with mock.patch.object(fs, "state", return_value=None):
            self.assertEqual(fs.blocked("tcp", 445, "", None), "")
            self.assertFalse(fs.rule_inactive(None))
        self.assertEqual(fs.blocked("tcp", 445, "", {}), "")
        self.assertFalse(fs.rule_inactive({}))


class ListenerSeverityTests(unittest.TestCase):
    CONN = {"pid": 4, "proto": "tcp", "local_ip": "0.0.0.0", "local_port": 445,
            "remote_ip": "0.0.0.0", "remote_port": 0, "state": "LISTEN"}

    def severity(self, firewall):
        findings, _ = analyze("win", {"apps": [{"pid": 4, "name": "System", "exe": ""}],
                                      "connections": [self.CONN]}, firewall)
        return [f["severity"] for f in findings if "listening" in f["title"]]

    def test_proven_block_lowers_unproven_stays_medium(self):
        self.assertEqual(self.severity(fw(allow_rules="False")), ["low"])
        self.assertEqual(self.severity(fw(rules=[rule("445")])), ["medium"])
        self.assertEqual(self.severity(None), ["medium"])


if __name__ == "__main__":
    unittest.main()


class PermissiveRuleTests(unittest.TestCase):
    RULES = {"rules": [
        {"name": "Node.js", "app": "C:\\Program Files\\nodejs\\node.exe", "remote": "Any",
         "exists": True},
        {"name": "AnyDesk", "app": "C:\\Program Files\\AnyDesk\\AnyDesk.exe", "remote": "Any",
         "exists": True}]}

    def severities(self, ignored):
        from unittest import mock

        from jarvis.collectors.network import firewall
        with mock.patch.object(firewall, "ps_json", return_value=self.RULES), \
             mock.patch.object(firewall.firewall_state, "rule_inactive", return_value=ignored):
            return {f["where"].rsplit("\\", 1)[-1]: f["severity"]
                    for f in firewall.audit_windows() if f["title"] == "permissive inbound rule"}

    def test_block_all_makes_ordinary_rules_inactive_but_not_agents(self):
        active = self.severities(False)
        self.assertEqual(active["node.exe"], "medium")
        inactive = self.severities(True)
        self.assertEqual(inactive["node.exe"], "low")
        self.assertEqual(inactive["AnyDesk.exe"], active["AnyDesk.exe"])
