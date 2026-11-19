"""Tests for the AI Agent Guardian collector.

Covers: sample, risk scoring, heuristic classification, and the audit output
shape. The environment has no Claude/Codex/etc processes running, so these
tests only assert on the *mechanism* of observation, not on a specific
process found on the host.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from jarvis.collectors.host import agent_guardian


class TestAgentSample(unittest.TestCase):
    def test_dataclass_shapes(self):
        s = agent_guardian.AgentSample(
            pid=123, name="claude", exe="claude",
            cmdline="claude --read file.txt", ppid=456, host="wsl",
        )
        self.assertEqual(s.pid, 123)
        self.assertEqual(s.name, "claude")
        self.assertTrue(s.identified_agent)

    def test_non_agent_identification(self):
        s = agent_guardian.AgentSample(
            pid=123, name="bash", exe="/bin/bash", cmdline="/bin/bash",
            ppid=0, host="wsl",
        )
        self.assertFalse(s.identified_agent)


class TestRiskAssess(unittest.TestCase):
    def test_privilege_escalation_scores(self):
        s = agent_guardian.AgentSample(
            pid=999, name="claude", exe="claude",
            cmdline="claude sudo rm -rf /", ppid=0, host="wsl",
        )
        result = agent_guardian.assess(s)
        self.assertGreaterEqual(result["score"], 8)  # sum of reasons

    def test_risky_verbs_score(self):
        s = agent_guardian.AgentSample(
            pid=999, name="claude", exe="claude",
            cmdline="claude rm -rf /tmp/somefile", ppid=0, host="wsl",
        )
        result = agent_guardian.assess(s)
        self.assertGreaterEqual(result["score"], 6)

    def test_file_read_targets(self):
        s = agent_guardian.AgentSample(
            pid=999, name="claude", exe="claude",
            cmdline="claude cat ~/.ssh/id_rsa", ppid=0, host="wsl",
        )
        result = agent_guardian.assess(s)
        self.assertGreaterEqual(result["score"], 7)


class TestSampleAndHistory(unittest.TestCase):
    def test_sample_returns_none_or_a_sample(self):
        # No agents should exist on a clean test host, so sample returns None
        # or a benign process. We only assert the type.
        s = agent_guardian.sample(host="wsl")
        if s is not None:
            self.assertIsInstance(s, agent_guardian.AgentSample)

    def test_window_returns_list(self):
        samples = agent_guardian.window(max_samples=10)
        self.assertIsInstance(samples, list)

    def test_time_span_seconds_returns_int(self):
        span = agent_guardian.time_span_seconds()
        self.assertIsInstance(span, int)


class TestAudit(unittest.TestCase):
    def test_audit_returns_list(self):
        findings = agent_guardian.audit(host="wsl")
        self.assertIsInstance(findings, list)

    def test_audit_findings_have_expected_keys(self):
        # The audit returns findings for the scheduler. The shape varies by
        # what the sampler saw, so we check the general shape.
        findings = agent_guardian.audit(host="wsl")
        for f in findings:
            self.assertIn("host", f)
            self.assertIn("category", f)
            self.assertIn("title", f)
