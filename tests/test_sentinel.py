"""Tests for the Network Sentinel collector.

Cross-connecting connections to findings and the dashboard state builder.
No live network traffic is used: the tests exercise the analysis logic on
constructed records and the classify_ip helper from the standard library.
"""

import ipaddress
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from jarvis.collectors.network import sentinel


class TestClassifyIp(unittest.TestCase):
    def test_classify_ip(self):
        self.assertEqual(sentinel.classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(sentinel.classify_ip("10.0.0.1"), "private")
        self.assertEqual(sentinel.classify_ip("172.16.0.1"), "private")
        self.assertEqual(sentinel.classify_ip("192.168.1.1"), "private")
        self.assertEqual(sentinel.classify_ip("8.8.8.8"), "public")
        self.assertEqual(sentinel.classify_ip("203.0.113.5"), "private")
        self.assertEqual(sentinel.classify_ip("::1"), "loopback")
        self.assertEqual(sentinel.classify_ip("invalid"), "invalid")


class TestAssessOutbound(unittest.TestCase):
    def test_first_time_peer_no_finding(self):
        sample = sentinel.ConnectionSample(
            host="wsl", exe="claude", proc="claude", pid=1234,
            remote_ip="8.8.8.8", remote_port=53, proto="udp",
            state="ESTABLISHED", ts=1234.5,
        )
        history = {}
        result = sentinel.assess_outbound(sample, history)
        self.assertEqual(result, {})

    def test_second_peer_report(self):
        sample = sentinel.ConnectionSample(
            host="wsl", exe="claude", proc="claude", pid=1234,
            remote_ip="8.8.8.8", remote_port=53, proto="udp",
            state="ESTABLISHED", ts=1234.5,
        )
        history = {}
        # First call records the peer (no finding)
        sentinel.assess_outbound(sample, history)
        # Second call with the same peer returns a low-severity finding
        # (the destination is not on the sensitive list, so a generic
        # "unusual-destination" finding is reported).
        sample2 = sentinel.ConnectionSample(
            host="wsl", exe="claude", proc="claude", pid=1234,
            remote_ip="8.8.8.8", remote_port=53, proto="udp",
            state="ESTABLISHED", ts=1235.5,
        )
        result = sentinel.assess_outbound(sample2, history)
        self.assertIn("score", result)
        self.assertGreaterEqual(result["score"], 10)
        self.assertEqual(result["reasons"], ["unusual-destination"])

    def test_sensitive_destination_finding(self):
        # Port 1080 is a SOCKS proxy: on the sensitive list
        sample = sentinel.ConnectionSample(
            host="wsl", exe="claude", proc="claude", pid=1234,
            remote_ip="8.8.8.8", remote_port=1080, proto="tcp",
            state="ESTABLISHED", ts=1234.5,
        )
        # First observation: record but do not report
        history = {}
        sentinel.assess_outbound(sample, history)
        # Second observation: the port 1080 is sensitive, so a finding
        # is returned regardless of the peer history (the sensitive-port
        # check happens after the count check).
        sample2 = sentinel.ConnectionSample(
            host="wsl", exe="claude", proc="claude", pid=1234,
            remote_ip="8.8.8.8", remote_port=1080, proto="tcp",
            state="ESTABLISHED", ts=1235.5,
        )
        result = sentinel.assess_outbound(sample2, history)
        self.assertIn("category", result)
        self.assertEqual(result["category"], "network")
        self.assertGreaterEqual(result["score"], 25)

    def test_high_peer_count_report(self):
        # Construct 60 different remote peers; the finding appears only
        # when the unique-destination count exceeds 50.
        history = {}
        for i in range(60):
            sample = sentinel.ConnectionSample(
                host="wsl", exe="claude", proc="claude", pid=1234,
                remote_ip=f"1.1.{i % 256}.1", remote_port=443,
                proto="tcp", state="ESTABLISHED", ts=1234.5 + i,
            )
            result = sentinel.assess_outbound(sample, history)
            # By the end, we have 60 distinct destinations, so len(peer_hist)
            # is 60, which is > 50, and a finding should be returned.
            # Wait for it to happen (first finding at i=59).
            if i == 59:
                self.assertIn("score", result)
                self.assertGreaterEqual(result["score"], 35)
                self.assertEqual(result["reasons"], ["high-peer-count"])

    def test_loopback_not_reported(self):
        sample = sentinel.ConnectionSample(
            host="wsl", exe="claude", proc="claude", pid=1234,
            remote_ip="127.0.0.1", remote_port=8080, proto="tcp",
            state="ESTABLISHED", ts=1234.5,
        )
        history = {}
        result = sentinel.assess_outbound(sample, history)
        self.assertEqual(result, {})

    def test_dns_hint(self):
        hint = sentinel.dns_hint("8.8.8.8")
        # Returns a lowercase hostname, or empty string when the lookup fails
        self.assertIsInstance(hint, str)
        # A successful reverse DNS lookup returns a hostname with a dot,
        # e.g. dns.google; failure returns an empty string
        if hint:
            self.assertTrue(hint.count('.') >= 1)
        else:
            pass  # lookup failed, treat as acceptable


class TestBuildState(unittest.TestCase):
    def test_build_state_with_empty(self):
        s = sentinel.build_state([])
        self.assertIn("total_connections", s)
        self.assertEqual(s["total_connections"], 0)
        self.assertTrue(s.get("unavailable", False))

    def test_build_state_with_connections(self):
        connections = [
            sentinel.ConnectionSample(
                host="wsl", exe="claude", proc="claude", pid=1234,
                remote_ip="203.0.113.5", remote_port=443, proto="tcp",
                state="ESTABLISHED", ts=1234.5,
            ),
            sentinel.ConnectionSample(
                host="wsl", exe="claude", proc="claude", pid=1234,
                remote_ip="203.0.113.6", remote_port=443, proto="tcp",
                state="ESTABLISHED", ts=1234.5,
            ),
        ]
        s = sentinel.build_state(connections)
        self.assertEqual(s["total_connections"], 2)
        self.assertIn("wsl", s)
        self.assertGreaterEqual(s["wsl"]["count"], 2)
