"""Tests for the DeepScan collector.

Filesystem auditing: executable detection, hash computation, persistence
planting detection and risk scoring. Tests run against the real file system
for fast fixtures (e.g. /tmp); production calls to subprocess or external
services are mocked where they would require a live endpoint.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from jarvis.collectors.host.deepscan import scan_file, scan_directory


class TestScanFile(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cleanup_files = []

    def tearDown(self):
        for f in self.cleanup_files:
            try:
                os.unlink(f)
            except OSError:
                pass
        try:
            os.rmdir(self.tmpdir)
        except OSError:
            pass

    def test_scan_file_skips_non_regular(self):
        # Create a symlink; on Windows this requires admin, so mock the
        # os.path.islink check instead.
        with mock.patch("os.path.islink", return_value=True):
            with mock.patch("os.path.isfile", return_value=False):
                r = scan_file("/some/link", host="wsl")
        self.assertFalse(r.get("accessible"))

    def test_scan_file_regular(self):
        f = os.path.join(self.tmpdir, "plain.sh")
        with open(f, "w") as fh:
            fh.write("#!/bin/bash\necho ok\n")
        self.cleanup_files.append(f)
        r = scan_file(f, host="wsl")
        self.assertTrue(r.get("accessible"))
        self.assertIn("path", r)
        self.assertIn("executable", r)
        self.assertIn("hash", r)
        self.assertIn("size", r)

    def test_scan_file_result_keys(self):
        f = os.path.join(self.tmpdir, "keys.sh")
        with open(f, "w") as fh:
            fh.write("echo test\n")
        self.cleanup_files.append(f)
        r = scan_file(f, host="wsl")
        for key in ("host", "path", "size", "hash", "executable", "permissions"):
            self.assertIn(key, r)


class TestScanDirectory(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cleanup_files = []

    def tearDown(self):
        for f in self.cleanup_files:
            try:
                os.unlink(f)
            except OSError:
                pass
        try:
            os.rmdir(self.tmpdir)
        except OSError:
            pass

    def test_scan_directory_returns_list(self):
        findings = scan_directory(self.tmpdir, host="wsl", max_depth=1)
        self.assertIsInstance(findings, list)
        for f in findings:
            for key in ("path", "category", "severity", "score", "hash"):
                self.assertIn(key, f)

    def test_scan_directory_returns_finding_for_executable(self):
        f = os.path.join(self.tmpdir, "suspicious.sh")
        with open(f, "w") as fh:
            fh.write("#!/bin/bash\n")
        self.cleanup_files.append(f)
        findings = scan_directory(self.tmpdir, host="wsl", max_depth=1)
        self.assertTrue(any(
            "executable" in str(f) for f in findings
        ))


class TestAudit(unittest.TestCase):
    def test_audit_returns_list(self):
        from jarvis.collectors.host import deepscan
        with mock.patch(
            "jarvis.collectors.host.deepscan.scan_directory",
            return_value=[],
        ):
            findings = deepscan.audit(host="wsl")
        self.assertIsInstance(findings, list)

    def test_audit_returns_empty_list_when_no_roots(self):
        from jarvis.collectors.host import deepscan
        with mock.patch(
            "jarvis.collectors.host.deepscan.os.path.isdir",
            return_value=False,
        ):
            findings = deepscan.audit(host="wsl")
        self.assertEqual(findings, [])
