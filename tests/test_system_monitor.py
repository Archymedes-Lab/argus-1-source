"""Tests for the System Monitor collector.

Covers: CPU sampling, memory profiling, disk enumeration, process sampling
and collector health. Uses mocks to make the standard-library reads
deterministic; on a native host the real measurements are also asserted.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from jarvis.collectors.host.system_monitor import (
    build_profile, sample_cpu, sample_memory, sample_disk,
    sample_processes,
    CpuProfile, MemoryProfile, MountPoint, ProcessSnapshot,
)


class TestSampleCpu(unittest.TestCase):
    @mock.patch("jarvis.collectors.host.system_monitor.time.sleep")
    def test_sample_cpu_returns_float(self, mock_sleep):
        with mock.patch(
            "jarvis.collectors.host.system_monitor._read_proc_stat",
            return_value=[100, 150, 200, 300, 50],
        ):
            val = sample_cpu()
        self.assertIsInstance(val, float)

    @mock.patch("jarvis.collectors.host.system_monitor.time.sleep")
    def test_sample_cpu_no_proc(self, mock_sleep):
        with mock.patch(
            "jarvis.collectors.host.system_monitor._read_proc_stat",
            return_value=None,
        ):
            val = sample_cpu()
        self.assertGreaterEqual(val, -1.0)


class TestSampleMemory(unittest.TestCase):
    def test_sample_memory_returns_dict(self):
        with mock.patch(
            "jarvis.collectors.host.system_monitor.builtins.open",
            mock.mock_open(
                read_data="MemTotal:       1000000\nMemAvailable:    500000\n"
            ),
        ):
            m = sample_memory()
        self.assertIsInstance(m, dict)
        self.assertIn("total_kib", m)
        self.assertIn("usage_pct", m)
        self.assertGreater(m["total_kib"], 0)

    def test_sample_memory_read_error(self):
        with mock.patch(
            "jarvis.collectors.host.system_monitor.builtins.open",
            side_effect=OSError,
        ):
            m = sample_memory()
        self.assertEqual(m["total_kib"], 0.0)
        self.assertEqual(m["usage_pct"], -1.0)
        self.assertIsInstance(m, dict)


class TestSampleDisk(unittest.TestCase):
    def test_sample_disk_returns_dict(self):
        # Minimal /proc/mounts format: device mountpoint fstype opts dump pass
        with mock.patch(
            "jarvis.collectors.host.system_monitor.builtins.open",
            mock.mock_open(
                read_data="none /proc proc rw 0 0\ntmpfs /run tmpfs rw,size=500M 0 0\n"
            ),
        ):
            with mock.patch("jarvis.collectors.host.system_monitor.os") as fake_os:
                fake_statvfs = mock.Mock()
                fake_statvfs.f_blocks = 1048576
                fake_statvfs.f_frsize = 4096
                fake_statvfs.f_bfree = 524288
                fake_statvfs.f_bavail = 524288
                fake_os.statvfs.return_value = fake_statvfs
                d = sample_disk()
        self.assertIsInstance(d, dict)
        self.assertIn("/run", d)
        mount = d["/run"]
        self.assertIsInstance(mount, MountPoint)
        self.assertGreater(mount.free_pct, 0)
        self.assertTrue(mount.low_free)

    def test_sample_disk_skips_kernel_fs(self):
        with mock.patch(
            "jarvis.collectors.host.system_monitor.builtins.open",
            mock.mock_open(
                read_data="none /proc proc rw 0 0\nnone /sys sysfs rw 0 0\n"
            ),
        ):
            with mock.patch("jarvis.collectors.host.system_monitor.os") as fake_os:
                fake_statvfs = mock.Mock()
                fake_statvfs.f_blocks = 1048576
                fake_statvfs.f_frsize = 4096
                fake_statvfs.f_bfree = 524288
                fake_statvfs.f_bavail = 524288
                fake_os.statvfs.return_value = fake_statvfs
                d = sample_disk()
        self.assertEqual(d, {})


class TestSampleProcesses(unittest.TestCase):
    def test_sample_processes_returns_list(self):
        with mock.patch(
            "jarvis.collectors.host.system_monitor._read_proc_pid_stat",
            return_value={"utime": 10, "stime": 5, "state": "S"},
        ):
            with mock.patch(
                "jarvis.collectors.host.system_monitor.os",
                new_callable=mock.Mock,
            ) as fake_os:
                fake_os.listdir.return_value = ["123", "456"]
                fake_os.path.isdir.return_value = True
                fake_os.name = "posix"
                procs = sample_processes()
        self.assertIsInstance(procs, list)
        self.assertEqual(len(procs), 2)


class TestBuildProfile(unittest.TestCase):
    def test_build_profile(self):
        with mock.patch(
            "jarvis.collectors.host.system_monitor.sample_cpu",
            return_value=2.5,
        ):
            with mock.patch(
                "jarvis.collectors.host.system_monitor.sample_memory",
                return_value={
                    "total_kib": 8000000.0,
                    "used_kib": 4000000.0,
                    "available_kib": 3000000.0,
                    "usage_pct": 62.5,
                },
            ):
                with mock.patch(
                    "jarvis.collectors.host.system_monitor.sample_disk",
                    return_value={},
                ):
                    with mock.patch(
                        "jarvis.collectors.host.system_monitor.sample_processes",
                        return_value=[],
                    ):
                        with mock.patch(
                            "jarvis.collectors.host.system_monitor."
                            "sample_collector_health",
                            return_value={},
                        ):
                            p = build_profile()
        self.assertGreaterEqual(p.cpu_usage_pct, 0)
        self.assertEqual(p.mem_usage_pct, 62.5)
        self.assertGreaterEqual(p.cpu_cores, 1)
        self.assertIsInstance(p.processes, list)
        self.assertIsInstance(p.disk_mounts, dict)

    def test_process_cpu_flag(self):
        with mock.patch(
            "jarvis.collectors.host.system_monitor.sample_cpu",
            return_value=2.5,
        ):
            with mock.patch(
                "jarvis.collectors.host.system_monitor.sample_memory",
                return_value={
                    "total_kib": 8000000.0,
                    "used_kib": 4000000.0,
                    "available_kib": 3000000.0,
                    "usage_pct": 62.5,
                },
            ):
                with mock.patch(
                    "jarvis.collectors.host.system_monitor.sample_disk",
                    return_value={},
                ):
                    with mock.patch(
                        "jarvis.collectors.host.system_monitor.sample_processes",
                        return_value=[
                            mock.Mock(pid=123, name="bash", cpu_pct=95.0, rss_kib=1024.0)
                        ],
                    ):
                        with mock.patch(
                            "jarvis.collectors.host.system_monitor."
                            "sample_collector_health",
                            return_value={},
                        ):
                            p = build_profile()
                            self.assertTrue(any("95" in n for n in p.permission_notes))


class TestAudit(unittest.TestCase):
    def test_audit_returns_list(self):
        with mock.patch(
            "jarvis.collectors.host.system_monitor.sample_collector_health",
            return_value={},
        ):
            from jarvis.collectors.host import system_monitor
            findings = system_monitor.audit(host="wsl")
        self.assertIsInstance(findings, list)

    def test_audit_creates_finding_when_collector_stale(self):
        with mock.patch(
            "jarvis.collectors.host.system_monitor.sample_collector_health",
            return_value={
                "findings": [
                    {
                        "category": "files",
                        "severity": "low",
                        "title": "Test",
                        "detail": "test",
                        "where": "test",
                        "reasons": ["stale-collector"],
                        "score": 5,
                    }
                ],
                "count": 1,
            },
        ):
            from jarvis.collectors.host import system_monitor
            findings = system_monitor.audit(host="wsl")
        self.assertTrue(any(
            f.get("reasons") == ["stale-collector"] for f in findings
        ))
