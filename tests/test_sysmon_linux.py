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
