"""Without the administrator sensor, affected jobs say so and coverage is never full."""

import unittest
from unittest import mock

from jarvis.core import elevated
from jarvis.platform import broker

LABELS = {j: j.title() for j in elevated.ADMIN_SENSOR_JOBS} | {"scan": "Processes"}


class ElevatedHonestyTest(unittest.TestCase):
    def test_every_affected_job_is_named_with_the_one_reason(self):
        out = elevated.blind_entries(LABELS, is_absent=True)
        self.assertEqual({e["job"] for e in out}, set(elevated.ADMIN_SENSOR_JOBS))
        self.assertTrue(all(e["reason"] == "Needs administrator sensor" for e in out))
        self.assertNotIn("scan", {e["job"] for e in out}, "jobs that need no sensor are not accused")

    def test_a_job_already_blind_keeps_its_own_more_specific_reason(self):
        out = elevated.blind_entries(LABELS, already={"native"}, is_absent=True)
        self.assertNotIn("native", {e["job"] for e in out})

    def test_nothing_is_reported_once_the_sensor_is_installed(self):
        self.assertEqual(elevated.blind_entries(LABELS, is_absent=False), [])

    def test_unavailable_and_limited_are_distinguished(self):
        levels = {e["job"]: e["level"] for e in elevated.blind_entries(LABELS, is_absent=True)}
        self.assertEqual(levels["fwaudit"], "unavailable")
        self.assertEqual(levels["memscan"], "limited")

    def test_the_broker_gives_the_same_reason_when_it_is_missing(self):
        with mock.patch.object(broker, "installed", return_value=False):
            data, why = broker.result(next(iter(broker.SCRIPTS)))
        self.assertIsNone(data)
        self.assertTrue(why.startswith("Needs administrator sensor"), why)

    def test_linux_is_never_accused(self):
        with mock.patch("sys.platform", "linux"):
            self.assertFalse(elevated.absent())


if __name__ == "__main__":
    unittest.main()
