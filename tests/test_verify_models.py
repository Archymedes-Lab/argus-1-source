"""Exhaustive checks of the protocol models, through the real code where it is pure."""

import unittest

from jarvis.verify.models import lanes, privacy_seal, release


class PrivacySealModelTests(unittest.TestCase):
    def test_every_reachable_state_keeps_the_seal_invariants(self):
        r = privacy_seal.model().check()
        self.assertTrue(r.ok, str(r))
        self.assertTrue(r.exhausted, str(r))
        self.assertGreater(r.states, 40)

    def test_a_breach_is_reachable_and_then_reported(self):
        # Sanity: the model can express a breach, so the invariant is not vacuous.
        m = privacy_seal.model()
        path = m.reachable(lambda s: s.sampled and s.reported)
        self.assertIsNotNone(path)
        self.assertIn("collect", [a for a, _ in path])

    def test_planted_bug_is_caught(self):
        # If the collector stopped treating a reopened desktop value as a breach,
        # the checker must say so: swap the real function for a weakened one.
        real = privacy_seal.ps._seal_findings

        def weakened(current, seal, previous):
            row = current["caps"]["microphone"]
            row["user"]["nonpackaged"] = "Deny"      # ignore desktop reopen
            return real(current, seal, previous)
        privacy_seal.ps._seal_findings = weakened
        try:
            r = privacy_seal.model().check()
        finally:
            privacy_seal.ps._seal_findings = real
        self.assertFalse(r.ok)
        self.assertEqual(r.violated, "a breach is reported high by the next collection")
        self.assertIn("reopen_desktop", [a for a, _ in r.counterexample])


class ReleaseModelTests(unittest.TestCase):
    def test_stale_base_is_always_refused(self):
        r = release.model().check()
        self.assertTrue(r.ok, str(r))
        self.assertTrue(r.exhausted, str(r))

    def test_refusal_is_reachable(self):
        m = release.model()
        path = m.reachable(lambda s: s.last == "refused")
        self.assertIsNotNone(path)
        self.assertEqual([a for a, _ in path][:3], ["stage", "foreign_switch", "deploy"])

    def test_rollback_after_a_deploy_restores_the_previous_release(self):
        m = release.model()
        path = m.reachable(lambda s: s.last == "deployed")
        deployed = path[-1][1]
        rolled = release.act_rollback(deployed)[0]
        self.assertEqual(rolled.live, deployed.live - 1)


class LaneModelTests(unittest.TestCase):
    def test_fast_lane_never_waits_behind_main(self):
        r = lanes.model().check()
        self.assertTrue(r.ok and r.exhausted, str(r))

    def test_protection_jobs_are_in_the_fast_lane(self):
        self.assertTrue(lanes.required_fast_jobs_are_in_the_fast_lane())


if __name__ == "__main__":
    unittest.main()
