import unittest

from jarvis.impersonation import rules


def sev(findings, part):
    return [f["severity"] for f in findings if part in f["title"]]


class SessionTests(unittest.TestCase):
    ME = "DESK\\chris"

    def test_a_remote_desktop_session_is_high(self):
        out = rules.sessions({"me": self.ME, "logons": [
            {"id": "7", "type": 10, "user": self.ME, "start": "now"}]})

        self.assertEqual(sev(out, "Remote Desktop session"), ["high"])

    def test_another_account_holding_an_interactive_session_is_reported(self):
        out = rules.sessions({"me": self.ME, "logons": [
            {"id": "9", "type": 2, "user": "DESK\\someone", "start": "now"}]})

        self.assertEqual(sev(out, "belongs to another account"), ["medium"])

    def test_your_own_interactive_session_is_not_an_alert(self):
        out = rules.sessions({"me": self.ME, "logons": [
            {"id": "1", "type": 2, "user": self.ME, "start": "now"}]})

        self.assertEqual(sev(out, "no session belongs to anyone but you"),
                         ["ok"])

    def test_service_and_network_sessions_are_not_treated_as_people(self):
        out = rules.sessions({"me": self.ME, "logons": [
            {"id": "2", "type": 5, "user": "NT AUTHORITY\\SYSTEM"},
            {"id": "3", "type": 3, "user": "DESK\\other"}]})

        self.assertEqual(sev(out, "no session belongs to anyone but you"),
                         ["ok"])

    def test_machine_accounts_are_not_reported_as_other_people(self):
        out = rules.sessions({"me": self.ME, "logons": [
            {"id": "4", "type": 2, "user": "DESK\\DESKTOP$"}]})

        self.assertEqual(sev(out, "belongs to another account"), [])


class LockedInputTests(unittest.TestCase):
    def test_real_input_while_locked_is_critical(self):
        out = rules.input_while_locked({"locked": 1}, real_keys=12)

        self.assertEqual(sev(out, "while the workstation was locked"),
                         ["critical"])

    def test_a_locked_and_quiet_session_is_stated_as_ok(self):
        out = rules.input_while_locked({"locked": 1}, 0, 0)

        self.assertEqual([f["severity"] for f in out], ["ok"])

    def test_input_while_unlocked_is_not_an_alert(self):
        self.assertEqual(rules.input_while_locked({"locked": 0}, 500, 90), [])

    def test_unknown_lock_state_makes_no_claim_either_way(self):
        self.assertEqual(rules.input_while_locked({"locked": -1}, 500), [])


class AssistiveTechnologyTests(unittest.TestCase):
    """The ATs key mixes accessibility settings with assistive programs.

    A first cut flagged every setting -- stickykeys, highcontrast, filterkeys,
    whose ATExe is a number -- as a non-Windows automation surface, producing
    31 false HIGH findings on a clean machine.
    """

    def test_accessibility_settings_are_not_automation_surfaces(self):
        out = rules.automation({"atServices": [
            {"name": "stickykeys", "exe": "4"},
            {"name": "highcontrast", "exe": "1"},
            {"name": "cursorscheme", "exe": ""},
            {"name": "ScreenTint", "exe": "screentint"}]})

        self.assertEqual([f["severity"] for f in out], ["ok"])

    def test_a_stock_windows_assistive_program_is_low(self):
        out = rules.automation({"atServices": [
            {"name": "Narrator", "exe": "Narrator.exe"}]})

        self.assertEqual([f["severity"] for f in out], ["low"])
        self.assertIn("ships with Windows", out[0]["detail"])

    def test_a_third_party_assistive_program_is_high(self):
        out = rules.automation({"atServices": [
            {"name": "helper", "exe": "C:\\Users\\a\\AppData\\thing.exe"}]})

        self.assertEqual([f["severity"] for f in out], ["high"])
        self.assertIn("does not ship with Windows", out[0]["detail"])

    def test_a_program_under_the_windows_directory_is_stock(self):
        out = rules.automation({"atServices": [
            {"name": "x", "exe": "C:\\WINDOWS\\System32\\LiveCaptions.exe"}]})

        self.assertEqual([f["severity"] for f in out], ["low"])

    def test_startexe_is_used_when_atexe_is_only_a_flag(self):
        out = rules.automation({"atServices": [
            {"name": "x", "exe": "12", "startExe": "C:\\tmp\\drive.exe"}]})

        self.assertEqual([f["severity"] for f in out], ["high"])


class CredentialTests(unittest.TestCase):
    def test_automatic_logon_is_high_and_names_a_stored_password(self):
        out = rules.credentials({"autoLogon": {
            "enabled": "1", "user": "chris", "hasPassword": True}})

        hit = [f for f in out if "automatic logon" in f["title"]][0]
        self.assertEqual(hit["severity"], "high")
        self.assertIn("clear text", hit["detail"])

    def test_windows_own_credential_entries_are_not_reported(self):
        out = rules.credentials({"creds": [
            "virtualapp/didlogical", "MicrosoftAccount:user=x"]})

        self.assertEqual(sev(out, "stored credentials"), [])

    def test_real_saved_targets_are_reported_once(self):
        out = rules.credentials({"creds": [
            "LegacyGeneric:target=git:https://github.com"]})

        self.assertEqual(sev(out, "stored credentials"), ["medium"])


class AuditTests(unittest.TestCase):
    def test_a_missing_sample_is_unknown_not_clean(self):
        out = rules.audit_data(None)

        self.assertEqual([f["severity"] for f in out], ["low"])
        self.assertIn("unknown", out[0]["detail"])

    def test_every_finding_carries_the_shared_shape(self):
        out = rules.audit_data({"me": "D\\c", "logons": [], "locked": 0,
                                "atServices": [], "creds": []})
        for f in out:
            for key in ("category", "severity", "title", "detail", "where",
                        "host"):
                self.assertIn(key, f)


if __name__ == "__main__":
    unittest.main()
