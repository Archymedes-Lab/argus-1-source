import pathlib
import unittest
import xml.etree.ElementTree as ET

POLICY = pathlib.Path(__file__).parents[1] / "windows-sysmon" / "jarvis-windows-baseline.xml"
INSTALLER = pathlib.Path(__file__).parents[1] / "scripts" / "repair" / "apply-jarvis-sysmon-policy.ps1"


class WindowsSysmonPolicyTests(unittest.TestCase):
    def setUp(self):
        self.root = ET.parse(POLICY).getroot()
        self.events = self.root.find("EventFiltering")

    def event(self, name):
        return self.events.find(name)

    def test_policy_is_well_formed_and_uses_current_schema(self):
        self.assertEqual(self.root.tag, "Sysmon")
        self.assertEqual(self.root.attrib["schemaversion"], "4.90")

    def test_process_creation_has_no_exclusions(self):
        event = self.event("ProcessCreate")
        self.assertEqual(event.attrib["onmatch"], "exclude")
        self.assertEqual(list(event), [])

    def test_high_volume_process_termination_is_limited(self):
        event = self.event("ProcessTerminate")
        self.assertEqual(event.attrib["onmatch"], "include")
        self.assertEqual([node.text for node in event], ["C:\\Users\\", "\\Device\\"])

    def registry(self, onmatch):
        found = [event for event in self.events.iter("RegistryEvent")
                 if event.attrib["onmatch"] == onmatch]
        self.assertEqual(len(found), 1)
        return found[0]

    def test_registry_collection_is_high_signal_not_unbounded(self):
        event = self.registry("include")
        targets = [node.text for node in event.findall("TargetObject")]
        self.assertIn("\\CurrentControlSet\\Services\\", targets)
        self.assertIn("\\Image File Execution Options\\", targets)

    def test_registry_include_and_exclude_live_in_separate_rule_groups(self):
        groups = self.events.findall("RuleGroup")
        kinds = sorted(group.find("RegistryEvent").attrib["onmatch"] for group in groups
                       if group.find("RegistryEvent") is not None)
        self.assertEqual(kinds, ["exclude", "include"])

    def test_registry_exclusions_only_drop_measured_noise_operations(self):
        # Every exclusion is an AND of one noise operation and one key, so
        # deletions, renames and security value changes are never excluded.
        rules = self.registry("exclude").findall("Rule")
        self.assertEqual(len(rules), 5)
        for rule in rules:
            self.assertEqual(rule.attrib["groupRelation"], "and")
            (kind,) = [n.text for n in rule.findall("EventType")]
            (target,) = [n.text for n in rule.findall("TargetObject")]
            self.assertIn(kind, ("CreateKey", "SetValue"))
            self.assertIn("\\Services\\", target)
        excluded = [n.text for n in self.registry("exclude").iter("TargetObject")]
        for signal in ("NameServer", "\\Parameters\\ServiceDll", "ImagePath",
                       "\\CurrentVersion\\Run", "Winlogon", "NtpServer"):
            self.assertFalse(any(signal in value for value in excluded), signal)
        self.assertEqual(sum(1 for event in self.events.iter("RegistryEvent")
                             for _ in event.iter("EventType")
                             if _.text in ("DeleteKey", "DeleteValue", "RenameKey")), 0)

    def test_credential_access_and_injection_evidence_remain_enabled(self):
        access = self.event("ProcessAccess")
        self.assertEqual(access.attrib["onmatch"], "include")
        self.assertIn("\\lsass.exe", [node.text for node in access])
        self.assertEqual(self.event("CreateRemoteThread").attrib["onmatch"], "exclude")

    def test_installer_verifies_process_starts_are_not_filtered_after_apply(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("$create.Success", installer)
        self.assertIn("\\bfilter:\\s*", installer)

    def test_installer_refuses_unexpected_policy_and_backs_up_first(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        refuse = installer.index("does not match the expected")
        backup = installer.index("reg.exe export")
        apply = installer.index("& $svc.Exe -c $PolicyPath")
        self.assertLess(refuse, backup)
        self.assertLess(backup, apply)
        self.assertIn("Jarvis\\Vault", installer)
        self.assertIn("-Pattern 'Rules'", installer)

    def test_installer_restores_the_backup_when_verification_fails(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        failed = installer.index("if (-not $receipt.verified)")
        self.assertIn("Restore-Backup $backup", installer[failed:])
        for check in ("running config hash differs", "ProcessCreate is filtered",
                      "registry noise exclusions are missing"):
            self.assertIn(check, installer)


if __name__ == "__main__":
    unittest.main()
