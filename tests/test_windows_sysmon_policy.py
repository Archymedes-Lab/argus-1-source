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

    def test_registry_collection_is_high_signal_not_unbounded(self):
        event = self.event("RegistryEvent")
        self.assertEqual(event.attrib["onmatch"], "include")
        targets = [node.text for node in event.findall("TargetObject")]
        self.assertIn("\\CurrentControlSet\\Services\\", targets)
        self.assertIn("\\Image File Execution Options\\", targets)

    def test_credential_access_and_injection_evidence_remain_enabled(self):
        access = self.event("ProcessAccess")
        self.assertEqual(access.attrib["onmatch"], "include")
        self.assertIn("\\lsass.exe", [node.text for node in access])
        self.assertEqual(self.event("CreateRemoteThread").attrib["onmatch"], "exclude")

    def test_installer_verifies_process_starts_are_not_filtered_after_apply(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("$processCreate.Success", installer)
        self.assertIn("\\bfilter:\\s*", installer)


if __name__ == "__main__":
    unittest.main()
