import unittest
from unittest import mock

from jarvis.intel import hunt


def _row(norm):
    return {'norm': norm, 'context': 'ctx', 'source_url': 'u'}


class CheckPathsTest(unittest.TestCase):
    def run_paths(self, rows, signed):
        with mock.patch.object(hunt, '_active', return_value=rows), \
             mock.patch('os.path.lexists', return_value=True), \
             mock.patch('os.path.isdir', return_value=False), \
             mock.patch('os.path.isfile', return_value=True), \
             mock.patch.object(hunt, '_microsoft_signed',
                               side_effect=lambda p: set(p) & signed) as sig:
            return hunt.check_paths(None), sig

    def test_signed_stock_binary_is_not_reported(self):
        out, _ = self.run_paths([_row('C:\\\\Windows\\\\System32\\\\rundll32.exe'),
                                 _row('C:\\Windows\\explorer.exe')],
                                {'C:\\Windows\\System32\\rundll32.exe',
                                 'C:\\Windows\\explorer.exe'})
        self.assertEqual(out, [])

    def test_unsigned_windows_drop_is_reported(self):
        out, _ = self.run_paths([_row('C:\\Windows\\cloudflared.exe')], set())
        self.assertEqual(len(out), 1)

    def test_signed_binary_in_writable_dir_is_still_reported(self):
        out, sig = self.run_paths([_row('C:\\Windows\\Temp\\dbghelp.dll')],
                                  {'C:\\Windows\\Temp\\dbghelp.dll'})
        self.assertEqual(len(out), 1)
        self.assertEqual(sig.call_args[0][0], set())


if __name__ == '__main__':
    unittest.main()
