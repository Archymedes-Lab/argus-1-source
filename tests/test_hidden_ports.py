import tempfile
import pathlib
import unittest
from unittest.mock import patch
from jarvis import hidden


class PortVisibilityTests(unittest.TestCase):
    def test_all_inode_zero_time_wait_ports_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            net = pathlib.Path(directory) / 'net'
            net.mkdir()
            (net / 'tcp').write_text('header\n0: 0100007F:9090 remote 06 0 0 0 0 0 0\n1: 0100007F:9091 remote 06 0 0 0 0 0 0\n')
            with patch.object(hidden, 'PROC', directory):
                self.assertEqual(hidden._visible_tcp_ports(), {0x9090, 0x9091})

    def test_unreadable_table_is_not_empty_clean_table(self):
        with patch.object(hidden, '_visible_tcp_ports', return_value=None):
            with self.assertRaises(RuntimeError):
                hidden.hidden_listeners(1)
