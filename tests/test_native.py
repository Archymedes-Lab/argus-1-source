import copy
import json
import tempfile
import unittest
from pathlib import Path

from jarvis.native.store import BatchError, EventStore


def batch(sequence=1, events=None):
    return {'schema': 1, 'sensor_id': 'sensor', 'host_id': 'host', 'channel': 'Sysmon',
            'generation': 'generation-1', 'sequence': sequence, 'previous_sequence': sequence-1,
            'created_at': '2026-09-13T12:00:00Z', 'bookmark': '<Bookmark/>',
            'status': 'complete', 'gap': None,
            'events': events if events is not None else [
                {'record_id': 1, 'event_id': 1, 'time': '2026-09-13T12:00:00Z', 'xml': '<Event>original</Event>'}]}


class NativeIngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'events.db'
        self.store = EventStore(self.path)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def ingest(self, value):
        return self.store.ingest(json.dumps(value).encode())

    def test_replay_after_restart_is_idempotent(self):
        self.assertEqual(self.ingest(batch())['events'], 1)
        self.store.close(); self.store = EventStore(self.path)
        self.assertTrue(self.ingest(batch())['duplicate'])
        self.assertEqual(self.store.db.execute('select count(*) from events').fetchone()[0], 1)

    def test_out_of_order_does_not_advance(self):
        with self.assertRaises(BatchError):
            self.ingest(batch(2))
        self.assertEqual(self.store.db.execute('select count(*) from cursors').fetchone()[0], 0)

    def test_conflict_rolls_back_earlier_event_in_same_batch(self):
        self.ingest(batch())
        events = [dict(batch()['events'][0], record_id=2), dict(batch()['events'][0], xml='<Event>changed</Event>')]
        with self.assertRaises(BatchError):
            self.ingest(batch(2, events))
        self.assertEqual(self.store.db.execute('select count(*) from events').fetchone()[0], 1)
        self.assertEqual(self.store.db.execute('select sequence from cursors').fetchone()[0], 1)

    def test_changed_batch_identity_rejected(self):
        self.ingest(batch())
        changed = batch(); changed['bookmark'] = 'changed'
        with self.assertRaises(BatchError): self.ingest(changed)

    def test_generation_reset_requires_gap_and_keeps_old_event(self):
        self.ingest(batch())
        changed = batch(2); changed['generation'] = 'generation-2'
        with self.assertRaises(BatchError): self.ingest(changed)
        changed['gap'] = 'channel cleared'
        self.ingest(changed)
        self.assertEqual(self.store.db.execute('select count(*) from events').fetchone()[0], 2)
        self.assertEqual(self.store.db.execute('select count(*) from gaps').fetchone()[0], 1)

    def test_repeated_event_across_batches_is_deduplicated(self):
        self.ingest(batch()); self.assertEqual(self.ingest(batch(2))['events'], 0)

    def test_duplicate_record_inside_batch_is_rejected(self):
        with self.assertRaises(BatchError): self.ingest(batch(events=batch()['events']*2))

    def test_import_stops_before_corrupt_sequence(self):
        directory = Path(self.temp.name)/'spool'/'channel'; directory.mkdir(parents=True)
        (directory/'0001.json').write_text(json.dumps(batch()))
        (directory/'0002.json').write_text('{')
        (directory/'0003.json').write_text(json.dumps(batch(3, [])))
        result = self.store.import_directory(directory.parent)
        self.assertEqual(result['batches'], 1)
        self.assertEqual(len(result['errors']), 1)
        self.assertEqual(self.store.db.execute('select sequence from cursors').fetchone()[0], 1)
