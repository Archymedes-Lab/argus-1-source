"""Durable, idempotent import of immutable native sensor batches."""
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

MAX_BATCH_BYTES = 16 * 1024 * 1024
SCHEMA = '''
CREATE TABLE IF NOT EXISTS batches (
 sensor TEXT NOT NULL, channel TEXT NOT NULL, sequence INTEGER NOT NULL,
 digest TEXT NOT NULL, imported_at REAL NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(sensor,channel,sequence));
CREATE TABLE IF NOT EXISTS events (
 host TEXT NOT NULL, channel TEXT NOT NULL, generation TEXT NOT NULL,
 record_id INTEGER NOT NULL, event_id INTEGER NOT NULL, event_time TEXT NOT NULL,
 xml TEXT NOT NULL, digest TEXT NOT NULL, sensor TEXT NOT NULL,
 PRIMARY KEY(host,channel,generation,record_id));
CREATE TABLE IF NOT EXISTS cursors (
 sensor TEXT NOT NULL, channel TEXT NOT NULL, sequence INTEGER NOT NULL,
 generation TEXT NOT NULL, bookmark TEXT NOT NULL, status TEXT NOT NULL,
 observed_at TEXT NOT NULL, imported_at REAL NOT NULL,
 PRIMARY KEY(sensor,channel));
CREATE TABLE IF NOT EXISTS gaps (
 sensor TEXT NOT NULL, channel TEXT NOT NULL, sequence INTEGER NOT NULL,
 reason TEXT NOT NULL, recorded_at REAL NOT NULL,
 PRIMARY KEY(sensor,channel,sequence));
'''


class BatchError(ValueError):
    pass


def _text(value, name, maximum=4096):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise BatchError('invalid ' + name)
    return value


def validate(batch):
    if not isinstance(batch, dict) or batch.get('schema') != 1:
        raise BatchError('unsupported schema')
    for name in ('sensor_id', 'host_id', 'channel', 'generation', 'created_at'):
        _text(batch.get(name), name)
    sequence = batch.get('sequence')
    if type(sequence) is not int or sequence < 1 or sequence > 2**63 - 1:
        raise BatchError('invalid sequence')
    if batch.get('previous_sequence') != sequence - 1:
        raise BatchError('invalid previous sequence')
    if batch.get('status') not in ('complete', 'partial', 'unavailable'):
        raise BatchError('invalid status')
    if not isinstance(batch.get('bookmark'), str):
        raise BatchError('invalid bookmark')
    events = batch.get('events')
    if not isinstance(events, list) or len(events) > 500:
        raise BatchError('invalid event batch')
    seen = set()
    for event in events:
        if not isinstance(event, dict):
            raise BatchError('invalid event')
        record = event.get('record_id')
        if type(record) is not int or not 0 < record < 2**63 or record in seen:
            raise BatchError('invalid or duplicate record ID')
        seen.add(record)
        if type(event.get('event_id')) is not int or not 0 <= event['event_id'] <= 65535:
            raise BatchError('invalid event ID')
        _text(event.get('time'), 'event time')
        _text(event.get('xml'), 'event XML', 1024 * 1024)
    if batch.get('gap') is not None:
        _text(batch['gap'], 'gap')
    return batch


class EventStore:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def ingest(self, raw):
        if len(raw) > MAX_BATCH_BYTES:
            raise BatchError('batch exceeds size limit')
        batch = validate(json.loads(raw))
        digest = hashlib.sha256(raw).hexdigest()
        sensor, channel, seq = batch['sensor_id'], batch['channel'], batch['sequence']
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            existing = self.db.execute('SELECT digest FROM batches WHERE sensor=? AND channel=? AND sequence=?',
                                       (sensor, channel, seq)).fetchone()
            if existing:
                if existing[0] != digest:
                    raise BatchError('batch identity reused with different content')
                return {'duplicate': True, 'events': 0}
            cursor = self.db.execute('SELECT sequence,generation FROM cursors WHERE sensor=? AND channel=?',
                                     (sensor, channel)).fetchone()
            if seq != (cursor[0] if cursor else 0) + 1:
                raise BatchError('missing or out-of-order batch; cursor unchanged')
            if cursor and batch['generation'] != cursor[1] and not batch.get('gap'):
                raise BatchError('log generation changed without a gap record')
            stamp = time.time()
            count = 0
            for event in batch['events']:
                identity = (batch['host_id'], channel, batch['generation'], event['record_id'])
                event_hash = hashlib.sha256(event['xml'].encode()).hexdigest()
                old = self.db.execute('SELECT digest FROM events WHERE host=? AND channel=? AND generation=? AND record_id=?', identity).fetchone()
                if old and old[0] != event_hash:
                    raise BatchError('event identity conflict; entire batch rolled back')
                if not old:
                    self.db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)',
                                    (*identity, event['event_id'], event['time'], event['xml'], event_hash, sensor))
                    count += 1
            self.db.execute('INSERT INTO batches VALUES(?,?,?,?,?,?)',
                            (sensor, channel, seq, digest, stamp, raw.decode('utf-8')))
            if batch.get('gap'):
                self.db.execute('INSERT INTO gaps VALUES(?,?,?,?,?)', (sensor, channel, seq, batch['gap'], stamp))
            self.db.execute('INSERT INTO cursors VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(sensor,channel) DO UPDATE SET '
                            'sequence=excluded.sequence,generation=excluded.generation,bookmark=excluded.bookmark,'
                            'status=excluded.status,observed_at=excluded.observed_at,imported_at=excluded.imported_at',
                            (sensor, channel, seq, batch['generation'], batch['bookmark'], batch['status'], batch['created_at'], stamp))
        return {'duplicate': False, 'events': count}

    def import_directory(self, directory):
        result = {'batches': 0, 'events': 0, 'duplicates': 0, 'errors': []}
        # Native filenames use fixed-width sequence numbers, one directory/channel.
        for path in sorted(Path(directory).glob('*/*.json')):
            if path.name == 'health.json':
                continue
            try:
                with path.open('rb') as stream:
                    item = self.ingest(stream.read(MAX_BATCH_BYTES + 1))
                result['duplicates' if item['duplicate'] else 'batches'] += 1
                result['events'] += item['events']
            except (OSError, ValueError, sqlite3.Error) as exc:
                result['errors'].append({'file': str(path), 'error': str(exc)[:240]})
                # Do not advance through a missing/corrupt batch.
                break
        return result
