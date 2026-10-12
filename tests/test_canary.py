"""Canary tokens and the tamper-evident journal (2026-10-12).

Covers: the append-only hash chain and its tamper detection; inert token
generation; the on-box fingerprint tripwire; owner-listener callback ingestion;
external anchoring with an injected submit; and the collector end to end. No
network, no real bait placed outside the temp dir, no attacker ever contacted.
"""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from jarvis.collectors.host import canary as canary_job
from jarvis.core import canary


class FakeStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key):
        return self.meta.get(key)

    def set_meta(self, key, value):
        self.meta[key] = value

    def commit(self):
        pass


class JournalChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.journal = canary.CanaryJournal(self.root)

    def test_append_and_verify_clean_chain(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})
        self.journal.append("trip", {"id": "a", "reason": "modified"})
        self.assertIsNone(self.journal.verify())
        head = self.journal.head()
        self.assertEqual(head["seq"], 2)
        self.assertNotEqual(head["hash"], canary.GENESIS)

    def test_edit_breaks_the_chain(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})
        self.journal.append("plant", {"id": "b", "kind": "credential"})
        recs = [json.loads(line) for line in
                self.journal.path.read_text().splitlines()]
        recs[0]["payload"]["id"] = "tampered"          # edit, keep the stored hash
        self.journal.path.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in recs) + "\n")
        broken = self.journal.verify()
        self.assertIsNotNone(broken)
        self.assertEqual(broken["seq"], 1)
        self.assertEqual(broken["reason"], "record altered")

    def test_deletion_breaks_the_chain(self):
        for i in range(3):
            self.journal.append("plant", {"id": str(i), "kind": "credential"})
        lines = self.journal.path.read_text().splitlines()
        del lines[1]                                    # drop the middle record
        self.journal.path.write_text("\n".join(lines) + "\n")
        broken = self.journal.verify()
        self.assertIsNotNone(broken)
        # The record that was seq 3 now sits where seq 2 is expected.
        self.assertEqual(broken["reason"], "sequence break")

    def test_reorder_breaks_the_chain(self):
        for i in range(3):
            self.journal.append("plant", {"id": str(i), "kind": "credential"})
        lines = self.journal.path.read_text().splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        self.journal.path.write_text("\n".join(lines) + "\n")
        self.assertIsNotNone(self.journal.verify())

    def test_corrupt_line_is_a_break_not_a_crash(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})
        # A non-UTF-8 byte and garbage appended by a clumsy tamperer.
        with open(self.journal.path, "ab") as fh:
            fh.write(b"\xff not json at all\n")
        broken = self.journal.verify()          # must not raise
        self.assertIsNotNone(broken)
        self.assertEqual(broken["reason"], "corrupt record")
        # State still enumerates the valid records without throwing.
        self.assertIn("a", self.journal.state()["tokens"])

    def test_record_hash_is_independent_of_key_order(self):
        rec = {"seq": 1, "at": 5, "kind": "plant", "prev": canary.GENESIS,
               "payload": {"b": 2, "a": 1}}
        h1 = canary.record_hash(rec)
        rec2 = {"payload": {"a": 1, "b": 2}, "prev": canary.GENESIS,
                "kind": "plant", "at": 5, "seq": 1, "hash": "ignored"}
        self.assertEqual(h1, canary.record_hash(rec2))


class TokenGenerationTests(unittest.TestCase):
    def test_file_decoy_captures_fingerprint(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("BEGIN OPENSSH PRIVATE KEY\n")
            path = fh.name
        self.addCleanup(os.unlink, path)
        token = canary.make_token("file_decoy", "ssh key", path=path)
        self.assertEqual(token["kind"], "file_decoy")
        self.assertIn("sha256", token["fingerprint"])
        self.assertEqual(token["fingerprint"]["size"], os.path.getsize(path))

    def test_doc_url_requires_owner_base_and_is_unique(self):
        with self.assertRaises(canary.CanaryError):
            canary.make_token("doc_url", "plan")                     # no base
        with self.assertRaises(canary.CanaryError):
            canary.make_token("doc_url", "plan", url_base="not-a-url")
        t1 = canary.make_token("doc_url", "plan", url_base="https://c.example.com/")
        t2 = canary.make_token("doc_url", "plan", url_base="https://c.example.com")
        self.assertTrue(t1["url"].startswith("https://c.example.com/c/"))
        self.assertNotEqual(t1["url"], t2["url"])        # unique per token
        self.assertEqual(t1["url"].count("://"), 1)      # points only at the owner

    def test_credential_is_fake_and_unique(self):
        t1 = canary.make_token("credential", "aws")
        t2 = canary.make_token("credential", "aws")
        self.assertTrue(t1["bait_value"].startswith("AKIA"))
        self.assertNotEqual(t1["bait_value"], t2["bait_value"])
        self.assertIn("secret_fp", t1)

    def test_unknown_kind_rejected(self):
        with self.assertRaises(canary.CanaryError):
            canary.make_token("bomb", "no")


class OnboxTripwireTests(unittest.TestCase):
    def _decoy(self, content="secret"):
        fh = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        fh.write(content)
        fh.close()
        self.addCleanup(lambda: os.path.exists(fh.name) and os.unlink(fh.name))
        return fh.name

    def test_untouched_decoy_does_not_trip(self):
        path = self._decoy()
        token = canary.make_token("file_decoy", "d", path=path)
        self.assertEqual(canary.onbox_trips({token["id"]: token}), [])

    def test_modified_decoy_trips(self):
        path = self._decoy("original")
        token = canary.make_token("file_decoy", "d", path=path)
        time.sleep(0.01)
        Path(path).write_text("CHANGED BY INTRUDER")
        os.utime(path, (time.time() + 5, time.time() + 5))
        trips = canary.onbox_trips({token["id"]: token})
        self.assertEqual(len(trips), 1)
        self.assertEqual(trips[0]["reason"], "modified")

    def test_same_size_same_mtime_edit_still_caught_by_hash(self):
        path = self._decoy("AAAA")
        token = canary.make_token("file_decoy", "d", path=path)
        st = os.stat(path)
        Path(path).write_text("BBBB")                    # same length
        os.utime(path, (st.st_atime, st.st_mtime))       # restore mtime
        trips = canary.onbox_trips({token["id"]: token})
        self.assertEqual([t["reason"] for t in trips], ["modified"])

    def test_removed_decoy_trips(self):
        path = self._decoy()
        token = canary.make_token("file_decoy", "d", path=path)
        os.unlink(path)
        trips = canary.onbox_trips({token["id"]: token})
        self.assertEqual(trips[0]["reason"], "removed")

    def test_access_is_weak_and_off_by_default(self):
        token = {"id": "x", "kind": "file_decoy", "path": "/decoy",
                 "created_at": 100, "fingerprint": {"sha256": "h", "size": 4,
                                                    "mtime": 200}}
        st = SimpleNamespace(st_size=4, st_mtime=200, st_atime=999)
        stat = lambda p: st
        reader = lambda p: b"same"
        # "same" hashes to something != "h", so without check_access this reads
        # as a (false) modification unless the hash matches; force the hash match:
        import hashlib
        token["fingerprint"]["sha256"] = hashlib.sha256(b"same").hexdigest()
        self.assertEqual(canary.onbox_trips({"x": token}, stat=stat,
                                            read_bytes=reader), [])
        trips = canary.onbox_trips({"x": token}, stat=stat, read_bytes=reader,
                                   check_access=True)
        self.assertEqual([t["reason"] for t in trips], ["accessed"])


class CallbackIngestionTests(unittest.TestCase):
    def _inbox(self, lines):
        fh = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        for line in lines:
            fh.write(line + "\n")
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_wellformed_hit_parsed_metadata_only(self):
        inbox = self._inbox([json.dumps(
            {"hit_id": "h1", "token": "t1", "ip": "203.0.113.7",
             "ua": "curl/8", "at": 1000, "extra": "x" * 100})])
        hits = canary.read_callbacks(inbox)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["ip"], "203.0.113.7")
        self.assertNotIn("extra", hits[0])               # unknown fields dropped

    def test_malformed_lines_skipped_not_fatal(self):
        inbox = self._inbox([
            "not json", "{}", json.dumps({"hit_id": "h", "token": "t"}),
            json.dumps(["list", "not", "dict"])])
        hits = canary.read_callbacks(inbox)
        self.assertEqual([h["hit_id"] for h in hits], ["h"])

    def test_seen_hits_deduped(self):
        inbox = self._inbox([json.dumps({"hit_id": "h1", "token": "t"})])
        self.assertEqual(canary.read_callbacks(inbox, seen_hits={"h1"}), [])

    def test_oversized_line_skipped(self):
        inbox = self._inbox([json.dumps({"hit_id": "h", "token": "t",
                                         "ua": "z" * 9000})])
        self.assertEqual(canary.read_callbacks(inbox), [])

    def test_missing_inbox_is_empty(self):
        self.assertEqual(canary.read_callbacks(None), [])
        self.assertEqual(canary.read_callbacks("/no/such/inbox"), [])


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.journal = canary.CanaryJournal(Path(self.tmp.name))

    def test_no_anchor_for_empty_chain(self):
        digest, err = canary.anchor_head(self.journal, submit=lambda d: (b"p", []))
        self.assertIsNone(digest)
        self.assertIsNone(err)

    def test_anchor_writes_proof_and_respects_interval(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})
        calls = []

        def submit(digest):
            calls.append(digest)
            return b"PROOF", ["cal"]

        digest, err = canary.anchor_head(self.journal, now=1000, submit=submit)
        self.assertIsNone(err)
        self.assertTrue((self.journal.anchors / f"{digest}.json").exists())
        self.assertEqual((self.journal.anchors / f"{digest}.ots").read_bytes(),
                         b"PROOF")
        last = {"hash": self.journal.head()["hash"], "at": 1000}
        # Same head, inside the interval: no second submit.
        d2, _ = canary.anchor_head(self.journal, now=1100, last=last, submit=submit)
        self.assertIsNone(d2)
        self.assertEqual(len(calls), 1)

    def test_submit_failure_stays_advisory(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})

        def boom(digest):
            raise RuntimeError("calendar unreachable")

        digest, err = canary.anchor_head(self.journal, now=1, submit=boom)
        self.assertIsNone(digest)
        self.assertEqual(err, "RuntimeError")

    def test_network_disabled_does_not_anchor(self):
        self.journal.append("plant", {"id": "a", "kind": "credential"})
        digest, err = canary.anchor_head(self.journal, network=False,
                                         submit=lambda d: (b"p", []))
        self.assertIsNone(digest)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "canary"

    def _decoy(self, content="BEGIN OPENSSH PRIVATE KEY"):
        p = Path(self.tmp.name) / "id_rsa"
        p.write_text(content)
        return str(p)

    def _titles(self, findings):
        return [f["title"] for f in findings]

    def test_empty_registry_reports_no_tokens(self):
        store = FakeStore()
        out = canary_job.audit(store, root=self.root, conf={}, now=1, network=False)
        self.assertIn("No canary tokens are planted", self._titles(out))
        self.assertTrue(json.loads(store.meta[canary_job.META])["chain_ok"])

    def test_armed_token_and_then_tripwire(self):
        decoy = self._decoy()
        canary.plant("file_decoy", "ssh key", path=decoy, root=self.root)
        store = FakeStore()
        out = canary_job.audit(store, root=self.root, conf={}, now=1, network=False)
        self.assertTrue(any("armed" in t for t in self._titles(out)))

        # An intruder edits the decoy; the next pass reports it and records one trip.
        Path(decoy).write_text("stolen")
        out = canary_job.audit(store, root=self.root, conf={}, now=2, network=False)
        self.assertTrue(any("was touched" in t or "was taken" in t
                            for t in self._titles(out)))
        journal = canary.CanaryJournal(self.root)
        trips = [r for r in journal.records() if r["kind"] == "trip"]
        self.assertEqual(len(trips), 1)

        # A second pass keeps reporting but does not append a duplicate trip.
        canary_job.audit(store, root=self.root, conf={}, now=3, network=False)
        trips = [r for r in canary.CanaryJournal(self.root).records()
                 if r["kind"] == "trip"]
        self.assertEqual(len(trips), 1)

    def test_callback_raises_critical_and_dedupes(self):
        token = canary.plant("doc_url", "merger plan",
                             url_base="https://c.example.com", root=self.root)
        inbox = Path(self.tmp.name) / "hits.jsonl"
        inbox.write_text(json.dumps(
            {"hit_id": "h1", "token": token["id"], "ip": "198.51.100.9",
             "ua": "Office", "at": 50}) + "\n")
        store = FakeStore()
        conf = {"callback_inbox": str(inbox)}
        out = canary_job.audit(store, root=self.root, conf=conf, now=1, network=False)
        crit = [f for f in out if f["severity"] == "critical"]
        self.assertTrue(crit)
        self.assertIn("opened off this machine", crit[0]["title"])
        self.assertIn("198.51.100.9", crit[0]["detail"])

        callbacks = [r for r in canary.CanaryJournal(self.root).records()
                     if r["kind"] == "callback"]
        self.assertEqual(len(callbacks), 1)
        # Same inbox again: no duplicate callback recorded.
        canary_job.audit(store, root=self.root, conf=conf, now=2, network=False)
        callbacks = [r for r in canary.CanaryJournal(self.root).records()
                     if r["kind"] == "callback"]
        self.assertEqual(len(callbacks), 1)

    def test_tampered_journal_is_critical_and_halts_writes(self):
        decoy = self._decoy()
        canary.plant("file_decoy", "ssh key", path=decoy, root=self.root)
        journal = canary.CanaryJournal(self.root)
        recs = journal.path.read_text().splitlines()
        obj = json.loads(recs[0])
        obj["payload"]["label"] = "nothing to see"       # edit, keep stored hash
        journal.path.write_text(json.dumps(obj, sort_keys=True) + "\n")
        before = journal.path.read_text()

        store = FakeStore()
        Path(decoy).write_text("stolen")                 # would trip if writing continued
        out = canary_job.audit(store, root=self.root, conf={}, now=1, network=False)
        titles = self._titles(out)
        self.assertIn("Canary journal was tampered with", titles)
        # Nothing appended to a chain that no longer verifies.
        self.assertEqual(journal.path.read_text(), before)
        self.assertFalse(json.loads(store.meta[canary_job.META])["chain_ok"])


if __name__ == "__main__":
    unittest.main()
