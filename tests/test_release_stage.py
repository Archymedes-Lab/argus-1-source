"""release/stage.py only ever touches temporary staging drafts.

No network: the GitHub API calls are replaced by an in-memory fake.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import stage  # noqa: E402


class FakeGitHub:
    def __init__(self, releases):
        self.releases = releases
        self.calls = []

    def __call__(self, method, url, body=None, headers=None, raw=False, attempts=4):
        self.calls.append((method, url.split("?")[0]))
        if method == "GET" and "/releases" in url:
            return self.releases
        if method == "POST" and url.endswith("/releases"):
            rel = {"id": 99, "name": body["name"], "draft": body["draft"], "assets": []}
            self.releases.append(rel)
            return rel
        return None


class StageTests(unittest.TestCase):
    def setUp(self):
        env = {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r"}
        self.env = mock.patch.dict(os.environ, env)
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_delete_refuses_a_published_or_non_staging_release(self):
        fake = FakeGitHub([{"id": 1, "name": "staging-1", "draft": False, "assets": []}])
        with mock.patch.object(stage, "call", fake):
            # A published release of that name is not even found as a staging draft.
            stage.delete("staging-1")
        self.assertNotIn("DELETE", [m for m, _ in fake.calls])

    def test_delete_removes_only_the_named_staging_draft(self):
        fake = FakeGitHub([{"id": 7, "name": "v2026.11.01", "draft": True, "assets": []},
                           {"id": 8, "name": "staging-42", "draft": True, "assets": []}])
        with mock.patch.object(stage, "call", fake):
            stage.delete("staging-42")
        self.assertEqual([c for c in fake.calls if c[0] == "DELETE"],
                         [("DELETE", "https://api.github.com/repos/o/r/releases/8")])

    def test_create_is_idempotent_and_always_a_draft_prerelease(self):
        fake = FakeGitHub([])
        with mock.patch.object(stage, "call", fake):
            stage.create("staging-5", "abc")
            stage.create("staging-5", "abc")
        posts = [c for c in fake.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertTrue(fake.releases[0]["draft"])

    def test_cli_refuses_names_that_are_not_staging(self):
        with mock.patch.object(sys, "argv", ["stage.py", "delete", "--name", "v2026.11.01"]):
            with self.assertRaises(SystemExit) as cm:
                stage.main()
        self.assertIn("staging-", str(cm.exception))

    def test_no_redirect_keeps_the_token_off_storage_hosts(self):
        handler = stage._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://storage.example/x"))

    def test_upload_replaces_an_asset_of_the_same_name(self):
        fake = FakeGitHub([{"id": 3, "name": "staging-9", "draft": True,
                            "assets": [{"name": "a.deb", "id": 31}]}])
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "a.deb"
            f.write_bytes(b"x")
            with mock.patch.object(stage, "call", fake):
                stage.upload("staging-9", [str(f)])
        self.assertIn(("DELETE", "https://api.github.com/repos/o/r/releases/assets/31"), fake.calls)


if __name__ == "__main__":
    unittest.main()
