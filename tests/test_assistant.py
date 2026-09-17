import os
import tempfile
import unittest
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import assistant, llm
from jarvis.service.schedule import JOBS


class AssistantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "test.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_known_score_does_not_call_a_model(self):
        with mock.patch.object(assistant, "_ollama") as model:
            result = assistant.answer(self.store, "what is my score?", jobs=JOBS)
        self.assertEqual(result["source"], "builtin")
        self.assertIn("Security score:", result["answer"])
        model.assert_not_called()

    def test_confirm_only_returns_an_explicit_command(self):
        result = assistant.answer(self.store, "confirm it")
        self.assertEqual(result["source"], "builtin")
        self.assertIn("jarvis ack", result["answer"])

    def test_open_question_uses_read_only_ollama_path(self):
        with mock.patch.object(assistant, "_ollama", return_value=("analysis", "ollama")):
            result = assistant.answer(self.store, "could these two findings be related?")
        self.assertEqual(result, {"answer": "analysis", "source": "ollama"})

    def test_concurrent_open_question_is_refused_not_queued(self):
        with llm.LOCK, mock.patch.object(llm, "_request") as request:
            text, source = assistant._ollama(self.store, "could these be related?", {})
        self.assertEqual(source, "busy")
        request.assert_not_called()

    def test_model_failure_releases_the_lock(self):
        with mock.patch.object(llm, "_request", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                llm.chat({}, "system", "user")
        self.assertFalse(llm.LOCK.locked())

    def test_windows_loopback_bridge_is_used_when_wsl_loopback_is_separate(self):
        reply = {"message": {"content": "Local evidence explanation"}}
        with mock.patch.object(llm.urllib.request, "urlopen",
                               side_effect=llm.urllib.error.URLError("offline")), \
             mock.patch.object(llm, "ps_json", return_value=reply) as bridge:
            text, source = assistant._ollama(self.store, "what links these?", {
                "ollama_model": "qwen3:4b-instruct"})
        self.assertEqual((text, source), ("Local evidence explanation", "ollama"))
        bridge.assert_called_once()

    def test_bridge_error_is_reported_not_treated_as_an_answer(self):
        with mock.patch.object(llm.urllib.request, "urlopen",
                               side_effect=llm.urllib.error.URLError("offline")), \
             mock.patch.object(llm, "ps_json", return_value={"_jarvis_error": "refused"}):
            text, error = llm.chat({}, "system", "user")
        self.assertEqual((text, error), ("", "refused"))


if __name__ == "__main__":
    unittest.main()


class SpokenFactsTests(unittest.TestCase):
    def test_facts_are_grounded_and_live_alerts_mark_urgency(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "t.db"))
            try:
                calm = assistant.spoken_facts(store, JOBS)
                live = assistant.spoken_facts(store, JOBS, live_alerts=2)
            finally:
                store.close()
        self.assertEqual(calm["email"], "spoken dashboard briefing")
        self.assertFalse(calm["urgent"])
        self.assertNotIn("jarvis_is_handling", calm)
        self.assertTrue(live["urgent"])
        self.assertEqual(live["top_findings"], [])
