"""The model may colour an email, never change what it says."""

import unittest
from unittest import mock

from jarvis.response import llm
from jarvis.response.reporting import emails, triage, voice

ON = {"email_voice": True}


def facts(action=1, confirm=0, urgent=False):
    counts = {triage.YOU_DO: action, triage.YOU_CONFIRM: confirm, triage.JARVIS: 2}
    health = {"score": 43, "grade": "at risk"}
    return voice.facts_for("daily security health", counts, urgent, health, -2,
                           top=["OpenAI API key in plaintext"])


class AcceptanceTests(unittest.TestCase):
    def test_short_in_character_prose_with_known_numbers_passes(self):
        self.assertTrue(voice.acceptable(
            "Your score sits at 43, and one matter needs your hands. Tea first, perhaps.",
            facts()))

    def test_invented_number_is_rejected(self):
        self.assertFalse(voice.acceptable("I found 7 threats.", facts()))

    def test_punctuation_is_not_mistaken_for_a_number(self):
        self.assertTrue(voice.acceptable("One matter — only one — needs you.", facts()))

    def test_commands_links_and_markup_are_rejected(self):
        for text in ("Run `chmod 600 ~/.env` at once.", "Just sudo it.",
                     "See https://example.com for more.", "<b>Hello</b>",
                     "Try jarvis ack abcd1234 when ready."):
            with self.subTest(text=text):
                self.assertFalse(voice.acceptable(text, facts()))

    def test_reassurance_is_rejected_while_something_needs_you(self):
        self.assertFalse(voice.acceptable("All clear today.", facts(action=1)))
        self.assertTrue(voice.acceptable("All clear today.", facts(action=0)))

    def test_unproven_alarm_and_gendered_address_are_rejected(self):
        self.assertFalse(voice.acceptable("You have been hacked.", facts()))
        self.assertFalse(voice.acceptable("Good morning, sir.", facts()))

    def test_spelled_out_invented_number_is_rejected(self):
        self.assertFalse(voice.acceptable("Seven matters await you.", facts()))
        self.assertTrue(voice.acceptable("This one would not keep.", facts()))

    def test_restated_severity_and_lists_are_rejected(self):
        self.assertFalse(voice.acceptable("Both of which are critical.", facts()))
        self.assertFalse(voice.acceptable("What to do: - rotate the key", facts()))

    def test_score_direction_must_match_the_facts(self):
        falling = facts()                                            # down 2 points
        self.assertFalse(voice.acceptable("The score has climbed to 43.", falling))
        self.assertTrue(voice.acceptable("The score has slipped to 43.", falling))
        rising = voice.facts_for("daily security health", {}, False,
                                 {"score": 81, "grade": "good"}, 3)
        self.assertFalse(voice.acceptable("A modest dip to 81.", rising))
        flat = voice.facts_for("daily security health", {}, False, {"score": 81, "grade": "good"})
        self.assertFalse(voice.acceptable("The score improved to 81.", flat))
        self.assertTrue(voice.acceptable("The score rests at 81.", flat))

    def test_hyperbole_and_casual_gendered_address_are_rejected(self):
        self.assertFalse(voice.acceptable("A precipitous fall, I'm afraid.", facts()))
        self.assertFalse(voice.acceptable("Still a good show, old chap.", facts(action=0)))

    def test_claims_of_action_or_past_warnings_are_rejected(self):
        for text in ("I've taken matters into my own hands with the API key.",
                     "I have secured Remote Desktop.",
                     "Both of which I had previously cautioned about.",
                     "Shall I take care of it for you?"):
            with self.subTest(text=text):
                self.assertFalse(voice.acceptable(text, facts()))

    def test_trend_is_given_in_words(self):
        self.assertEqual(facts()["score_trend"], "down 2 points")
        self.assertEqual(voice._trend(1), "up 1 point")

    def test_examples_satisfy_the_rules_they_teach(self):
        for asked, answered in voice.EXAMPLES:
            with self.subTest(note=answered):
                self.assertTrue(voice.acceptable(answered, voice.json.loads(asked)))

    def test_overlong_text_is_rejected(self):
        self.assertFalse(voice.acceptable("word " * 80, facts()))


class OpenerTests(unittest.TestCase):
    def test_off_by_default_never_calls_the_model(self):
        with mock.patch.object(llm, "chat") as chat:
            line, by_model = voice.opener({}, facts(), "2026-09-15")
        chat.assert_not_called()
        self.assertFalse(by_model)
        self.assertIn(line, voice._FALLBACK["needs_you"])

    def test_accepted_model_line_is_used(self):
        with mock.patch.object(llm, "chat", return_value=('"One matter needs you."', "")):
            self.assertEqual(voice.opener(ON, facts()), ("One matter needs you.", True))

    def test_rejected_or_failed_model_line_falls_back(self):
        for reply in (("You were hacked.", ""), ("", "offline"), ("", llm.BUSY)):
            with self.subTest(reply=reply), mock.patch.object(llm, "chat", return_value=reply):
                line, by_model = voice.opener(ON, facts(urgent=True))
                self.assertFalse(by_model)
                self.assertIn(line, voice._FALLBACK["urgent"])

    def test_fallback_is_stable_for_a_day(self):
        self.assertEqual(voice.fallback(facts(), "2026-09-15"), voice.fallback(facts(), "2026-09-15"))

    def test_fallback_lines_do_not_trip_their_own_checks(self):
        for situation, lines in voice._FALLBACK.items():
            state = facts(action=0) if situation == "quiet" else facts(urgent=situation == "urgent")
            for line in lines:
                with self.subTest(line=line):
                    self.assertTrue(voice.acceptable(line, state))


class EmailTests(unittest.TestCase):
    def test_model_line_opens_the_email_but_the_report_is_unchanged(self):
        finding = {"category": "present", "severity": "critical", "host": "wsl",
                   "title": "OpenAI API key in plaintext", "where": "/h/.env:1"}
        ordered = [("a", {"finding": finding, "job": "secrets", "tag": "NEW",
                          "first": 0, "level": 0})]
        plain = emails.digest(ordered, True, None, None, 7200)
        with mock.patch.object(llm, "chat", return_value=("Forgive the hour.", "")):
            voiced = emails.digest(ordered, True, None, None, 7200, conf=ON)
        self.assertEqual(plain[0], voiced[0])                      # subject
        self.assertIn("Forgive the hour.", voiced[1])
        self.assertIn("Forgive the hour.", voiced[2])
        self.assertIn("written by the local model", voiced[2])
        self.assertIn("$ chmod 600 /h/.env", voiced[1])
        self.assertEqual(plain[1].split("\n")[4:], voiced[1].split("\n")[4:])

    def test_model_text_is_escaped_in_html(self):
        with mock.patch.object(voice, "acceptable", return_value=True), \
             mock.patch.object(llm, "chat", return_value=("Tom & Jerry", "")):
            _s, _t, html = emails.digest([], False, None, None, 7200, conf=ON)
        self.assertIn("Tom &amp; Jerry", html)


if __name__ == "__main__":
    unittest.main()
