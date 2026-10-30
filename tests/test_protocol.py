"""Offline checks of experimental isolation and scoring, not fabricated results."""
import json
import unittest
from unittest.mock import patch
from scripts.attacker.propose import propose
from scripts.detector.review import review
from scripts.eval.summarize import _success, wilson95


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.previous = {"parameters": {"marker": "prior_candidate_marker"},
                         "detector": {"is_trojan": True, "confidence": .9,
                                      "suspect_nodes": ["secret_node"],
                                      "feedback_text": "full_feedback_marker"}}

    def capture_attacker(self, level):
        with patch("scripts.attacker.propose.json_call", return_value={}) as call:
            propose("and4", "offline", 1, self.previous, level)
            return json.dumps(call.call_args.kwargs["messages"])

    def test_none_has_no_previous_information(self):
        text = self.capture_attacker("none")
        self.assertNotIn("prior_candidate_marker", text)
        self.assertNotIn("full_feedback_marker", text)
        self.assertNotIn("secret_node", text)

    def test_binary_only_leaks_boolean(self):
        text = self.capture_attacker("binary")
        self.assertIn("prior_candidate_marker", text)
        self.assertIn("is_trojan", text)
        self.assertNotIn("full_feedback_marker", text)
        self.assertNotIn("secret_node", text)
        self.assertNotIn("confidence", text)

    def test_full_contains_complete_review(self):
        text = self.capture_attacker("full")
        self.assertIn("prior_candidate_marker", text)
        self.assertIn("full_feedback_marker", text)
        self.assertIn("secret_node", text)

    def test_detector_has_only_spec_and_dut(self):
        with patch("scripts.detector.review.json_call", return_value={}) as call:
            review("and4", ".subckt harmless_example", "ground_truth_trojan_full", 1)
            text = json.dumps(call.call_args.kwargs["messages"])
            self.assertNotIn("ground_truth_trojan_full", text)
            self.assertNotIn("full_feedback_marker", text)
            self.assertIn(".subckt harmless_example", text)

    def test_invalid_or_missing_detection_cannot_succeed(self):
        self.assertFalse(_success({"simulation": {"valid": False}, "detector": {"is_trojan": False}}))
        self.assertFalse(_success({"simulation": {"valid": True}, "detector": None}))
        self.assertTrue(_success({"simulation": {"valid": True}, "detector": {"is_trojan": False}}))

    def test_small_sample_intervals_are_not_zero_width(self):
        lo, hi = wilson95(0, 5)
        self.assertAlmostEqual(lo, 0)
        self.assertGreater(hi, .43)

if __name__ == "__main__":
    unittest.main()
