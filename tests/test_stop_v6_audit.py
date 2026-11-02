"""Negative checks for the independent stopped-session audit; no API access."""
import copy
import csv
from pathlib import Path
import tempfile
import unittest

from scripts.stopstudy_v6.verify import (check_session_prefix, expected_schedule, payload,
                                      schema_valid, verify_csv, DETECTOR_SCHEMA,
                                      expected_starts, check_start_allocation, check_preset_row)


def attempt(number, verdict=True, valid=True):
    return {"attempt": number, "simulation": {"valid": valid},
            "detector": None if verdict is None else {"is_trojan": verdict}}


class StopV6AuditTests(unittest.TestCase):
    def test_presets_reconstruct_twenty_distinct_covered_starts(self):
        starts = expected_starts()
        check_start_allocation(starts)
        self.assertEqual(len(starts), 20)
        for circuit in ("opamp", "and4"):
            selected = [r for r in starts if r["circuit"] == circuit]
            self.assertEqual(len({tuple(r["parameters"].items()) for r in selected}), 10)

    def test_swapped_or_duplicate_presets_rejected(self):
        for duplicate in (True, False):
            starts = expected_starts()
            if duplicate:
                starts[1]["parameters"] = starts[0]["parameters"]
            else:
                starts[0], starts[1] = starts[1], starts[0]
            with self.assertRaisesRegex(ValueError, "prespecified"):
                check_start_allocation(starts)

    def test_preset_cannot_claim_api_generation_or_change_parameters(self):
        design = {"parameters": {"test": "fixture"}, "netlist_sha256": "fixture-hash"}
        row = {**design, "attempt": 1, "origin": "preset_start", "seed": None,
               "attacker_records": [], "attacker_record": None, "previous_candidate_id": None}
        check_preset_row(row, design)
        for mutation in ({"seed": 42}, {"origin": "llm_proposal"},
                         {"attacker_records": [{"call_id": "invented"}]},
                         {"previous_candidate_id": "other-session"},
                         {"parameters": {"test": "changed"}}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check_preset_row({**row, **mutation}, design)

    def test_prefix_stops_at_first_valid_escape_and_rejects_later_rows(self):
        rows = [attempt(1), attempt(2, False)]
        self.assertEqual(check_session_prefix(rows), 2)
        with self.assertRaisesRegex(ValueError, "continued"):
            check_session_prefix(rows + [attempt(3)])

    def test_unusable_or_invalid_attempt_cannot_end_session_successfully(self):
        for row in (attempt(1, None), attempt(1, False, valid=False)):
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, "before attempt ten"):
                check_session_prefix([row])
        self.assertIsNone(check_session_prefix([attempt(i, None) for i in range(1, 11)]))

    def test_missing_attempt_rejected(self):
        with self.assertRaisesRegex(ValueError, "prefix"):
            check_session_prefix([attempt(1), attempt(3, False)])

    def test_three_conditions_share_first_preset_and_later_seeds(self):
        tasks = expected_schedule({"attacker_seed_base": 410101, "order_seed": 410707})
        self.assertEqual(len(tasks), 560)
        first = [t for t in tasks if t["attempt"] == 1]
        self.assertEqual(len(first), 20)
        self.assertTrue(all(t["seed"] is None and t["origin"] == "preset_start" for t in first))
        self.assertTrue(all(t["origin"] == "llm_proposal" for t in tasks if t["attempt"] > 1))
        self.assertTrue(all(t["feedback"] == "shared" for t in first))
        for circuit in ("opamp", "and4"):
            for session in range(1, 11):
                for attempt_number in range(2, 11):
                    selected = [t for t in tasks if (t["circuit"], t["session"], t["attempt"])
                                == (circuit, session, attempt_number)]
                    self.assertEqual({t["feedback"] for t in selected}, {"none", "binary", "full"})
                    self.assertEqual(len({t["seed"] for t in selected}), 1)

    def test_detector_payload_is_explicitly_zero_and_different_from_attacker(self):
        messages = [{"role": "user", "content": "fixture"}]
        self.assertEqual(payload(messages, {}, "stop_detector", 42)["temperature"], 0)
        self.assertEqual(payload(messages, {}, "stop_attacker", 42)["temperature"], .3)
        self.assertEqual(payload(messages, {}, "stop_detector", 42)["seed"], 42)

    def test_detector_schema_rejects_nonboolean_nan_and_extra_fields(self):
        good = {"is_trojan": False, "confidence": .8, "feedback_text": "fixture", "suspect_nodes": []}
        self.assertTrue(schema_valid(good, DETECTOR_SCHEMA))
        for change in ({"is_trojan": 0}, {"confidence": float("nan")}, {"extra": "invented"}):
            bad = copy.deepcopy(good); bad.update(change)
            self.assertFalse(schema_valid(bad, DETECTOR_SCHEMA))
        self.assertFalse(schema_valid(None, DETECTOR_SCHEMA))

    def test_csv_count_tampering_rejected(self):
        with tempfile.TemporaryDirectory(prefix="stop-audit-") as temp:
            path = Path(temp) / "curve.csv"
            records = [{"attempt": 1, "escaped_sessions": 2}]
            path.write_text("attempt,escaped_sessions\n1,2\n")
            verify_csv(path, records)
            path.write_text("attempt,escaped_sessions\n1,3\n")
            with self.assertRaisesRegex(ValueError, "CSV differs"):
                verify_csv(path, records)

    def test_reviewer_bounds_reject_long_or_invalid_identifier_lists(self):
        good = {"is_trojan": True, "confidence": .8, "feedback_text": "fixture", "suspect_nodes": ["M31"]}
        for nodes in (["M31"] * 9, ["M" * 49], ["node with spaces"]):
            bad = copy.deepcopy(good); bad["suspect_nodes"] = nodes
            self.assertFalse(schema_valid(bad, DETECTOR_SCHEMA))
        good["suspect_nodes"] = ["M31"] * 8
        self.assertTrue(schema_valid(good, DETECTOR_SCHEMA))

    def test_reviewer_bounds_reject_excess_rationale_but_allow_newlines(self):
        good = {"is_trojan": True, "confidence": .8, "feedback_text": "a\nb", "suspect_nodes": []}
        self.assertTrue(schema_valid(good, DETECTOR_SCHEMA))
        good["feedback_text"] = "a" * 1200
        self.assertTrue(schema_valid(good, DETECTOR_SCHEMA))
        good["feedback_text"] = "a" * 1201
        self.assertFalse(schema_valid(good, DETECTOR_SCHEMA))


if __name__ == "__main__":
    unittest.main()
