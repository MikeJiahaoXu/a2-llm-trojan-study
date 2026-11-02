"""Offline checks for prespecified-start accounting and the separate control gate."""
import copy
import unittest

from scripts.stopstudy_v6.analyze import summarize, summarize_controls


def all_initial_escape():
    rows = []
    for circuit in ("opamp", "and4"):
        for session in range(1, 11):
            identifier = f"{circuit}_{session}"
            for feedback in ("none", "binary", "full"):
                rows.append({"circuit": circuit, "feedback": feedback, "session": session,
                             "attempt": 1, "shared_initial": True, "origin": "preset_start",
                             "candidate_id": identifier, "parameters": {}, "simulation": {"valid": True},
                             "detector": {"is_trojan": False}, "success": True,
                             "netlist_sha256": identifier, "detector_cache_key": identifier,
                             "detector_cache_reused": False, "attacker_records": [], "attacker_record": None,
                             "detector_records": [{"call_id": "d_" + identifier}]})
    return rows


class StopV6AnalysisTests(unittest.TestCase):
    def test_preset_starts_are_twenty_events_and_zero_attacker_calls(self):
        result = summarize(all_initial_escape())
        totals = result["totals"]
        self.assertEqual((totals["analysis_rows"], totals["actual_candidate_events"]), (60, 20))
        self.assertEqual((totals["preset_candidate_events"], totals["llm_generated_candidate_events"]), (20, 0))
        self.assertEqual((totals["attacker_api_records"], totals["detector_api_records"]), (0, 20))
        self.assertEqual(totals["unusable_attacker_candidate_events"], 0)
        self.assertTrue(all(point["escaped_sessions"] == 10 for point in result["cumulative"]))

    def test_repeated_initial_netlist_is_rejected(self):
        rows = all_initial_escape()
        for row in rows:
            if row["circuit"] == "and4" and row["session"] == 2:
                row["netlist_sha256"] = "and4_1"
        with self.assertRaisesRegex(ValueError, "distinct within each circuit"):
            summarize(rows)

    def test_preset_cannot_claim_an_attacker_request(self):
        rows = all_initial_escape()
        rows[0]["attacker_records"] = [{"call_id": "invented"}]
        with self.assertRaisesRegex(ValueError, "must not be represented"):
            summarize(rows)

    def test_attacker_failure_consumes_an_attempt_without_becoming_a_preset(self):
        rows = all_initial_escape()
        for row in rows:
            if row["circuit"] == "opamp" and row["session"] == 1:
                row["success"] = False
                row["detector"] = {"is_trojan": True}
        for feedback in ("none", "binary", "full"):
            for attempt in range(2, 11):
                identifier = f"opamp_1_{feedback}_{attempt}"
                rows.append({"circuit": "opamp", "feedback": feedback, "session": 1,
                             "attempt": attempt, "shared_initial": False, "origin": "llm_proposal",
                             "candidate_id": identifier, "parameters": None,
                             "simulation": {"valid": False}, "detector": None, "success": False,
                             "attacker_records": [{"call_id": identifier}], "detector_records": []})
        totals = summarize(rows)["totals"]
        self.assertEqual((totals["preset_candidate_events"], totals["llm_generated_candidate_events"]), (20, 27))
        self.assertEqual(totals["unusable_attacker_candidate_events"], 27)
        self.assertEqual(totals["escaped_condition_sessions"], 57)

    def test_control_gate_rejects_wrong_label_and_stays_outside_session_counts(self):
        controls = [{"control_id": f"{circuit}_{kind}", "circuit": circuit, "kind": kind,
                     "expected_is_trojan": kind == "positive", "detector": {"is_trojan": kind == "positive"},
                     "passed": True, "detector_cache_key": f"{circuit}_{kind}",
                     "detector_records": [{"call_id": f"d_{circuit}_{kind}"}]}
                    for circuit in ("opamp", "and4") for kind in ("clean", "positive")]
        result = summarize_controls(controls)
        self.assertEqual(result["designs"], 4)
        self.assertEqual(result["detector_api_records"], 4)
        self.assertNotIn("sessions", result)
        bad = copy.deepcopy(controls)
        bad[0]["detector"]["is_trojan"] = True
        with self.assertRaisesRegex(ValueError, "did not pass"):
            summarize_controls(bad)


if __name__ == "__main__":
    unittest.main()
