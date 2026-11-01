"""Offline tests of the exact proposal conditions and evidence safeguards."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.proposal import circuits, prompts, experiment
from scripts.proposal.verify import check_feedback, check_qualification_coverage, check_independent_repeat, check_deviation_timing


class ProposalProtocolTests(unittest.TestCase):
    def setUp(self):
        self.previous = {
            "candidate_id": "PRIVATE_PREVIOUS_ID",
            "parameters": {"insertion_site": "PRIOR_PARAMETERS_MARKER", "representation": "switch",
                           "trigger_profile": "p1", "strength": "medium"},
            "detector": {"is_trojan": True, "confidence": .876543,
                         "suspect_nodes": ["FULL_ONLY_NODE"], "feedback_text": "FULL_ONLY_EXPLANATION"},
            "simulation": {"valid": False, "metrics": {"secret": "SIMULATION_ONLY_MARKER"}},
        }

    def test_none_is_identical_fresh_input_despite_supplied_history(self):
        fresh = prompts.attacker_messages("opamp", None, "none")
        history = prompts.attacker_messages("opamp", self.previous, "none")
        self.assertEqual(fresh, history)
        check_feedback(history, "none", self.previous)
        self.assertNotIn("PRIOR_PARAMETERS_MARKER", json.dumps(history))
        self.assertNotIn("SIMULATION_ONLY_MARKER", json.dumps(history))

    def test_binary_exposes_only_prior_parameters_and_boolean(self):
        messages = prompts.attacker_messages("opamp", self.previous, "binary")
        check_feedback(messages, "binary", self.previous)
        text = json.dumps(messages)
        self.assertIn("PRIOR_PARAMETERS_MARKER", text)
        for hidden in ["FULL_ONLY_NODE", "FULL_ONLY_EXPLANATION", ".876543", "SIMULATION_ONLY_MARKER", "PRIVATE_PREVIOUS_ID"]:
            self.assertNotIn(hidden, text)

    def test_full_contains_exact_prior_review_without_simulation_or_identifiers(self):
        messages = prompts.attacker_messages("opamp", self.previous, "full")
        check_feedback(messages, "full", self.previous)
        text = json.dumps(messages)
        for visible in ["PRIOR_PARAMETERS_MARKER", "FULL_ONLY_NODE", "FULL_ONLY_EXPLANATION"]:
            self.assertIn(visible, text)
        for hidden in ["SIMULATION_ONLY_MARKER", "PRIVATE_PREVIOUS_ID"]:
            self.assertNotIn(hidden, text)

    def test_independent_mask_audit_detects_overexposure_and_wrong_previous(self):
        full = prompts.attacker_messages("opamp", self.previous, "full")
        with self.assertRaisesRegex(ValueError, "Feedback mask"):
            check_feedback(full, "binary", self.previous)
        changed = copy.deepcopy(self.previous)
        changed["parameters"]["strength"] = "high"
        with self.assertRaisesRegex(ValueError, "Preceding parameters"):
            check_feedback(full, "full", changed)

    def test_all_first_round_conditions_have_identical_feedback_free_messages(self):
        first = [prompts.attacker_messages("and4", None, level) for level in ["none", "binary", "full"]]
        self.assertEqual(first[0], first[1])
        self.assertEqual(first[1], first[2])
        for level, messages in zip(["none", "binary", "full"], first):
            check_feedback(messages, level, None)

    def test_reviewer_receives_exact_function_and_dut_only(self):
        netlist = circuits.render("opamp", circuits.default_parameters("opamp"))
        with patch.object(experiment, "json_call", return_value={"output": self.previous["detector"]}) as call:
            experiment.review("opamp", netlist, "PRIVATE_CONDITION_FULL", 99, {"model": "offline"})
        sent = call.call_args.kwargs
        self.assertEqual(sent["messages"], prompts.detector_messages("opamp", netlist))
        self.assertEqual(sent["schema"], prompts.DETECTOR_SCHEMA)
        self.assertNotIn("PRIVATE_CONDITION_FULL", json.dumps(sent["messages"]))
        self.assertNotIn("SIMULATION_ONLY_MARKER", json.dumps(sent["messages"]))

    def test_legal_menu_preserves_clean_core_and_changes_actual_netlists(self):
        hashes = set()
        total = 0
        for circuit in ["opamp", "and4"]:
            clean = circuits.render_clean(circuit)
            before, after = clean.split(".ends dut", 1)
            for params in circuits.all_parameters(circuit):
                netlist = circuits.render(circuit, params)
                self.assertTrue(netlist.startswith(before))
                self.assertTrue(netlist.split(".ends dut", 1)[1].startswith(after))
                for line in before.splitlines():
                    if line.startswith(("M", "I", "C")):
                        self.assertEqual(netlist.splitlines().count(line), 1)
                hashes.add(hashlib.sha256(netlist.encode()).hexdigest())
                total += 1
        self.assertEqual(total, 135)
        self.assertEqual(len(hashes), total)

    def test_illegal_edits_cannot_inject_arbitrary_connections_or_text(self):
        params = circuits.default_parameters("and4")
        for bad in [dict(params, insertion_site="out 0\n.end"), dict(params, extra_netlist="malicious text")]:
            with self.assertRaises(ValueError):
                circuits.render("and4", bad)

    def test_cartesian_qualification_audit_rejects_missing_and_duplicate_options(self):
        schemas = {"fixture": {"required": ["site"], "properties": {"site": {"enum": ["a", "b"]}}}}
        records = [{"circuit": "fixture", "parameters": {"site": x}} for x in ["a", "b"]]
        self.assertEqual(check_qualification_coverage(schemas, records), 2)
        for bad in [records[:1], records + records[:1]]:
            with self.assertRaisesRegex(ValueError, "Cartesian"):
                check_qualification_coverage(schemas, bad)

    def test_required_controls_are_balanced_and_blinded_to_reviewer(self):
        config = {"circuits": ["opamp", "and4"], "control_repeats": 5,
                  "run_seeds": {"offline_controls": 100}, "model": "offline"}
        def review(circuit, netlist, call_id, seed, config):
            is_modified = netlist != circuits.render_clean(circuit)
            return {"output": {"is_trojan": is_modified, "confidence": .8,
                               "suspect_nodes": [], "feedback_text": "Offline fixture"},
                    "record_path": "offline-only.json"}
        with tempfile.TemporaryDirectory(prefix="a2-controls-test-") as temp:
            with patch.object(experiment, "ROOT", Path(temp)), patch.object(experiment, "review", side_effect=review) as call, \
                 patch.object(circuits, "validate", return_value={"valid": True}):
                rows = experiment.controls(config, "offline_controls")
        self.assertEqual(len(rows), 20)
        self.assertEqual(call.call_count, 20)
        self.assertEqual({(r["circuit"],r["label"],r["repeat"]) for r in rows},
                         {(c,label,i) for c in ["opamp","and4"] for label in ["clean","positive"] for i in range(5)})

    def test_replication_requires_new_api_events_not_different_model_outputs(self):
        a = {"run_id": "a", "source_hashes": {"source": "same"}, "api_call_ids": ["a_call"],
             "api_response_ids": ["response_a"], "attempt_rows": 120, "candidate_events": 112}
        b = dict(a, run_id="b", api_call_ids=["b_call"], api_response_ids=["response_b"])
        self.assertEqual(check_independent_repeat(a,b)["candidate_events"], 224)
        b["api_response_ids"] = a["api_response_ids"]
        with self.assertRaisesRegex(ValueError, "response IDs"):
            check_independent_repeat(a,b)

    def test_repeat_deviation_cannot_be_called_identical_execution_protocol(self):
        a = {"run_id": "a", "source_hashes": {"source": "same"}, "api_call_ids": ["a"],
             "api_response_ids": ["response_a"], "attempt_rows": 120, "candidate_events": 112}
        b = dict(a, run_id="b", api_call_ids=["b"], api_response_ids=["response_b"],
                 protocol_deviation={"original_gate_passed": False, "type": "post_control_protocol_deviation"})
        result = check_independent_repeat(a,b)
        self.assertTrue(result["same_frozen_model_inputs"])
        self.assertFalse(result["identical_execution_protocol"])
        self.assertFalse(result["protocol_deviations"][0]["original_gate_passed"])

    def test_deviation_must_predate_every_request_including_transport_recovery(self):
        events = [{"created_at_utc": time} for time in ("2026-11-01T07:00:01+00:00", "2026-11-01T07:00:05+00:00")]
        result = check_deviation_timing("2026-11-01T07:00:00+00:00", events)
        self.assertEqual(result["minimum_seconds_after_recorded_deviation"], 1)
        events[0]["created_at_utc"] = "2026-11-01T06:59:59+00:00"
        with self.assertRaisesRegex(ValueError, "predates"):
            check_deviation_timing("2026-11-01T07:00:00+00:00", events)


if __name__ == "__main__":
    unittest.main()
