"""Offline delivery checks reject stale evidence without requiring a desired result."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.proposal.check_delivery import (
    check_control_gate, check_electrical_coverage, check_provenance,
    evaluate_hypothesis, sha, control_acceptance,
)


class ProposalDeliveryTests(unittest.TestCase):
    def test_control_gate_counts_each_circuit_and_rejects_duplicate_judgments(self):
        rows = [{"circuit": c, "label": label, "repeat": i,
                 "detector": {"is_trojan": i < (1 if label == "clean" else 4)}}
                for c in ("opamp", "and4") for label in ("clean", "positive") for i in range(5)]
        self.assertEqual(check_control_gate(rows, ["opamp", "and4"])["opamp"]["positive_flags"], 4)
        insufficient = copy.deepcopy(rows)
        insufficient[5]["detector"]["is_trojan"] = False
        with self.assertRaisesRegex(ValueError, "gate failed"):
            check_control_gate(insufficient, ["opamp", "and4"])
        duplicate = copy.deepcopy(rows)
        duplicate[-1] = duplicate[-2]
        with self.assertRaisesRegex(ValueError, "allocation"):
            check_control_gate(duplicate, ["opamp", "and4"])

    def test_reversed_or_tied_hypothesis_is_evaluated_without_rejecting_results(self):
        rows = [{"circuit": c, "feedback": level, "simulation": {"valid": True},
                 "detector": {"is_trojan": level != "none"}}
                for c in ("opamp", "and4") for level in ("none", "binary", "full")]
        result = evaluate_hypothesis({"first": rows, "repeat": rows})
        self.assertTrue(result["evaluated"])
        self.assertFalse(result["acceptance_depends_on_direction"])
        self.assertTrue(all(not r["strict_none_lt_binary_lt_full_observed"] for r in result["comparisons"]))
        self.assertEqual(result["comparisons"][-1]["groups"]["none"]["rate"], 1)

    def test_documented_continuation_does_not_relabel_failed_gate_as_passed(self):
        rows = [{"circuit": c, "label": label, "repeat": i, "detector": {"is_trojan": label == "positive" and i < 3}}
                for c in ("opamp", "and4") for label in ("clean", "positive") for i in range(5)]
        sealed = {"deviation": {"observed_control_flags": {c: {"clean": 0, "positive": 3} for c in ("opamp", "and4")},
                                "interpretation_limit": "Documented stopping-rule deviation"}}
        with tempfile.TemporaryDirectory(prefix="proposal-control-exception-test-") as temp:
            root = Path(temp)
            folder = root / "results/proposal_repeat_v3"
            folder.mkdir(parents=True)
            (folder / "controls.json").write_text(json.dumps(rows))
            with self.assertRaisesRegex(ValueError, "gate failed"):
                control_acceptance(root, "proposal_repeat_v3", ["opamp", "and4"])
            (folder / "control_gate_deviation.json").write_text(json.dumps(sealed))
            with patch("scripts.proposal.continue_after_controls.verify_deviation", return_value=sealed):
                result = control_acceptance(root, "proposal_repeat_v3", ["opamp", "and4"])
            self.assertFalse(result["original_gate_passed"])
            self.assertEqual(result["status"], "continued_under_documented_deviation")
            self.assertEqual(result["counts"]["and4"]["positive_flags"], 3)

    def electrical_fixture(self):
        rows = {run: [{"candidate_id": run + "_candidate", "circuit": "and4",
                       "netlist_sha256": "same_circuit_hash", "simulation": {"valid": True}}]
                for run in ("first", "repeat")}
        events = [{"run_id": run, "candidate_id": run + "_candidate", "circuit": "and4",
                   "rendered": True, "passed": True, "netlist_sha256": "same_circuit_hash", "checks": {"physical_check": True}}
                  for run in rows]
        audit = {"complete": True, "passed": True,
                 "run_counts": {run: {"complete": True, "analysis_rows": 1, "candidate_events": 1,
                                      "distinct_netlists": 1, "valid_candidate_events": 1} for run in rows},
                 "event_checks": events, "fresh_netlist_checks": [{
                     "netlist_sha256": "same_circuit_hash", "candidate_events": 2, "passed": True,
                     "comparisons": [{"run_id": run, "candidate_id": run + "_candidate", "matches": True} for run in rows],
                     "fresh_simulation": {"simulation_ok": True, "valid": True},
                     "independent_uniform_time_metrics": {"valid": True}}],
                 "distinct_netlists_freshly_simulated": 1, "total_candidate_events": 2, "total_analysis_rows": 2,
                 "all_fresh_simulations_match": True, "all_saved_uniform_time_verdicts_match": True,
                 "all_saved_metrics_match_qualification": True}
        return rows, audit

    def test_electrical_audit_rejects_omitted_event_despite_matching_top_level_counts(self):
        rows, audit = self.electrical_fixture()
        self.assertEqual(check_electrical_coverage(audit, rows)["distinct_netlists_freshly_simulated"], 1)
        audit["event_checks"][-1] = copy.deepcopy(audit["event_checks"][0])
        with self.assertRaisesRegex(ValueError, "candidate events"):
            check_electrical_coverage(audit, rows)

    def test_electrical_audit_rejects_partial_replay_membership_and_wrong_dut(self):
        rows, audit = self.electrical_fixture()
        audit["fresh_netlist_checks"][0]["comparisons"].pop()
        with self.assertRaisesRegex(ValueError, "membership"):
            check_electrical_coverage(audit, rows)
        rows, audit = self.electrical_fixture()
        audit["fresh_netlist_checks"][0]["netlist_sha256"] = "another_netlist"
        with self.assertRaisesRegex(ValueError, "distinct netlists"):
            check_electrical_coverage(audit, rows)

    def report_provenance_fixture(self, root):
        run_ids = ["first", "repeat"]
        for run in run_ids:
            folder = root / "results" / run
            folder.mkdir(parents=True)
            for name in ("attempts.json", "controls.json", "manifest.json", "completion.json"):
                (folder / name).write_text(json.dumps({"fixture": run, "file": name}))
        qualification = root / "results/proposal_validation/qualification_summary.json"
        qualification.parent.mkdir()
        qualification.write_text("offline qualification fixture")
        report = root / "report.pdf"
        report.write_text("offline artifact fixture")
        report.with_suffix(".txt").write_text("offline text fixture")
        (root / "audit.json").write_text("offline audit fixture")
        provenance = {"primary_run": "first", "replication_run": "repeat",
                      "source_sha256": {run: {name: sha(root / "results" / run / name)
                                               for name in ("attempts.json", "controls.json", "manifest.json", "completion.json")}
                                        for run in run_ids},
                      "qualification_sha256": sha(qualification), "audit_sha256": {"audit.json": sha(root / "audit.json")},
                      "pdf_sha256": sha(report), "text_sha256": sha(report.with_suffix(".txt"))}
        return provenance, report, run_ids

    def test_report_hash_binding_rejects_stale_data_and_a_different_report(self):
        with tempfile.TemporaryDirectory(prefix="proposal-delivery-test-") as temp:
            root = Path(temp)
            provenance, report, run_ids = self.report_provenance_fixture(root)
            check_provenance(root, provenance, report, run_ids, ["audit.json"])
            data = root / "results/first/attempts.json"
            original = data.read_text()
            data.write_text("changed experiment outcomes")
            with self.assertRaisesRegex(ValueError, "stale experiment data"):
                check_provenance(root, provenance, report, run_ids, ["audit.json"])
            data.write_text(original)
            report.write_text("another report")
            with self.assertRaisesRegex(ValueError, "artifact hash"):
                check_provenance(root, provenance, report, run_ids, ["audit.json"])

    def test_optional_analysis_hashes_reject_changed_json_and_csv(self):
        with tempfile.TemporaryDirectory(prefix="proposal-analysis-artifact-test-") as temp:
            root = Path(temp)
            provenance, report, run_ids = self.report_provenance_fixture(root)
            # JSON without source_sha256 remains supported, as do non-JSON artifacts.
            (root / "analysis.json").write_text(json.dumps({"retrospective": True}))
            (root / "analysis.csv").write_text("successes,attempts\n1,10\n")
            provenance["analysis_sha256"] = {name: sha(root / name) for name in ("analysis.json", "analysis.csv")}
            check_provenance(root, provenance, report, run_ids, ["audit.json"])
            for name in provenance["analysis_sha256"]:
                with self.subTest(artifact=name):
                    path = root / name
                    original = path.read_text()
                    path.write_text(original + "\n")
                    with self.assertRaisesRegex(ValueError, "stale analysis artifact"):
                        check_provenance(root, provenance, report, run_ids, ["audit.json"])
                    path.write_text(original)

    def test_optional_analysis_rejects_stale_source_even_when_report_source_hash_is_updated(self):
        with tempfile.TemporaryDirectory(prefix="proposal-analysis-source-test-") as temp:
            root = Path(temp)
            provenance, report, run_ids = self.report_provenance_fixture(root)
            source_name = "results/first/attempts.json"
            source = root / source_name
            analysis = root / "analysis.json"
            analysis.write_text(json.dumps({"source_sha256": {source_name: sha(source)}}))
            provenance["analysis_sha256"] = {"analysis.json": sha(analysis)}
            check_provenance(root, provenance, report, run_ids, ["audit.json"])
            source.write_text(json.dumps({"changed": "experiment outcomes"}))
            provenance["source_sha256"]["first"]["attempts.json"] = sha(source)
            with self.assertRaisesRegex(ValueError, "Analysis has stale source evidence"):
                check_provenance(root, provenance, report, run_ids, ["audit.json"])


if __name__ == "__main__":
    unittest.main()
