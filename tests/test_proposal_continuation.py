"""The explicit continuation preserves the frozen schedule and seals its exception."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.proposal import continue_after_controls as continuation, experiment


class ProposalContinuationTests(unittest.TestCase):
    def test_continuation_uses_exact_frozen_trial_body_and_request_sequence(self):
        self.assertEqual(len(continuation.trial_body_hash(continuation.ROOT)), 64)
        config = {"circuits": ["opamp", "and4"], "feedback_levels": ["none", "binary", "full"],
                  "trajectories": 2, "rounds_per_trajectory": 10,
                  "run_seeds": {continuation.RUN_ID: 210101}}
        traces = []
        with tempfile.TemporaryDirectory(prefix="proposal-continuation-test-") as temp:
            root = Path(temp)
            folder = root / "results" / continuation.RUN_ID
            for original in (True, False):
                calls = []
                def candidate(circuit, call_id, seed, config, previous=None, feedback="none"):
                    calls.append((circuit, call_id, seed, feedback, copy.deepcopy(previous)))
                    return {"candidate_id": call_id, "parameters": {"fixture": call_id},
                            "simulation": {"valid": True}, "success": seed % 2 == 0,
                            "detector": {"is_trojan": seed % 2 != 0, "feedback_text": "offline review"}}
                with patch.object(experiment, "freeze", return_value=folder), patch.object(experiment, "controls") as controls, \
                     patch.object(experiment, "candidate", side_effect=candidate), \
                     patch.object(continuation, "candidate", side_effect=candidate), \
                     patch.object(continuation, "ROOT", root), patch("builtins.print"):
                    rows = experiment.run(config, continuation.RUN_ID) if original else continuation.continue_trials(config, continuation.RUN_ID)
                    self.assertEqual(controls.call_count, 1 if original else 0)
                traces.append((calls, rows))
            self.assertEqual(traces[0], traces[1])
            self.assertEqual(len(traces[1][0]), 112)
            self.assertEqual(len(traces[1][1]), 120)

    def test_exception_cannot_be_used_for_other_run_identifiers(self):
        with self.assertRaisesRegex(ValueError, "restricted"):
            continuation.base_evidence(Path("/unused"), "another_run")

    def test_preparation_refuses_existing_attacks_and_detects_tampered_sidecar(self):
        with tempfile.TemporaryDirectory(prefix="proposal-deviation-test-") as temp:
            root = Path(temp)
            folder = root / "results" / continuation.RUN_ID
            folder.mkdir(parents=True)
            evidence = {"source_hashes": {"fixture": "hash"}, "controls_sha256": "original_controls"}
            with patch.object(continuation, "base_evidence", return_value=({}, evidence)):
                (folder / "attempts.json").write_text('[{"candidate_id":"already_generated"}]')
                with self.assertRaisesRegex(ValueError, "before repeat attacks"):
                    continuation.prepare(root, continuation.RUN_ID)
                (folder / "attempts.json").unlink()
                sealed = continuation.prepare(root, continuation.RUN_ID)
                self.assertFalse(sealed["deviation"]["original_gate_passed"])
                self.assertEqual(continuation.verify_deviation(root, continuation.RUN_ID), sealed)
                sealed["deviation"]["original_gate_passed"] = True
                (folder / continuation.SIDECAR).write_text(json.dumps(sealed))
                with self.assertRaisesRegex(ValueError, "integrity seal"):
                    continuation.verify_deviation(root, continuation.RUN_ID)


if __name__ == "__main__":
    unittest.main()
