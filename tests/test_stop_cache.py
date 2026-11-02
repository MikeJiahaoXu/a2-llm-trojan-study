"""Offline fixed-reviewer checks across tasks, resumption, and failed outputs."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import llm_client as shared
from scripts.stopstudy import client, experiment


VERDICT = {"is_trojan": False, "confidence": .75, "suspect_nodes": [],
           "feedback_text": "Offline fixed judgment."}


class FixedReviewerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="stop-cache-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.folder = self.root / "results/proposal_stop_v4"
        self.config = {"run_id": "proposal_stop_v4", "detector_seed": 42001}
        self.prompt = "Offline reviewer prompt."
        self.output = copy.deepcopy(VERDICT)
        self.output_error = None
        patches = [
            patch.object(experiment, "ROOT", self.root),
            patch.object(client, "record_path", side_effect=lambda call_id: self.root / "results/api" / (call_id + ".json")),
            patch.object(experiment, "detector_messages", side_effect=lambda circuit, netlist: [
                {"role": "system", "content": self.prompt},
                {"role": "user", "content": circuit + "\n" + netlist}]),
            patch.object(client.urllib.request, "urlopen", side_effect=AssertionError("No network allowed")),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        mocked = patch.object(client, "json_call", side_effect=self.fake_call)
        self.call = mocked.start()
        self.addCleanup(mocked.stop)

    def fake_call(self, messages, schema, call_id, role, seed, max_tokens=None):
        payload = client.payload_for(messages, schema, role, seed, max_tokens)
        result = {"output": copy.deepcopy(self.output), "record_path": str(client.record_path(call_id).relative_to(self.root))}
        if self.output_error:
            result["output_error"] = self.output_error
        # The runner requires durable evidence even for an unusable generation.
        record = {"call_id": call_id, "role": role, "request": payload,
                  "request_sha256": client.request_identity(payload, role), "result": result}
        shared._atomic_json(client.record_path(call_id), record)
        if self.output_error:
            raise client.APIOutputError(self.output_error)
        return result

    def review(self, task_id, netlist="M1 out in 0 0 NMOS\n"):
        return experiment.review_fixed("and4", netlist, task_id, self.config, self.folder)

    def test_same_dut_across_tasks_has_one_call_and_correct_resumption_flag(self):
        first, reused = self.review("first_task")
        self.assertFalse(reused)
        resumed, reused = self.review("first_task")
        self.assertFalse(reused)
        another, reused = self.review("second_task")
        self.assertTrue(reused)
        third, reused = self.review("third_task")
        self.assertTrue(reused)
        self.assertEqual(first, resumed)
        self.assertEqual(first, another)
        self.assertEqual(first, third)
        self.assertEqual(self.call.call_count, 1)
        self.assertEqual(first["detector"], VERDICT)
        self.assertEqual(len(list((self.folder / "detector_cache").glob("*.json"))), 1)
        self.assertEqual(first["request"]["temperature"], 0)
        self.assertEqual(first["request"]["seed"], self.config["detector_seed"])

    def test_first_unusable_reply_is_frozen_without_resampling(self):
        self.output_error = "Billed API output unusable: truncated"
        first, reused = self.review("first_task")
        self.assertFalse(reused)
        self.assertFalse(first["usable"])
        self.assertIsNone(first["detector"])
        self.assertEqual(first["error"], self.output_error)
        # A hypothetical subsequent healthy service must not change the label.
        self.output_error = None
        resumed, reused = self.review("first_task")
        self.assertFalse(reused)
        repeated, reused = self.review("another_task")
        self.assertTrue(reused)
        self.assertEqual(first, resumed)
        self.assertEqual(first, repeated)
        self.assertEqual(self.call.call_count, 1)

    def test_schema_invalid_reply_is_cached_as_unusable(self):
        self.output = dict(VERDICT, is_trojan="false")
        first, _ = self.review("first_task")
        self.assertEqual(first["error"], "review_schema_invalid")
        self.assertFalse(first["usable"])
        self.assertIsNone(first["detector"])
        self.output = VERDICT
        second, reused = self.review("another_task")
        self.assertTrue(reused)
        self.assertEqual(first, second)
        self.assertEqual(self.call.call_count, 1)

    def test_different_dut_gets_a_different_cache_key(self):
        first, _ = self.review("first_task", "R1 out 0 1000\n")
        second, reused = self.review("second_task", "R1 out 0 2000\n")
        self.assertFalse(reused)
        self.assertNotEqual(first["cache_key"], second["cache_key"])
        self.assertNotEqual(first["netlist_sha256"], second["netlist_sha256"])
        self.assertEqual(self.call.call_count, 2)

    def test_changed_prompt_payload_cannot_reuse_old_verdict(self):
        first, _ = self.review("first_task")
        self.prompt = "A different offline reviewer prompt."
        second, reused = self.review("second_task")
        self.assertFalse(reused)
        self.assertNotEqual(first["cache_key"], second["cache_key"])
        self.assertEqual(first["netlist_sha256"], second["netlist_sha256"])
        self.assertNotEqual(first["request"], second["request"])
        self.assertEqual(self.call.call_count, 2)

    def test_modified_raw_response_is_rejected_before_any_new_call(self):
        first, _ = self.review("first_task")
        raw_path = self.root / first["api_records"][0]["path"]
        raw = json.loads(raw_path.read_text())
        raw["result"]["output"]["is_trojan"] = True
        shared._atomic_json(raw_path, raw)
        with self.assertRaisesRegex(ValueError, "response changed"):
            self.review("another_task")
        self.assertEqual(self.call.call_count, 1)

    def test_cache_input_corruption_is_rejected_without_api(self):
        first, _ = self.review("first_task")
        cache_path = self.folder / "detector_cache" / (first["cache_key"] + ".json")
        corrupt = copy.deepcopy(first)
        corrupt["request"]["temperature"] = .3
        shared._atomic_json(cache_path, corrupt)
        with self.assertRaisesRegex(ValueError, "input mismatch"):
            self.review("another_task")
        self.assertEqual(self.call.call_count, 1)


if __name__ == "__main__":
    unittest.main()
