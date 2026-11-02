"""Offline behavioral checks for stopping, shared starts, and honest accounting."""
import contextlib
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.stopstudy_v5 import experiment as exp


class StopExecutionTests(unittest.TestCase):
    def setUp(self):
        self.config = exp.read(exp.ROOT/exp.CONFIG)

    def simulate(self, escape_at):
        tasks = exp.make_schedule(self.config)
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder/"manifest.json").write_text('{}')
            (folder/"schedule.json").write_text(json.dumps(tasks))
            actual = []

            def fake(task, previous, config, folder):
                if task["attempt"] == 1:
                    self.assertIsNone(previous)
                else:
                    self.assertIsNotNone(previous)
                    self.assertEqual(previous["attempt"], task["attempt"]-1)
                    self.assertFalse(previous["success"])
                actual.append(task["task_id"])
                success = task["attempt"] == escape_at
                return {**task, "candidate_id": task["task_id"], "success": success,
                        "parameters": {}, "simulation": {"valid": True},
                        "detector": {"is_trojan": not success}, "detector_cache_reused": False}

            with patch.object(exp, "freeze", return_value=(folder, tasks)), \
                 patch.object(exp, "clean_references"), patch.object(exp, "event", side_effect=fake), \
                 patch.object(exp.shared, "_locked", return_value=contextlib.nullcontext()), \
                 patch.object(exp.shared, "_read_ledger", return_value={"calls": {}}), \
                 patch('builtins.print'):
                completion = exp.run(self.config)
            return completion, exp.read(folder/"attempts.json"), exp.read(folder/"dispositions.json"), actual

    def test_shared_first_escape_stops_all_three_arms_without_extra_calls(self):
        result, rows, tasks, actual = self.simulate(1)
        self.assertEqual(len(actual), 20)
        self.assertEqual(len(rows), 60)
        self.assertEqual(result["skipped_tasks"], 540)
        self.assertTrue(all(r["attempt"] == 1 and r["success"] for r in rows))

    def test_followup_escape_stops_at_first_success_with_no_synthetic_rows(self):
        result, rows, tasks, actual = self.simulate(3)
        self.assertEqual(len(actual), 140)
        self.assertEqual(len(rows), 180)
        self.assertEqual(result["skipped_tasks"], 420)
        self.assertEqual(sum(r["success"] for r in rows), 60)
        self.assertEqual(max(r["attempt"] for r in rows), 3)
        self.assertTrue(all(t.get("first_escape_attempt") == 3 for t in tasks if t["status"] != "executed"))

    def test_no_escape_exhausts_ten_attempts_for_every_session(self):
        result, rows, tasks, actual = self.simulate(None)
        self.assertEqual(len(actual), 560)
        self.assertEqual(len(rows), 600)
        self.assertEqual(result["skipped_tasks"], 0)
        self.assertFalse(any(r["success"] for r in rows))

    def test_apply_event_refuses_any_attempt_after_success(self):
        task = exp.make_schedule(self.config)[0]
        row = {**task, "candidate_id": task["task_id"], "success": True}
        state, rows = {}, []
        exp.apply_event(task, row, state, rows, self.config)
        followup = {**task, "feedback": "binary", "attempt": 2}
        with self.assertRaisesRegex(ValueError, "after first escape"):
            exp.apply_event(followup, {**followup, "success": False}, state, rows, self.config)

    def test_invalid_or_unusable_review_is_not_a_boolean_verdict(self):
        valid = {"is_trojan": False, "confidence": 0.9, "suspect_nodes": [], "feedback_text": "Example"}
        self.assertTrue(exp.check_review(valid))
        for value in (None, {}, {**valid, "is_trojan": "false"}, {**valid, "confidence": float('nan')},
                      {**valid, "confidence": True}, {**valid, "suspect_nodes": [1]}):
            self.assertFalse(exp.check_review(value))

    def test_schedule_pairs_seeds_and_uses_new_distinct_session_seeds(self):
        tasks = exp.make_schedule(self.config)
        self.assertEqual(len(tasks), 560)
        self.assertEqual(len({t['task_id'] for t in tasks}), 560)
        seeds = {}
        for t in tasks:
            key = t['circuit'], t['session'], t['attempt']
            seeds.setdefault(key, set()).add(t['seed'])
        self.assertEqual(len(seeds), 200)
        self.assertTrue(all(len(v) == 1 for v in seeds.values()))
        self.assertEqual(len({next(iter(v)) for v in seeds.values()}), 200)


if __name__ == '__main__':
    unittest.main()
