"""Adversarial fixture checks that the offline audit detects data misattribution."""
import copy
import json
import unittest

from scripts.eval.verify_cross_review import check_union_reviews, check_raw, STRONGER


def verdict(flag):
    return {"is_trojan": flag, "confidence": .8, "suspect_nodes": [], "feedback_text": "fixture"}


class CrossReviewAuditTests(unittest.TestCase):
    def setUp(self):
        a = {"candidate_id": "a", "netlist_sha256": "hash-one", "circuit": "opamp",
             "simulation": {"valid": True}, "detector": verdict(True)}
        b = dict(copy.deepcopy(a), candidate_id="b")
        c = {"candidate_id": "c", "netlist_sha256": "hash-two", "circuit": "and4",
             "simulation": {"valid": False}, "detector": verdict(False)}
        self.sources = {"baseline": [a, copy.deepcopy(a)], "extension": [b,c]}
        self.reviews = [
            {"sha256": "hash-one", "circuit": "opamp", "representative_id": "a", "valid": True,
             "baseline_detector": verdict(True), "stronger_detector": verdict(True),
             "members": [{"run": "baseline", "id": "a", "valid": True, "baseline_flag": True},
                         {"run": "extension", "id": "b", "valid": True, "baseline_flag": True}]},
            {"sha256": "hash-two", "circuit": "and4", "representative_id": "c", "valid": False,
             "baseline_detector": verdict(False), "stronger_detector": verdict(True),
             "members": [{"run": "extension", "id": "c", "valid": False, "baseline_flag": False}]},
        ]

    def test_all_union_includes_invalid_and_opposite_verdict(self):
        groups = check_union_reviews(self.sources, self.reviews)
        self.assertEqual(set(groups), {"hash-one", "hash-two"})
        self.assertEqual(sum(len(members) for members in groups.values()), 3)

    def test_rejects_filtering_invalid_or_negative_examples(self):
        with self.assertRaisesRegex(ValueError, "omitted/duplicated"):
            check_union_reviews(self.sources, self.reviews[:1])

    def test_rejects_wrong_representative_and_baseline_verdict(self):
        changed = copy.deepcopy(self.reviews)
        changed[0]["representative_id"] = "b"
        with self.assertRaisesRegex(ValueError, "lexicographically"):
            check_union_reviews(self.sources, changed)
        changed = copy.deepcopy(self.reviews)
        changed[0]["baseline_detector"] = verdict(False)
        with self.assertRaisesRegex(ValueError, "Baseline verdict"):
            check_union_reviews(self.sources, changed)

    def test_rejects_omitted_members_and_inconsistent_physics(self):
        changed = copy.deepcopy(self.reviews)
        changed[0]["members"] = changed[0]["members"][:1]
        with self.assertRaisesRegex(ValueError, "membership"):
            check_union_reviews(self.sources, changed)
        sources = copy.deepcopy(self.sources)
        sources["extension"][0]["simulation"]["valid"] = False
        with self.assertRaisesRegex(ValueError, "inconsistent physical"):
            check_union_reviews(sources, self.reviews)

    def raw_fixture(self):
        messages = [{"role": "user", "content": "fixture"}]
        schema = {"type": "object"}
        output = {"ok": True}
        usage = {"prompt_tokens": 10, "completion_tokens": 5}
        raw = {"request": {"model": STRONGER, "messages": messages, "temperature": .3,
                           "max_completion_tokens": 700, "reasoning_effort": "none",
                           "response_format": {"type": "json_schema", "json_schema": {
                               "name": "experiment_output", "strict": True, "schema": schema}}},
               "response": {"model": STRONGER, "usage": usage,
                            "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(output)}}]},
               "result": {"model": STRONGER, "usage": usage, "output": output,
                          "seed_sent": False, "requested_seed": None},
               "seed_sent": False, "requested_seed": None}
        return raw, messages, schema, output

    def test_actual_returned_model_checked_independently_of_result_metadata(self):
        raw, messages, schema, output = self.raw_fixture()
        check_raw(raw, STRONGER, messages, schema, output, seed=None, max_tokens=700)
        raw["response"]["model"] = "different-returned-model"
        with self.assertRaisesRegex(ValueError, "Actual response model"):
            check_raw(raw, STRONGER, messages, schema, output, seed=None, max_tokens=700)

    def test_raw_prompt_and_seed_tampering_detected(self):
        raw, messages, schema, output = self.raw_fixture()
        changed = copy.deepcopy(raw)
        changed["request"]["messages"][0]["content"] = "different prompt"
        with self.assertRaisesRegex(ValueError, "prompt messages"):
            check_raw(changed, STRONGER, messages, schema, output, seed=None, max_tokens=700)
        changed = copy.deepcopy(raw)
        changed["request"]["seed"] = 7
        with self.assertRaisesRegex(ValueError, "stronger-model seed"):
            check_raw(changed, STRONGER, messages, schema, output, seed=None, max_tokens=700)


if __name__ == "__main__":
    unittest.main()
