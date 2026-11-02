"""Offline protocol, budget, failure accounting, and paired-analysis tests."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from scripts import llm_client as shared
from scripts.defense import client, experiment, analyze


OUTPUT = {"is_trojan": False, "confidence": 0.5, "suspect_nodes": [], "feedback_text": "Offline review."}


class FakeResponse:
    def __init__(self, output=None, finish="stop", refusal=None):
        self.headers = {"x-request-id": "offline-defense-request"}
        self.body = {"id": "offline-defense-response", "model": client.MODEL,
                     "system_fingerprint": "fp_offline",
                     "usage": {"prompt_tokens": 100, "completion_tokens": 20,
                               "prompt_tokens_details": {"cached_tokens": 40}},
                     "choices": [{"finish_reason": finish, "message": {
                         "content": json.dumps(OUTPUT if output is None else output), "refusal": refusal}}]}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.body).encode()


class IsolatedClient(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="defense-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for item in [patch.object(shared, "ROOT", self.root),
                     patch.object(shared, "RESULTS", self.root / "results"),
                     patch.object(shared, "_key", return_value="offline-credential")]:
            item.start()
            self.addCleanup(item.stop)
        network = patch.object(client.urllib.request, "urlopen", return_value=FakeResponse())
        self.network = network.start()
        self.addCleanup(network.stop)
        self.kwargs = {"messages": [{"role": "user", "content": "Offline input."}],
                       "schema": experiment.SCHEMA, "seed": 19}

    def ledger(self):
        return json.loads((self.root / "results/cost_ledger.json").read_text())


class ClientTests(IsolatedClient):
    def test_fresh_repetitions_and_exact_resume_do_not_double_bill(self):
        for rep in range(3):
            client.json_call(**self.kwargs, call_id=client.CALL_PREFIX + str(rep))
        again = client.json_call(**self.kwargs, call_id=client.CALL_PREFIX + "1")
        self.assertTrue(again["cache_hit"])
        self.assertEqual(again["cost_usd"], 0)
        self.assertEqual(self.network.call_count, 3)
        self.assertAlmostEqual(self.ledger()["spent_usd"], 3*.000024)
        payload = json.loads(self.network.call_args.args[0].data)
        self.assertEqual((payload["model"], payload["temperature"], payload["max_tokens"]), (client.MODEL, 0, 1200))

    def test_changed_request_rejects_cache_collision_before_network(self):
        call_id = client.CALL_PREFIX + "collision"
        client.json_call(**self.kwargs, call_id=call_id)
        with self.assertRaisesRegex(ValueError, "collision"):
            client.json_call(**dict(self.kwargs, seed=20), call_id=call_id)
        self.assertEqual(self.network.call_count, 1)

    def test_global_and_supplement_caps_prevent_any_network(self):
        for owner, name in [(client, "SUPPLEMENT_CAP_USD"), (shared, "HARD_CAP_USD")]:
            with self.subTest(name=name), patch.object(owner, name, 0):
                with self.assertRaises(client.BudgetExceeded):
                    client.json_call(**self.kwargs, call_id=client.CALL_PREFIX + name)
        self.network.assert_not_called()
        self.assertFalse((self.root / "results/cost_ledger.json").exists())

    def test_supplement_cap_counts_prefix_or_role_and_existing_holds(self):
        entries = {client.CALL_PREFIX + "old": {"role": "other", "status": "success", "actual_cost_usd": .7},
                   "other_id": {"role": client.ROLE, "status": "uncertain", "reserved_usd": .8},
                   "baseline": {"role": "detector", "status": "success", "actual_cost_usd": .2}}
        state = client.budget_state({"calls": entries})
        self.assertEqual(state["supplement_committed_usd"], 1.5)
        self.assertEqual(state["project_committed_usd"], 1.7)

    def test_transport_retry_retains_hold_and_is_cached_on_resume(self):
        self.network.side_effect = [TimeoutError("offline timeout"), FakeResponse()]
        call_id = client.CALL_PREFIX + "transport"
        client.json_call(**self.kwargs, call_id=call_id)
        again = client.json_call(**self.kwargs, call_id=call_id)
        ledger = self.ledger()
        self.assertEqual(set(ledger["calls"]), {call_id, call_id + "_transport_retry1"})
        self.assertEqual(ledger["calls"][call_id]["status"], "uncertain")
        self.assertAlmostEqual(ledger["held_usd"], ledger["calls"][call_id]["reserved_usd"])
        self.assertAlmostEqual(ledger["spent_usd"], .000024)
        self.assertTrue(again["cache_hit"])
        self.assertEqual(self.network.call_count, 2)

    def test_retained_transport_hold_counts_against_retry_cap(self):
        reserve = client.reservation(client.payload_for(self.kwargs["messages"], self.kwargs["schema"], 19))[1]
        self.network.side_effect = TimeoutError("offline timeout")
        with patch.object(client, "SUPPLEMENT_CAP_USD", reserve*1.5):
            with self.assertRaises(client.BudgetExceeded):
                client.json_call(**self.kwargs, call_id=client.CALL_PREFIX + "limited_retry")
        self.assertEqual(self.network.call_count, 1)
        self.assertEqual(len(self.ledger()["calls"]), 1)
        self.assertAlmostEqual(self.ledger()["held_usd"], reserve)

    def test_http_response_never_retried_and_503_hold_retained(self):
        self.network.side_effect = urllib.error.HTTPError(shared.ENDPOINT, 503, "offline", {}, io.BytesIO(b"offline"))
        with self.assertRaises(client.APIRequestError):
            client.json_call(**self.kwargs, call_id=client.CALL_PREFIX + "http")
        self.assertEqual(self.network.call_count, 1)
        self.assertGreater(self.ledger()["held_usd"], 0)

    def test_truncation_and_refusal_are_charged_once_and_never_retried(self):
        for index, response in enumerate([FakeResponse(finish="length"), FakeResponse(refusal="offline refusal")]):
            self.network.return_value = response
            call_id = client.CALL_PREFIX + "unusable" + str(index)
            for _ in range(2):
                with self.assertRaises(client.APIOutputError):
                    client.json_call(**self.kwargs, call_id=call_id)
        self.assertEqual(self.network.call_count, 2)
        self.assertAlmostEqual(self.ledger()["spent_usd"], .000048)
        self.assertEqual(self.ledger()["held_usd"], 0)


class ExperimentTests(IsolatedClient):
    def setUp(self):
        super().setUp()
        self.config = json.loads((experiment.ROOT / experiment.CONFIG_PATH).read_text())
        self.config.update(expected_cases=2, expected_observed_cases={"and4": 1, "opamp": 1},
                           expected_controls_per_circuit={"clean": 0, "positive": 0})
        for filename in experiment.RUNTIME_FILES + [experiment.CONFIG_PATH, self.config["prompt"], self.config["protocol_document"]]:
            path = self.root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Offline immutable source fixture.\n")
        (self.root / experiment.CONFIG_PATH).write_text(json.dumps(self.config))
        cases = []
        for circuit in ["and4", "opamp"]:
            netlist = "* exact bytes " + circuit + "\nR1 out 0 1000\n"
            digest = hashlib.sha256(netlist.encode()).hexdigest()
            relative = "results/defense_comparison_v1/corpus/" + digest[:16] + "/dut.cir"
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(netlist)
            summary = "normal sample " + circuit
            cases.append({"case_id": digest[:16], "circuit": circuit, "label": "trojan",
                          "netlist_path": relative, "netlist_sha256": digest,
                          "summary_text": summary, "summary_sha256": hashlib.sha256(summary.encode()).hexdigest(),
                          "memberships": [{"kind": "candidate", "run_id": "historical-secret", "earlier_verdict": True}]*3,
                          "normal_simulation": {"sha256": {}}})
        self.corpus = {"protocol": "defense_comparison_v1", "cases": cases, "source_sha256": {}}
        (self.root / self.config["corpus"]).write_text(json.dumps(self.corpus))

    def test_pairing_only_appends_summary_and_never_metadata(self):
        tasks = experiment.build_tasks(self.root, self.config, self.corpus, "shared system")
        self.assertEqual(len(tasks), 12)
        self.assertEqual(len({t["call_id"] for t in tasks}), 12)
        self.assertEqual(tasks, experiment.build_tasks(self.root, self.config, self.corpus, "shared system"))
        for case in self.corpus["cases"]:
            seeds = []
            for rep in range(3):
                pair = {t["condition"]: t for t in tasks if t["case_id"] == case["case_id"] and t["repetition"] == rep}
                left, right = pair["netlist_only"]["request"], pair["normal_logs"]["request"]
                self.assertEqual(left["seed"], right["seed"])
                seeds.append(left["seed"])
                self.assertEqual(left["messages"][0], right["messages"][0])
                self.assertEqual(left["messages"][1]["content"] + experiment.SUMMARY_SEPARATOR + case["summary_text"], right["messages"][1]["content"])
                self.assertNotIn("historical-secret", json.dumps(left))
                self.assertNotIn(case["netlist_path"], json.dumps(right))
                self.assertEqual({k:v for k,v in left.items() if k != "messages"}, {k:v for k,v in right.items() if k != "messages"})
            self.assertEqual(len(set(seeds)), 3)

    def test_freeze_offline_and_resume_rejects_source_mutation(self):
        manifest, tasks, _ = experiment.freeze(self.root)
        self.assertEqual(manifest["planned_primary_requests"], 12)
        self.assertEqual(experiment.freeze(self.root)[0], manifest)
        self.network.assert_not_called()
        (self.root / self.config["prompt"]).write_text("Changed after freeze")
        with self.assertRaisesRegex(ValueError, "Frozen protocol changed"):
            experiment.freeze(self.root)

    def test_fixed_denominator_retains_truncation_and_resume_uses_no_calls(self):
        self.network.side_effect = [FakeResponse(finish="length")] + [FakeResponse() for _ in range(11)]
        complete = experiment.run(self.root)
        self.assertTrue(complete["complete"])
        self.assertEqual((complete["recorded_reviews"], complete["usable_reviews"], complete["unusable_reviews"]), (12, 11, 1))
        self.assertEqual(self.network.call_count, 12)
        experiment.run(self.root)
        self.assertEqual(self.network.call_count, 12)
        rows = json.loads((self.root / "results/defense_comparison_v1/reviews.json").read_text())
        summary = analyze.summarize(self.corpus, rows)
        self.assertEqual(summary["unusable_reviews"], 1)
        self.assertEqual(sum(g["scheduled_reviews"] for g in summary["groups"]), 12)
        self.assertEqual(sum(g["negative"] for g in summary["groups"]), 11)

    def test_unavailable_request_is_retained_then_resume_continues_next_task(self):
        self.network.side_effect = urllib.error.HTTPError(shared.ENDPOINT, 503, "offline", {}, io.BytesIO(b"offline"))
        with self.assertRaises(client.APIRequestError):
            experiment.run(self.root)
        rows_path = self.root / "results/defense_comparison_v1/reviews.json"
        rows = json.loads(rows_path.read_text())
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["usable"])
        self.network.side_effect = None
        complete = experiment.run(self.root)
        self.assertEqual(complete["unusable_reviews"], 1)
        self.assertEqual(self.network.call_count, 12)

    def test_membership_dedup_and_paired_direction_use_cases_not_source_rows(self):
        tasks = experiment.build_tasks(self.root, self.config, self.corpus, "system")
        rows = []
        for task in tasks:
            row = {key: task[key] for key in ["case_id", "circuit", "condition", "repetition"]}
            row.update(usable=True, output=dict(OUTPUT, is_trojan=task["condition"] == "normal_logs"))
            if task["circuit"] == "and4" and task["condition"] == "normal_logs" and task["repetition"] == 2:
                row.update(usable=False, output=None)
            rows.append(row)
        summary = analyze.summarize(self.corpus, rows)
        groups = [g for g in summary["groups"] if g["population"] == "observed_candidates"]
        self.assertTrue(all(g["distinct_cases"] == 1 and g["scheduled_reviews"] == 3 for g in groups))
        paired = next(p for p in summary["paired"] if p["circuit"] == "and4" and p["population"] == "observed_candidates")
        self.assertEqual(paired["transitions"]["negative_to_positive"], 2)
        self.assertEqual(paired["transitions"]["negative_to_unusable"], 1)
        self.assertEqual(paired["both_usable_pairs"], 2)
        majority = next(c for c in summary["per_case"] if c["circuit"] == "and4" and c["condition"] == "normal_logs")
        self.assertEqual(majority["majority"], "unusable")
        with self.assertRaisesRegex(ValueError, "every scheduled"):
            analyze.summarize(self.corpus, rows[:-1])


if __name__ == "__main__":
    unittest.main()
