"""Offline checks for role settings, billed failures, recovery, and spending caps."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from scripts import llm_client as shared
from scripts.stopstudy_v5 import client


OUTPUT = {"is_trojan": False}
SCHEMA = {"type": "object", "properties": {"is_trojan": {"type": "boolean"}},
          "required": ["is_trojan"], "additionalProperties": False}


class FakeResponse:
    def __init__(self, finish="stop", refusal=None, model=client.MODEL):
        self.headers = {"x-request-id": "offline-stop-request"}
        self.body = {"id": "offline-stop-response", "model": model,
                     "system_fingerprint": "fp_offline",
                     "usage": {"prompt_tokens": 100, "completion_tokens": 20,
                               "prompt_tokens_details": {"cached_tokens": 40}},
                     "choices": [{"finish_reason": finish, "message": {
                         "content": json.dumps(OUTPUT), "refusal": refusal}}]}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.body).encode()


class StopV5ClientTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="stop-v5-client-test-")
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
                       "schema": SCHEMA, "role": "stop_detector", "seed": 19}

    def ledger(self):
        return json.loads((self.root / "results/cost_ledger.json").read_text())

    def test_roles_send_distinct_frozen_temperature_and_allowance(self):
        for role, temperature, limit in [("stop_attacker", .3, 500), ("stop_detector", 0, 1600)]:
            result = client.json_call(**dict(self.kwargs, role=role), call_id=client.CALL_PREFIX + role)
            payload = json.loads(self.network.call_args.args[0].data)
            self.assertEqual((payload["model"], payload["temperature"], payload["max_tokens"]),
                             (client.MODEL, temperature, limit))
            self.assertEqual(result["temperature"], temperature)
            record = json.loads((self.root / result["record_path"]).read_text())
            self.assertEqual(record["role"], role)
            self.assertEqual(record["request"], payload)

    def test_invalid_role_seed_or_allowance_never_calls_api(self):
        invalid = [{"role": "attacker"}, {"seed": True}, {"seed": -1},
                   {"seed": 2147483648}, {"max_tokens": 500}, {"max_tokens": True}]
        for index, change in enumerate(invalid):
            with self.subTest(change=change), self.assertRaises(ValueError):
                client.json_call(**dict(self.kwargs, **change), call_id=client.CALL_PREFIX + str(index))
        with self.assertRaises(ValueError):
            client.json_call(**self.kwargs, call_id="another_experiment")
        self.network.assert_not_called()

    def test_exact_resume_does_not_double_bill_but_new_ids_are_new_requests(self):
        for index in range(2):
            client.json_call(**self.kwargs, call_id=client.CALL_PREFIX + str(index))
        result = client.json_call(**self.kwargs, call_id=client.CALL_PREFIX + "1")
        self.assertTrue(result["cache_hit"])
        self.assertEqual(result["cost_usd"], 0)
        self.assertEqual(self.network.call_count, 2)
        # Includes cached-input pricing: 60*.15+40*.075+20*.60, per million.
        self.assertAlmostEqual(self.ledger()["spent_usd"], 2*.000024)

    def test_changed_request_or_role_rejects_id_collision_before_network(self):
        call_id = client.CALL_PREFIX + "collision"
        client.json_call(**self.kwargs, call_id=call_id)
        for change in [{"seed": 20}, {"role": "stop_attacker"}]:
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "collision"):
                client.json_call(**dict(self.kwargs, **change), call_id=call_id)
        self.assertEqual(self.network.call_count, 1)

    def test_project_and_study_caps_prevent_network(self):
        for owner, name in [(client, "STUDY_CAP_USD"), (shared, "HARD_CAP_USD")]:
            with self.subTest(name=name), patch.object(owner, name, 0):
                with self.assertRaises(client.BudgetExceeded):
                    client.json_call(**self.kwargs, call_id=client.CALL_PREFIX + name)
        self.network.assert_not_called()
        self.assertFalse((self.root / "results/cost_ledger.json").exists())

    def test_budget_uses_v5_prefix_and_keeps_v4_in_project_total(self):
        entries = {client.CALL_PREFIX + "legacy": {"role": "other", "status": "success", "actual_cost_usd": .2},
                   "proposal_stop_v4_attacker": {"role": "stop_attacker", "status": "success", "actual_cost_usd": .3},
                   "proposal_stop_v4_detector": {"role": "stop_detector", "status": "uncertain", "reserved_usd": .4},
                   client.CALL_PREFIX + "detector": {"role": "stop_detector", "status": "reserved", "reserved_usd": .5},
                   "unrelated": {"role": "other", "status": "reserved", "reserved_usd": .1}}
        state = client.budget_state({"calls": entries})
        self.assertEqual(state["study_committed_usd"], .7)
        self.assertEqual(state["project_committed_usd"], 1.5)

    def test_transport_recovery_retains_original_hold_and_resumes_without_calls(self):
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

    def test_second_transport_failure_never_creates_a_third_attempt(self):
        self.network.side_effect = TimeoutError("offline timeout")
        call_id = client.CALL_PREFIX + "twice"
        for _ in range(2):
            with self.assertRaises(client.APIRequestError):
                client.json_call(**self.kwargs, call_id=call_id)
        self.assertEqual(self.network.call_count, 2)
        self.assertEqual(len(self.ledger()["calls"]), 2)
        self.assertEqual(self.ledger()["spent_usd"], 0)
        self.assertGreater(self.ledger()["held_usd"], 0)

    def test_original_hold_counts_against_recovery_budget(self):
        reserve = client.reservation(client.payload_for(**self.kwargs))[1]
        self.network.side_effect = TimeoutError("offline timeout")
        with patch.object(client, "STUDY_CAP_USD", reserve*1.5):
            with self.assertRaises(client.BudgetExceeded):
                client.json_call(**self.kwargs, call_id=client.CALL_PREFIX + "limited_retry")
        self.assertEqual(self.network.call_count, 1)
        self.assertEqual(len(self.ledger()["calls"]), 1)
        self.assertAlmostEqual(self.ledger()["held_usd"], reserve)

    def test_http_rejections_and_server_failures_are_not_retried(self):
        for code in (400, 503):
            self.network.side_effect = urllib.error.HTTPError(shared.ENDPOINT, code, "offline", {}, io.BytesIO(b"offline"))
            call_id = client.CALL_PREFIX + "http" + str(code)
            for _ in range(2):
                with self.assertRaises(client.APIRequestError):
                    client.json_call(**self.kwargs, call_id=call_id)
            entry = self.ledger()["calls"][call_id]
            self.assertEqual(entry["status"], "rejected" if code == 400 else "uncertain")
        self.assertEqual(self.network.call_count, 2)
        self.assertGreater(self.ledger()["held_usd"], 0)

    def test_unusable_outputs_are_billed_once_without_output_retry(self):
        responses = [FakeResponse(finish="length"), FakeResponse(refusal="offline refusal"),
                     FakeResponse(model="different-model")]
        invalid_json = FakeResponse()
        invalid_json.body["choices"][0]["message"]["content"] = "not JSON"
        responses.append(invalid_json)
        for index, response in enumerate(responses):
            self.network.return_value = response
            call_id = client.CALL_PREFIX + "unusable" + str(index)
            for _ in range(2):
                with self.assertRaises(client.APIOutputError):
                    client.json_call(**self.kwargs, call_id=call_id)
        self.assertEqual(self.network.call_count, len(responses))
        self.assertAlmostEqual(self.ledger()["spent_usd"], len(responses)*.000024)
        self.assertEqual(self.ledger()["held_usd"], 0)

    def test_malformed_usage_is_retained_without_transport_retry(self):
        response = FakeResponse()
        response.body["usage"]["prompt_tokens_details"]["cached_tokens"] = 1000
        self.network.return_value = response
        with self.assertRaises(client.APIRequestError):
            client.json_call(**self.kwargs, call_id=client.CALL_PREFIX + "bad_usage")
        self.assertEqual(self.network.call_count, 1)
        self.assertGreater(self.ledger()["held_usd"], 0)
        self.assertFalse(next(iter(self.ledger()["calls"].values()))["transport_failure"])


if __name__ == "__main__":
    unittest.main()
