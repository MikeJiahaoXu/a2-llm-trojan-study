"""Offline checks for model pricing, shared budget, and cache identity."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from scripts import llm_client as shared
from scripts import model_client as client


class FakeResponse:
    def __init__(self, model, refusal=None):
        self.headers = {"x-request-id": "offline-model-request"}
        self.body = {
            "id": "offline-model-response", "model": model,
            "usage": {"prompt_tokens": 100, "completion_tokens": 20,
                      "prompt_tokens_details": {"cached_tokens": 40},
                      "completion_tokens_details": {"reasoning_tokens": 12}},
            "choices": [{"finish_reason": "stop", "message": {
                "content": None if refusal else '{"ok": true}', "refusal": refusal,
            }}],
        }

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.body).encode()


class ModelClientTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="a2-model-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for item in [patch.object(shared, "ROOT", self.root),
                     patch.object(shared, "RESULTS", self.root / "results"),
                     patch.object(shared, "_key", return_value="offline-credential")]:
            item.start()
            self.addCleanup(item.stop)
        network_patch = patch.object(client.urllib.request, "urlopen")
        self.network = network_patch.start()
        self.addCleanup(network_patch.stop)
        self.network.side_effect = lambda request, timeout: FakeResponse(json.loads(request.data)["model"])
        self.kwargs = {"messages": [{"role": "user", "content": "Return JSON."}],
                       "schema": {"type": "object", "properties": {"ok": {"type": "boolean"}},
                                  "required": ["ok"], "additionalProperties": False},
                       "role": "offline-test", "max_tokens": 100, "seed": 31}

    def ledger(self):
        return json.loads((self.root / "results/cost_ledger.json").read_text())

    def test_mixed_models_share_ledger_and_charge_all_completion_tokens(self):
        old = client.json_call(**self.kwargs, call_id="old", model=client.BASELINE_MODEL)
        new = client.json_call(**self.kwargs, call_id="new", model=client.STRONGER_MODEL)
        self.assertAlmostEqual(old["cost_usd"], .000024)
        # All 20 completion tokens are billed, including the 12 reasoning tokens.
        self.assertAlmostEqual(new["cost_usd"], .000138)
        ledger = self.ledger()
        self.assertAlmostEqual(ledger["spent_usd"], .000162)
        self.assertEqual(ledger["held_usd"], 0)
        self.assertEqual(ledger["calls"]["old"]["pricing_per_million"]["output"], .60)
        self.assertEqual(ledger["calls"]["new"]["pricing_per_million"]["output"], 4.50)
        self.assertTrue(old["seed_sent"])
        self.assertFalse(new["seed_sent"])
        self.assertEqual(new["requested_seed"], 31)
        sent = json.loads(self.network.call_args_list[1].args[0].data)
        self.assertNotIn("seed", sent)
        self.assertNotIn("max_tokens", sent)
        self.assertEqual(sent["max_completion_tokens"], 100)
        self.assertEqual(sent["reasoning_effort"], "none")
        self.assertEqual(sent["temperature"], .3)

    def test_cache_isolated_by_model_and_exact_request(self):
        first = client.json_call(**self.kwargs, call_id="same", model=client.STRONGER_MODEL)
        cached = client.json_call(**self.kwargs, call_id="same", model=client.STRONGER_MODEL)
        self.assertEqual(first["output"], cached["output"])
        self.assertTrue(cached["cache_hit"])
        self.assertEqual(cached["cost_usd"], 0)
        with self.assertRaisesRegex(ValueError, "collision"):
            client.json_call(**self.kwargs, call_id="same", model=client.BASELINE_MODEL)
        self.assertEqual(self.network.call_count, 1)
        self.assertAlmostEqual(self.ledger()["spent_usd"], .000138)

    def test_baseline_payload_and_cache_match_frozen_client(self):
        original = shared.json_call(**self.kwargs, call_id="compatible")
        reused = client.json_call(**self.kwargs, call_id="compatible", model=client.BASELINE_MODEL)
        self.assertTrue(reused["cache_hit"])
        self.assertEqual(reused["original_cost_usd"], original["cost_usd"])
        self.assertEqual(self.network.call_count, 1)

    def test_transport_recovery_keeps_model_price_and_original_reservation(self):
        self.network.side_effect = [TimeoutError("offline failure"), FakeResponse(client.STRONGER_MODEL)]
        result = client.json_call(**self.kwargs, call_id="recover", model=client.STRONGER_MODEL)
        ledger = self.ledger()
        self.assertEqual(set(ledger["calls"]), {"recover", "recover_transport_retry1"})
        self.assertEqual(ledger["calls"]["recover"]["status"], "uncertain")
        self.assertAlmostEqual(ledger["held_usd"], ledger["calls"]["recover"]["reserved_usd"])
        self.assertAlmostEqual(ledger["spent_usd"], .000138)
        self.assertEqual(result["model"], client.STRONGER_MODEL)
        reused = client.json_call(**self.kwargs, call_id="recover", model=client.STRONGER_MODEL)
        self.assertTrue(reused["cache_hit"])
        self.assertEqual(self.network.call_count, 2)

    def test_http_503_keeps_reservation_without_retry(self):
        self.network.side_effect = urllib.error.HTTPError(
            shared.ENDPOINT, 503, "offline failure", {}, io.BytesIO(b'{"error":"offline"}'))
        with self.assertRaises(client.APIRequestError):
            client.json_call(**self.kwargs, call_id="server", model=client.STRONGER_MODEL)
        self.assertEqual(self.network.call_count, 1)
        ledger = self.ledger()
        self.assertEqual(set(ledger["calls"]), {"server"})
        self.assertEqual(ledger["calls"]["server"]["status"], "uncertain")
        self.assertGreater(ledger["held_usd"], 0)

    def test_refusal_billed_once_and_never_retried(self):
        self.network.side_effect = None
        self.network.return_value = FakeResponse(client.STRONGER_MODEL, refusal="offline refusal")
        with self.assertRaises(client.APIOutputError):
            client.json_call(**self.kwargs, call_id="refusal", model=client.STRONGER_MODEL)
        self.assertEqual(self.network.call_count, 1)
        self.assertAlmostEqual(self.ledger()["spent_usd"], .000138)
        self.assertEqual(self.ledger()["held_usd"], 0)

    def test_existing_baseline_spend_counts_against_new_model_cap(self):
        shared.json_call(**self.kwargs, call_id="baseline")
        with patch.object(shared, "HARD_CAP_USD", .000024):
            with self.assertRaises(client.BudgetExceeded):
                client.json_call(**self.kwargs, call_id="blocked", model=client.STRONGER_MODEL)
        self.assertEqual(self.network.call_count, 1)
        self.assertEqual(set(self.ledger()["calls"]), {"baseline"})


if __name__ == "__main__":
    unittest.main()
