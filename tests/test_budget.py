"""Offline budget/recovery checks using temporary ledgers and a blocked network.

Every test replaces both client ROOT/RESULTS and recovery's root lookup. No
test reads credentials, opens the live ledger, or sends a network request.
"""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from scripts import llm_client as client
from scripts import request_recovery as recovery


class FakeResponse:
    def __init__(self, *, refusal=None):
        self.headers = {"x-request-id": "offline-request"}
        self.body = {
            "id": "offline-response", "model": client.MODEL,
            "system_fingerprint": "offline-fingerprint",
            "usage": {"prompt_tokens": 100, "completion_tokens": 20,
                      "prompt_tokens_details": {"cached_tokens": 40}},
            "choices": [{"finish_reason": "stop", "message": {
                "content": None if refusal else '{"ok": true}',
                "refusal": refusal,
            }}],
        }

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.body).encode()


class BudgetTests(unittest.TestCase):
    EXPECTED_COST = 0.000024  # 60 input + 40 cached input + 20 output tokens.

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="a2-budget-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        patches = [
            patch.object(client, "ROOT", self.root),
            patch.object(client, "RESULTS", self.results),
            patch.object(client, "_key", return_value="offline-test-credential"),
            patch.object(recovery, "__file__", str(self.root / "scripts/request_recovery.py")),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        network_patch = patch.object(
            client.urllib.request, "urlopen",
            side_effect=AssertionError("Unexpected outbound request in offline test"),
        )
        self.network = network_patch.start()
        self.addCleanup(network_patch.stop)
        self.network.side_effect = None
        self.network.return_value = FakeResponse()

    def call(self, *, call_id="offline-call", messages=None, recover=False):
        function = recovery.json_call if recover else client.json_call
        return function(
            messages=messages or [{"role": "user", "content": "Return JSON."}],
            schema={"type": "object", "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"], "additionalProperties": False},
            call_id=call_id, role="offline-test", max_tokens=100, seed=17,
        )

    def ledger(self):
        return json.loads((self.results / "cost_ledger.json").read_text())

    def test_exact_cache_hit_never_double_bills(self):
        first = self.call()
        second = self.call()
        self.assertEqual(self.network.call_count, 1)
        self.assertEqual(first["output"], {"ok": True})
        self.assertFalse(first["cache_hit"])
        self.assertTrue(second["cache_hit"])
        self.assertEqual(second["cost_usd"], 0)
        self.assertAlmostEqual(second["original_cost_usd"], self.EXPECTED_COST)
        ledger = self.ledger()
        self.assertEqual(len(ledger["calls"]), 1)
        self.assertAlmostEqual(ledger["spent_usd"], self.EXPECTED_COST)
        self.assertEqual(ledger["held_usd"], 0)

    def test_call_id_collision_refuses_different_request(self):
        self.call()
        before = self.ledger()
        with self.assertRaisesRegex(ValueError, "collision"):
            self.call(messages=[{"role": "user", "content": "Different request."}])
        self.assertEqual(self.network.call_count, 1)
        self.assertEqual(self.ledger(), before)

    def test_refusal_records_charge_and_never_retries(self):
        self.network.return_value = FakeResponse(refusal="Offline fixture refusal")
        for _ in range(2):
            with self.assertRaises(client.APIOutputError):
                self.call(recover=True)
        self.assertEqual(self.network.call_count, 1)
        ledger = self.ledger()
        self.assertEqual(set(ledger["calls"]), {"offline-call"})
        self.assertEqual(ledger["calls"]["offline-call"]["status"], "success")
        self.assertAlmostEqual(ledger["spent_usd"], self.EXPECTED_COST)
        self.assertEqual(ledger["held_usd"], 0)
        record = json.loads((self.root / ledger["calls"]["offline-call"]["record"]).read_text())
        self.assertIsNone(record["result"]["output"])
        self.assertIn("output_error", record["result"])

    def test_transport_recovery_holds_original_and_bills_distinct_retry(self):
        self.network.side_effect = [TimeoutError("Offline transport interruption"), FakeResponse()]
        first = self.call(recover=True)
        self.assertFalse(first["cache_hit"])
        ledger = self.ledger()
        self.assertEqual(set(ledger["calls"]), {"offline-call", "offline-call_transport_retry1"})
        original = ledger["calls"]["offline-call"]
        retried = ledger["calls"]["offline-call_transport_retry1"]
        self.assertEqual(original["status"], "uncertain")
        self.assertEqual(retried["status"], "success")
        self.assertAlmostEqual(ledger["held_usd"], original["reserved_usd"])
        self.assertAlmostEqual(ledger["spent_usd"], self.EXPECTED_COST)
        self.assertAlmostEqual(ledger["committed_usd"], original["reserved_usd"] + self.EXPECTED_COST)
        resumed = self.call(recover=True)
        self.assertTrue(resumed["cache_hit"])
        self.assertEqual(resumed["cost_usd"], 0)
        self.assertEqual(self.network.call_count, 2)
        self.assertEqual(self.ledger(), ledger)

    def test_second_transport_failure_does_not_create_third_attempt(self):
        self.network.side_effect = TimeoutError("Offline interruption")
        for _ in range(2):
            with self.assertRaises(client.APIRequestError):
                self.call(recover=True)
        ledger = self.ledger()
        self.assertEqual(self.network.call_count, 2)
        self.assertEqual(len(ledger["calls"]), 2)
        self.assertTrue(all(entry["status"] == "uncertain" for entry in ledger["calls"].values()))
        self.assertEqual(ledger["spent_usd"], 0)
        self.assertAlmostEqual(ledger["held_usd"], sum(entry["reserved_usd"] for entry in ledger["calls"].values()))

    def test_budget_cap_prevents_outbound_request(self):
        with patch.object(client, "HARD_CAP_USD", 0):
            with self.assertRaises(client.BudgetExceeded):
                self.call(recover=True)
        self.network.assert_not_called()
        self.assertEqual(self.ledger()["calls"], {})

    def test_uncertain_reservation_counts_against_retry_cap(self):
        self.network.side_effect = TimeoutError("Offline interruption")
        with self.assertRaises(client.APIRequestError):
            self.call()
        held = self.ledger()["held_usd"]
        with patch.object(client, "HARD_CAP_USD", held * 1.5):
            with self.assertRaises(client.BudgetExceeded):
                self.call(recover=True)
        self.assertEqual(self.network.call_count, 1)
        self.assertEqual(set(self.ledger()["calls"]), {"offline-call"})
        self.assertEqual(self.ledger()["held_usd"], held)

    def test_http_rejection_releases_reservation_without_retry(self):
        self.network.side_effect = urllib.error.HTTPError(
            client.ENDPOINT, 429, "Offline rate limit", {}, io.BytesIO(b'{"error":"offline"}')
        )
        with self.assertRaises(client.APIRequestError):
            self.call(recover=True)
        self.assertEqual(self.network.call_count, 1)
        ledger = self.ledger()
        self.assertEqual(ledger["calls"]["offline-call"]["status"], "rejected")
        self.assertEqual(ledger["spent_usd"], 0)
        self.assertEqual(ledger["held_usd"], 0)


if __name__ == "__main__":
    unittest.main()
