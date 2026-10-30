#!/usr/bin/env python3
"""One tiny, idempotent connectivity check; included in the project cost ledger."""
import json

from llm_client import APIRequestError, BudgetExceeded, budget_summary, json_call


def main():
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}},
              "required": ["ok"], "additionalProperties": False}
    try:
        result = json_call(
            [{"role": "user", "content": "Connectivity test. Return a JSON object with ok set to true."}],
            schema, call_id="api-connectivity-v1", role="smoke", max_tokens=32, seed=1)
    except (APIRequestError, BudgetExceeded) as error:
        print(str(error))
        return 1
    print(json.dumps({"ok": result["output"]["ok"], "model": result["model"],
                      "usage": result["usage"], "cost_usd": result["cost_usd"],
                      "cache_hit": result["cache_hit"], "budget": budget_summary()}, indent=2))
    return 0 if result["output"]["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
