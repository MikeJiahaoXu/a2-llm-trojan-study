"""Model-specific requests sharing the frozen client's cumulative budget ledger.

The baseline client is unchanged. Per-call prices are stored in each new ledger
entry. GPT-5.4-mini uses no reasoning and omits the seed parameter because its
snapshot-specific seed support is not established by the API documentation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request

from scripts import llm_client as shared
from scripts.llm_client import APIOutputError, APIRequestError, BudgetExceeded

BASELINE_MODEL = "gpt-4o-mini-2024-07-18"
STRONGER_MODEL = "gpt-5.4-mini-2026-03-17"
MODEL_PRICES = {
    BASELINE_MODEL: {"input": 0.15, "cached_input": 0.075, "output": 0.60},
    STRONGER_MODEL: {"input": 0.75, "cached_input": 0.075, "output": 4.50},
}
PRICING_SOURCES = {
    BASELINE_MODEL: "https://developers.openai.com/api/docs/models/gpt-4o-mini",
    STRONGER_MODEL: "https://developers.openai.com/api/docs/models/gpt-5.4-mini",
}


def _cost(usage, prices):
    prompt = int(usage["prompt_tokens"])
    completion = int(usage["completion_tokens"])
    cached = int((usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0))
    if not (0 <= cached <= prompt and completion >= 0):
        raise ValueError("Invalid API token accounting")
    # completion_tokens includes any reasoning tokens; never subtract them.
    return round(((prompt-cached)*prices["input"] + cached*prices["cached_input"]
                  + completion*prices["output"]) / 1_000_000, 10)


def _single_call(messages, schema, call_id, role, max_tokens=1000, seed=None,
                 model=BASELINE_MODEL):
    if model not in MODEL_PRICES:
        raise ValueError("Unsupported model: use an explicitly priced snapshot")
    if not isinstance(call_id, str) or not call_id.strip():
        raise ValueError("call_id must be a nonempty unique string")
    if not isinstance(role, str) or not role:
        raise ValueError("role must be a nonempty string")
    if type(max_tokens) is not int or not 1 <= max_tokens <= 16384:
        raise ValueError("max_tokens must be an integer in [1, 16384]")
    if seed is not None and type(seed) is not int:
        raise ValueError("seed must be an integer")
    prices = dict(MODEL_PRICES[model])
    payload = {"model": model, "messages": messages, "temperature": 0.3,
               "response_format": {"type": "json_schema", "json_schema": {
                   "name": "experiment_output", "strict": True, "schema": schema}}}
    if model == STRONGER_MODEL:
        payload.update(max_completion_tokens=max_tokens, reasoning_effort="none")
    else:
        payload["max_tokens"] = max_tokens
        if seed is not None:
            payload["seed"] = seed
    encoded = shared._canonical(payload).encode("utf-8")
    identity_data = {"request": payload, "role": role}
    if model == STRONGER_MODEL:
        identity_data["requested_seed"] = seed
    identity = hashlib.sha256(shared._canonical(identity_data).encode()).hexdigest()
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", call_id)[:90]
    record_path = shared.RESULTS / "api" / (
        safe_id + "-" + hashlib.sha256(call_id.encode()).hexdigest()[:12] + ".json")

    with shared._locked():
        ledger = shared._read_ledger()
        previous = ledger["calls"].get(call_id)
        if previous:
            if previous.get("request_sha256") != identity:
                raise ValueError("call_id collision: the existing request differs")
            if previous["status"] != "success" or not record_path.exists():
                raise APIRequestError("Existing call failed or has unresolved billing; not resent under this ID.")
            record = json.loads(record_path.read_text())
            if record.get("request_sha256") != identity:
                raise ValueError("Stored request hash differs from ledger")
            result = dict(record["result"])
            if result.get("output_error"):
                raise APIOutputError(result["output_error"])
            result.update(cache_hit=True, cost_usd=0.0)
            return result

        key = shared._key()
        input_upper_tokens = len(encoded) + 2048
        reserve = round((input_upper_tokens*prices["input"] + max_tokens*prices["output"])
                        / 1_000_000, 10)
        shared._save_ledger(ledger)
        if ledger["committed_usd"] + reserve > shared.HARD_CAP_USD:
            raise BudgetExceeded("Cumulative project budget would exceed its hard cap; request not sent.")
        entry = {"role": role, "model": model, "request_sha256": identity,
                 "status": "reserved", "reserved_usd": reserve,
                 "input_upper_tokens": input_upper_tokens, "max_output_tokens": max_tokens,
                 "pricing_per_million": prices, "pricing_source": PRICING_SOURCES[model],
                 "requested_seed": seed, "seed_sent": "seed" in payload,
                 "reasoning_effort": payload.get("reasoning_effort"),
                 "created_at_utc": shared._now(),
                 "record": str(record_path.relative_to(shared.ROOT))}
        ledger["calls"][call_id] = entry
        shared._save_ledger(ledger)
        record = {"call_id": call_id, "role": role, "request_sha256": identity,
                  "request": payload, "created_at_utc": entry["created_at_utc"],
                  "pricing_per_million": prices, "requested_seed": seed,
                  "seed_sent": entry["seed_sent"], "client": "model_client_v1"}
        shared._atomic_json(record_path, record)
        headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json"}
        if os.getenv("OPENAI_PROJECT_ID"):
            headers["OpenAI-Project"] = os.environ["OPENAI_PROJECT_ID"]
        request = urllib.request.Request(shared.ENDPOINT, data=encoded, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                request_id = response.headers.get("x-request-id")
                response_json = json.loads(response.read().decode("utf-8"))
            actual_cost = _cost(response_json["usage"], prices)
        except urllib.error.HTTPError as error:
            rejected = error.code in {400, 401, 403, 404, 413, 422, 429}
            entry.update(status="rejected" if rejected else "uncertain", http_status=error.code)
            record["error"] = {"http_status": error.code,
                               "body": shared._redact(error.read().decode("utf-8", errors="replace"), key),
                               "request_id": error.headers.get("x-request-id")}
            shared._atomic_json(record_path, record)
            shared._save_ledger(ledger)
            raise APIRequestError(f"OpenAI HTTP {error.code}; no HTTP retry. "
                                  + ("Reservation released." if rejected else "Reservation retained.")) from None
        except Exception as error:
            entry["status"] = "uncertain"
            record["error"] = {"type": type(error).__name__, "message": shared._redact(str(error), key)}
            shared._atomic_json(record_path, record)
            shared._save_ledger(ledger)
            raise APIRequestError("API result or billing uncertain; original reservation retained.") from None

        record["response"] = response_json
        choice = (response_json.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        output_error = None
        try:
            if choice.get("finish_reason") != "stop" or message.get("refusal"):
                raise ValueError("Model response refused or incomplete")
            output = json.loads(message["content"])
            if not isinstance(output, dict):
                raise ValueError("Expected JSON object")
        except (KeyError, TypeError, ValueError) as error:
            output, output_error = None, str(error)
        result = {"output": output, "usage": response_json["usage"],
                  "model": response_json.get("model", model),
                  "fingerprint": response_json.get("system_fingerprint"),
                  "request_id": request_id, "response_id": response_json.get("id"),
                  "cache_hit": False, "cost_usd": actual_cost, "original_cost_usd": actual_cost,
                  "record_path": str(record_path.relative_to(shared.ROOT)),
                  "pricing_per_million": prices, "requested_seed": seed,
                  "seed_sent": entry["seed_sent"], "reasoning_effort": payload.get("reasoning_effort")}
        if output_error:
            result["output_error"] = output_error
        record["result"] = result
        entry.update(status="success", actual_cost_usd=actual_cost, finished_at_utc=shared._now())
        shared._atomic_json(record_path, record)
        shared._save_ledger(ledger)
        if actual_cost > reserve:
            raise APIRequestError("Usage exceeded reservation; inspect pricing before continuing.")
        if output_error:
            raise APIOutputError("Billed API output unusable: " + output_error)
        return result


def json_call(messages, schema, call_id, role, max_tokens=1000, seed=None,
              model=BASELINE_MODEL):
    """One request plus at most one separately budgeted transport recovery.

HTTP responses and refusals never retry. A retry retains the first reservation,
uses a fixed distinct audit ID, and is cached on resume. Changing models under an
existing call ID is rejected before any network request.
    """
    kwargs = dict(messages=messages, schema=schema, call_id=call_id, role=role,
                  max_tokens=max_tokens, seed=seed, model=model)
    try:
        return _single_call(**kwargs)
    except APIOutputError:
        raise
    except APIRequestError:
        with shared._locked():
            entry = shared._read_ledger()["calls"].get(call_id, {})
        if entry.get("status") != "uncertain" or "http_status" in entry:
            raise
        kwargs["call_id"] = call_id + "_transport_retry1"
        print("Transport recovery: " + kwargs["call_id"] + " (original reservation retained)", flush=True)
        return _single_call(**kwargs)
