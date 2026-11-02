"""Role-specific OpenAI calls with exact-call resumption and cumulative caps.

Uses the original client's lock, ledger, credential loader and atomic writer.
Content-based detector caching belongs to the experiment runner. This module
only resumes an identical call identifier. Importing it makes no paid requests.
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

MODEL = "gpt-4o-mini-2024-07-18"
ROLES = {"stop_attacker": {"temperature": 0.3, "max_tokens": 500},
         "stop_detector": {"temperature": 0.0, "max_tokens": 1600}}
CALL_PREFIX = "proposal_stop_v5_"
STUDY_CAP_USD = 3.00
PRICES = {"input": 0.15, "cached_input": 0.075, "output": 0.60}
PRICING_SOURCE = "https://developers.openai.com/api/docs/models/gpt-4o-mini"


def payload_for(messages, schema, role, seed, max_tokens=None):
    if role not in ROLES:
        raise ValueError("Role must be stop_attacker or stop_detector")
    settings = ROLES[role]
    if type(seed) is not int or not 0 <= seed <= 2147483647:
        raise ValueError("A nonnegative, bounded integer seed is required")
    if max_tokens is None:
        max_tokens = settings["max_tokens"]
    if type(max_tokens) is not int or max_tokens != settings["max_tokens"]:
        raise ValueError("Output allowance must match the frozen role setting")
    return {"model": MODEL, "messages": messages, "temperature": settings["temperature"],
            "max_tokens": max_tokens, "seed": seed,
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "experiment_output", "strict": True, "schema": schema}}}


def request_identity(payload, role):
    if role not in ROLES:
        raise ValueError("Unknown study role")
    return hashlib.sha256(shared._canonical({"request": payload, "role": role}).encode()).hexdigest()


def reservation(payload):
    upper = len(shared._canonical(payload).encode("utf-8")) + 2048
    return upper, round((upper * PRICES["input"] + payload["max_tokens"] * PRICES["output"])
                        / 1_000_000, 10)


def committed(entries):
    return round(sum(e.get("actual_cost_usd", 0)
                     + (e.get("reserved_usd", 0) if e["status"] in {"reserved", "uncertain"} else 0)
                     for e in entries), 10)


def budget_state(ledger):
    # Historical v4 calls use the same role names. Their costs belong to the
    # project total, but never to this distinct v5 run's own spending limit.
    study = [entry for call_id, entry in ledger["calls"].items()
             if call_id.startswith(CALL_PREFIX)]
    return {"project_committed_usd": committed(ledger["calls"].values()),
            "study_committed_usd": committed(study),
            "project_cap_usd": shared.HARD_CAP_USD,
            "study_cap_usd": STUDY_CAP_USD}


def record_path(call_id):
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", call_id)[:90]
    return shared.RESULTS / "api" / (safe + "-" + hashlib.sha256(call_id.encode()).hexdigest()[:12] + ".json")


def _cost(usage):
    prompt, completion = int(usage["prompt_tokens"]), int(usage["completion_tokens"])
    cached = int((usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0))
    if not (0 <= cached <= prompt and completion >= 0):
        raise ValueError("Invalid API token accounting")
    return round(((prompt-cached)*PRICES["input"] + cached*PRICES["cached_input"]
                  + completion*PRICES["output"]) / 1_000_000, 10)


def _single_call(messages, schema, call_id, role, seed, max_tokens=None):
    if not isinstance(call_id, str) or not call_id.startswith(CALL_PREFIX):
        raise ValueError("Study calls must use their reserved experiment ID prefix")
    payload = payload_for(messages, schema, role, seed, max_tokens)
    identity = request_identity(payload, role)
    max_tokens = payload["max_tokens"]
    encoded = shared._canonical(payload).encode("utf-8")
    path = record_path(call_id)
    with shared._locked():
        ledger = shared._read_ledger()
        previous = ledger["calls"].get(call_id)
        if previous:
            if previous.get("request_sha256") != identity:
                raise ValueError("call_id collision: the existing request differs")
            if previous["status"] != "success" or not path.exists():
                raise APIRequestError("Existing call failed or has unresolved billing; not resent under this ID.")
            record = json.loads(path.read_text())
            if record.get("request_sha256") != identity or record.get("request") != payload:
                raise ValueError("Stored request differs from the frozen request")
            result = dict(record["result"])
            if result.get("output_error"):
                raise APIOutputError(result["output_error"])
            result.update(cache_hit=True, cost_usd=0.0)
            return result

        input_upper, reserve = reservation(payload)
        state = budget_state(ledger)
        if state["project_committed_usd"] + reserve > shared.HARD_CAP_USD:
            raise BudgetExceeded("Project cumulative hard cap would be exceeded; request not sent.")
        if state["study_committed_usd"] + reserve > STUDY_CAP_USD:
            raise BudgetExceeded("Study cumulative hard cap would be exceeded; request not sent.")
        key = shared._key()
        entry = {"role": role, "budget_scope": "proposal_stop_v5", "model": MODEL,
                 "request_sha256": identity, "status": "reserved", "reserved_usd": reserve,
                 "input_upper_tokens": input_upper, "max_output_tokens": max_tokens,
                 "pricing_per_million": PRICES, "pricing_source": PRICING_SOURCE,
                 "created_at_utc": shared._now(), "record": str(path.relative_to(shared.ROOT)),
                 "temperature": payload["temperature"], "requested_seed": seed, "seed_sent": True}
        ledger["calls"][call_id] = entry
        shared._save_ledger(ledger)
        record = {"call_id": call_id, "role": role, "request_sha256": identity,
                  "request": payload, "created_at_utc": entry["created_at_utc"],
                  "client": "stopstudy_v5_client_v1", "pricing_per_million": PRICES}
        shared._atomic_json(path, record)
        headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json"}
        if os.getenv("OPENAI_PROJECT_ID"):
            headers["OpenAI-Project"] = os.environ["OPENAI_PROJECT_ID"]
        request = urllib.request.Request(shared.ENDPOINT, data=encoded, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                request_id = response.headers.get("x-request-id")
                response_json = json.loads(response.read().decode("utf-8"))
            record["response"] = response_json
            cost = _cost(response_json["usage"])
        except urllib.error.HTTPError as error:
            rejected = error.code in {400, 401, 403, 404, 413, 422, 429}
            entry.update(status="rejected" if rejected else "uncertain", http_status=error.code)
            record["error"] = {"http_status": error.code,
                               "body": shared._redact(error.read().decode("utf-8", errors="replace"), key),
                               "request_id": error.headers.get("x-request-id")}
            shared._atomic_json(path, record)
            shared._save_ledger(ledger)
            raise APIRequestError(f"OpenAI HTTP {error.code}; no HTTP retry.") from None
        except Exception as error:
            entry["status"] = "uncertain"
            # A malformed response/accounting record is not a transport retry.
            entry["transport_failure"] = isinstance(error, (TimeoutError, ConnectionError,
                                                            urllib.error.URLError, OSError))
            record["error"] = {"type": type(error).__name__, "message": shared._redact(str(error), key)}
            shared._atomic_json(path, record)
            shared._save_ledger(ledger)
            raise APIRequestError("API result or billing uncertain; reservation retained.") from None

        record["response"] = response_json
        choice = (response_json.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        output_error = None
        try:
            if choice.get("finish_reason") != "stop" or message.get("refusal"):
                raise ValueError("Model response refused or incomplete")
            if response_json.get("model") != MODEL:
                raise ValueError("Unexpected returned model snapshot")
            output = json.loads(message["content"])
            if not isinstance(output, dict):
                raise ValueError("Expected JSON object")
        except (KeyError, TypeError, ValueError) as error:
            output, output_error = None, str(error)
        result = {"output": output, "usage": response_json["usage"],
                  "model": response_json.get("model"),
                  "fingerprint": response_json.get("system_fingerprint"),
                  "request_id": request_id, "response_id": response_json.get("id"),
                  "cache_hit": False, "cost_usd": cost, "original_cost_usd": cost,
                  "record_path": str(path.relative_to(shared.ROOT)),
                  "pricing_per_million": PRICES, "temperature": payload["temperature"],
                  "requested_seed": seed, "seed_sent": True}
        if output_error:
            result["output_error"] = output_error
        record["result"] = result
        entry.update(status="success", actual_cost_usd=cost, finished_at_utc=shared._now())
        shared._atomic_json(path, record)
        shared._save_ledger(ledger)
        if cost > reserve:
            raise APIRequestError("Usage exceeded reservation; inspect pricing before continuing.")
        if output_error:
            raise APIOutputError("Billed API output unusable: " + output_error)
        return result


def json_call(messages, schema, call_id, role, seed, max_tokens=None):
    """Fresh ID = fresh call; at most one separately reserved transport recovery."""
    kwargs = dict(messages=messages, schema=schema, call_id=call_id, role=role,
                  seed=seed, max_tokens=max_tokens)
    try:
        return _single_call(**kwargs)
    except APIOutputError:
        raise
    except APIRequestError:
        with shared._locked():
            entry = shared._read_ledger()["calls"].get(call_id, {})
        if (entry.get("status") != "uncertain" or "http_status" in entry
                or entry.get("transport_failure") is not True):
            raise
        kwargs["call_id"] = call_id + "_transport_retry1"
        return _single_call(**kwargs)
