"""Small, resumable OpenAI client with a conservative, project-wide USD cap.

Only this module sends paid requests. No automatic retries are performed.
An ambiguous failure retains its reservation; investigate it before spending more.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
MODEL = "gpt-4o-mini-2024-07-18"
ENDPOINT = "https://api.openai.com/v1/chat/completions"
HARD_CAP_USD = 6.50
PRICES_PER_MILLION = {"input": 0.15, "cached_input": 0.075, "output": 0.60}


class BudgetExceeded(RuntimeError):
    pass


class APIRequestError(RuntimeError):
    pass


class APIOutputError(APIRequestError):
    """A billed generation was refused, truncated, or not usable JSON."""
    pass


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def _locked():
    RESULTS.mkdir(parents=True, exist_ok=True)
    with (RESULTS / ".api.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _read_ledger():
    path = RESULTS / "cost_ledger.json"
    if path.exists():
        ledger = json.loads(path.read_text())
        if ledger.get("version") != 1 or not isinstance(ledger.get("calls"), dict):
            raise RuntimeError("Invalid cost ledger; refusing to send requests.")
        return ledger
    return {"version": 1, "hard_cap_usd": HARD_CAP_USD,
            "pricing_per_million": PRICES_PER_MILLION, "calls": {}}


def _save_ledger(ledger):
    entries = list(ledger["calls"].values())
    ledger["hard_cap_usd"] = HARD_CAP_USD
    ledger["spent_usd"] = round(sum(e.get("actual_cost_usd", 0) for e in entries), 10)
    ledger["held_usd"] = round(sum(e["reserved_usd"] for e in entries
                                   if e["status"] in {"reserved", "uncertain"}), 10)
    ledger["committed_usd"] = round(ledger["spent_usd"] + ledger["held_usd"], 10)
    ledger["remaining_usd"] = round(HARD_CAP_USD - ledger["committed_usd"], 10)
    ledger["updated_at_utc"] = _now()
    _atomic_json(RESULTS / "cost_ledger.json", ledger)


def budget_summary():
    with _locked():
        ledger = _read_ledger()
        _save_ledger(ledger)
        return {key: ledger[key] for key in
                ["hard_cap_usd", "spent_usd", "held_usd", "committed_usd", "remaining_usd"]}


def _key():
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env", override=False)
    except ImportError:
        env_path = ROOT / ".env"
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                match = re.match(r"^\s*(?:export\s+)?OPENAI_API_KEY\s*=\s*(.*?)\s*$", line)
                if match:
                    value = match.group(1)
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                        value = value[1:-1]
                    else:
                        value = value.split(" #", 1)[0].strip()
                    os.environ.setdefault("OPENAI_API_KEY", value)
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        raise APIRequestError("OPENAI_API_KEY is missing; configure the project .env file.")
    return key


def _redact(text, key):
    text = text.replace(key, "[REDACTED]")
    return re.sub(r"sk-[A-Za-z0-9_.*-]+", "[REDACTED_KEY]", text)


def _cost(usage):
    prompt = int(usage["prompt_tokens"])
    completion = int(usage["completion_tokens"])
    cached = int((usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0))
    if not (0 <= cached <= prompt and completion >= 0):
        raise ValueError("Invalid API token accounting")
    return round(((prompt - cached) * PRICES_PER_MILLION["input"]
                  + cached * PRICES_PER_MILLION["cached_input"]
                  + completion * PRICES_PER_MILLION["output"]) / 1_000_000, 10)


def json_call(messages, schema, call_id, role, max_tokens=1000, seed=None):
    """Return parsed output, complete usage metadata, and incremental USD cost.

    IDs are unique across the whole project. Reusing an ID returns the stored
    response at zero additional cost, or fails if its request differs. Cache hits
    retain ``original_cost_usd`` while ``cost_usd`` is zero. Calls with unresolved
    billing or failures are never resent automatically under the same ID.
    """
    if not isinstance(call_id, str) or not call_id.strip():
        raise ValueError("call_id must be a nonempty unique string")
    if not isinstance(role, str) or not role:
        raise ValueError("role must be a nonempty string")
    if type(max_tokens) is not int or not 1 <= max_tokens <= 16384:
        raise ValueError("max_tokens must be an integer in [1, 16384]")
    payload = {"model": MODEL, "messages": messages, "temperature": 0.3,
               "max_tokens": max_tokens,
               "response_format": {"type": "json_schema", "json_schema": {
                   "name": "experiment_output", "strict": True, "schema": schema}}}
    if seed is not None:
        if type(seed) is not int:
            raise ValueError("seed must be an integer")
        payload["seed"] = seed
    encoded = _canonical(payload).encode("utf-8")
    identity = hashlib.sha256(_canonical({"request": payload, "role": role}).encode()).hexdigest()
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", call_id)[:90]
    record_path = RESULTS / "api" / (safe_id + "-" + hashlib.sha256(call_id.encode()).hexdigest()[:12] + ".json")

    # The whole transaction is locked, preventing duplicate sends and overspending
    # from concurrent experiment processes. A crash leaves the reservation intact.
    with _locked():
        ledger = _read_ledger()
        previous = ledger["calls"].get(call_id)
        if previous:
            if previous.get("request_sha256") != identity:
                raise ValueError("call_id collision: the existing request differs")
            if previous["status"] != "success" or not record_path.exists():
                raise APIRequestError("This call ID already failed or has unresolved billing; no automatic retry.")
            record = json.loads(record_path.read_text())
            if record.get("request_sha256") != identity:
                raise ValueError("Stored request hash differs from ledger")
            result = dict(record["result"])
            if result.get("output_error"):
                raise APIOutputError(result["output_error"])
            result.update(cache_hit=True, cost_usd=0.0)
            return result

        key = _key()
        # Token count is conservatively bounded by encoded bytes plus framing
        # allowance; ordinary text tokens cannot exceed one token per byte.
        input_upper_tokens = len(encoded) + 2048
        reserve = round((input_upper_tokens * PRICES_PER_MILLION["input"]
                         + max_tokens * PRICES_PER_MILLION["output"]) / 1_000_000, 10)
        _save_ledger(ledger)
        if ledger["committed_usd"] + reserve > HARD_CAP_USD:
            raise BudgetExceeded("Project API budget would exceed $6.50; request was not sent.")
        entry = {"role": role, "model": MODEL, "request_sha256": identity,
                 "status": "reserved", "reserved_usd": reserve,
                 "input_upper_tokens": input_upper_tokens, "max_output_tokens": max_tokens,
                 "created_at_utc": _now(), "record": str(record_path.relative_to(ROOT))}
        ledger["calls"][call_id] = entry
        _save_ledger(ledger)
        record = {"call_id": call_id, "role": role, "request_sha256": identity,
                  "request": payload, "created_at_utc": entry["created_at_utc"]}
        _atomic_json(record_path, record)
        headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json"}
        if os.getenv("OPENAI_PROJECT_ID"):
            headers["OpenAI-Project"] = os.environ["OPENAI_PROJECT_ID"]
        request = urllib.request.Request(ENDPOINT, data=encoded, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                request_id = response.headers.get("x-request-id")
                body = response.read().decode("utf-8")
            response_json = json.loads(body)
            actual_cost = _cost(response_json["usage"])
        except urllib.error.HTTPError as error:
            # These rejected requests did not start generation. Server failures
            # are ambiguous and retain the reservation instead.
            rejected = error.code in {400, 401, 403, 404, 413, 422, 429}
            entry["status"] = "rejected" if rejected else "uncertain"
            entry["http_status"] = error.code
            record["error"] = {"http_status": error.code,
                               "body": _redact(error.read().decode("utf-8", errors="replace"), key),
                               "request_id": error.headers.get("x-request-id")}
            _atomic_json(record_path, record)
            _save_ledger(ledger)
            raise APIRequestError(f"OpenAI HTTP {error.code}; recorded without retry. "
                                  + ("No cost charged." if rejected else "Budget reservation retained.")) from None
        except Exception as error:
            entry["status"] = "uncertain"
            record["error"] = {"type": type(error).__name__, "message": _redact(str(error), key)}
            _atomic_json(record_path, record)
            _save_ledger(ledger)
            raise APIRequestError("API result or billing is uncertain; reservation retained, no retry.") from None

        record["response"] = response_json
        choice = (response_json.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        output_error = None
        try:
            if choice.get("finish_reason") != "stop" or message.get("refusal"):
                raise ValueError("Model response was refused or incomplete")
            output = json.loads(message["content"])
            if not isinstance(output, dict):
                raise ValueError("Expected a JSON object")
        except (KeyError, TypeError, ValueError) as error:
            output = None
            output_error = str(error)
        result = {"output": output, "usage": response_json["usage"],
                  "model": response_json.get("model", MODEL),
                  "fingerprint": response_json.get("system_fingerprint"),
                  "request_id": request_id, "response_id": response_json.get("id"),
                  "cache_hit": False, "cost_usd": actual_cost,
                  "original_cost_usd": actual_cost,
                  "record_path": str(record_path.relative_to(ROOT))}
        if output_error:
            result["output_error"] = output_error
        record["result"] = result
        entry.update(status="success", actual_cost_usd=actual_cost, finished_at_utc=_now())
        _atomic_json(record_path, record)
        _save_ledger(ledger)
        if actual_cost > reserve:
            raise APIRequestError("Usage exceeded the conservative reservation; inspect pricing before continuing.")
        if output_error:
            raise APIOutputError("API call billed, but JSON output unusable: " + output_error)
        return result
