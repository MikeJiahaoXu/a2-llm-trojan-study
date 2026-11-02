"""Independent, read-only-of-evidence audit of the fixed defender supplement.

python -m scripts.defense.verify --preflight  # after runner --prepare
python -m scripts.defense.verify             # after reviews and analysis finish

No API calls or new simulations. Audit outputs are separate from frozen evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import random
import re

import numpy as np

from scripts.detector.review import SCHEMA, SPECS
from scripts.sim import benchmark

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = "defense_comparison_v1"
OLD_RUNS = ("proposal_main_v3", "proposal_repeat_v3")
CONDITIONS = ("netlist_only", "normal_logs")
ROLE = "defense_reviewer"
SEPARATOR = "\nNORMAL-OPERATION MEASUREMENT SUMMARY:\n"
PRICES = {"input": .15, "cached_input": .075, "output": .60}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def text_sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_at(root, name):
    path = (root / name).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file(), "Missing/outside evidence file: " + name)
    return path


def hash_mapping(root, mapping, context):
    require(isinstance(mapping, dict), context + " hash mapping is invalid")
    for name, digest in mapping.items():
        require(sha(file_at(root, name)) == digest, context + " hash mismatch: " + name)


def independent_nodes(netlist):
    """Terminal extraction independent of the preparation module."""
    body = re.findall(r"(?ims)^\.subckt\s+dut\s+([^\n]+)\n(.*?)^\.ends(?:\s+dut)?\s*$", netlist)
    require(len(body) == 1, "Expected exactly one simple dut subcircuit")
    port_line, body_text = body[0]
    ports = {node.lower() for node in port_line.split()}
    statement_text = re.sub(r"\n\s*\+", " ", body_text)
    terminal_counts = {"M": 4, "S": 4, "E": 4, "G": 4, "J": 3,
                       "R": 2, "C": 2, "L": 2, "D": 2, "V": 2, "I": 2, "B": 2, "F": 2, "H": 2}
    nodes = set()
    for line in statement_text.splitlines():
        tokens = re.split(r"[;$]", line.strip())[0].split()
        if not tokens or tokens[0].startswith(("*", ".")):
            continue
        kind = tokens[0][0].upper()
        require(kind in terminal_counts, "Unsupported primitive: " + tokens[0])
        n = terminal_counts[kind]
        require(len(tokens) >= n + 2, "Incomplete primitive terminals")
        nodes.update(node.lower() for node in tokens[1:n + 1])
    return sorted(nodes - ports - {"0"})


def compare_value(actual, expected, context):
    if isinstance(expected, dict):
        require(isinstance(actual, dict) and set(actual) == set(expected), context + " fields differ")
        for key in expected:
            compare_value(actual[key], expected[key], context + "/" + key)
    elif isinstance(expected, list):
        require(isinstance(actual, list) and len(actual) == len(expected), context + " list differs")
        for index, value in enumerate(expected):
            compare_value(actual[index], value, context + f"/{index}")
    elif isinstance(expected, (int, float)) and not isinstance(expected, bool):
        require(type(actual) in (int, float) and math.isfinite(actual)
                and math.isclose(actual, expected, rel_tol=6e-7, abs_tol=1e-12), context + " numeric value differs")
    else:
        require(actual == expected, context + " value differs")


def independent_summary(circuit, data, external, nodes):
    require(data.shape[1] == 2 + len(external) + len(nodes) and np.isfinite(data).all(), "Trace columns/values differ")
    require(np.all(np.diff(data[:, 0]) >= 0), "Trace time is not ordered")
    if circuit == "opamp":
        start_us, stop_us, step_ns = 20., 200., 100.
        points = np.arange(20., 201., 20.)
        stimulus = "3.3 V supply; unity-follower connection; input 1.65 V + 0.05 V sin(2*pi*10 kHz*t); duration 200 us."
    else:
        start_us, stop_us, step_ns = 1., 360., 10.
        points = np.arange(30., 331., 20.)
        stimulus = "3.3 V supply; inputs enumerate integer 0..15 with a as the least significant bit, one vector every 20 us from t=20 us; 100 ps edges; all inputs reset to 0 at 340 us; duration 360 us."
    grid = np.arange(int(start_us * 1000), int(stop_us * 1000) + 1, int(step_ns)) * 1e-9
    require(data[0, 0] <= grid[0] and data[-1, 0] >= grid[-1] - 1e-14, "Insufficient trace duration")
    sampled = np.column_stack([np.interp(grid, data[:, 0], data[:, k]) for k in range(1, data.shape[1])])

    def statistics(values):
        return {"min": float(values.min()), "max": float(values.max()), "mean": float(values.sum() / len(values))}

    result = {
        "schema": "normal_operation_v1", "stimulus": stimulus,
        "statistics_sampling": {"method": "linear interpolation onto a uniform time grid; arithmetic statistics on grid values",
                                "start_us": start_us, "stop_us": stop_us, "step_ns": step_ns, "points": len(grid)},
        "external_voltage_V": {name: statistics(sampled[:, k]) for k, name in enumerate(external)},
        "internal_voltage_V": {name: statistics(sampled[:, len(external) + k]) for k, name in enumerate(nodes)},
        "supply_current_A": {"reference": "i(VDD); positive current enters the voltage source positive terminal", **statistics(sampled[:, -1])},
        "normal_samples": {"columns": ["time_us", *[name + "_V" for name in external]],
                           "rows": [[float(t), *[float(np.interp(t * 1e-6, data[:, 0], data[:, k + 1]))
                                                for k in range(len(external))]] for t in points]},
    }
    if circuit == "opamp":
        delta = sampled[:, external.index("out")] - sampled[:, external.index("inp")]
        result["follower_error_V"] = {"definition": "output minus input on the uniform grid", "mean": float(delta.mean()),
                                       "max_abs": float(abs(delta).max()), "rmse": float(np.sqrt(np.dot(delta, delta) / len(delta)))}
    return result


def audit_corpus(root, corpus):
    hash_mapping(root, corpus["source_sha256"], "Corpus source")
    expected = {}
    input_names = set()
    original_hash_checks = 0
    for run_id in OLD_RUNS:
        manifest_name = f"results/{run_id}/manifest.json"
        manifest = read(root / manifest_name)
        hash_mapping(root, manifest["source_hashes"], "Original frozen source")
        for name, digest in manifest["source_hashes"].items():
            require(sha(root / "results" / run_id / "source_snapshot" / name) == digest, "Original snapshot changed")
            original_hash_checks += 1
        input_names.add(manifest_name)
        for kind, filename in (("candidate", "attempts.json"), ("control", "controls.json")):
            input_name = f"results/{run_id}/{filename}"
            input_names.add(input_name)
            for row in read(root / input_name):
                digest = row["netlist_sha256"]
                input_names.add(row["netlist_path"])
                require(sha(root / row["netlist_path"]) == digest, "Original DUT changed")
                if kind == "candidate":
                    require(row["simulation"]["valid"] is True, "Observed DUT lacks valid prior electrical evidence")
                    label = "trojan"
                    member = {"kind": kind, "run_id": run_id, **{k: row[k] for k in ("candidate_id", "feedback", "trajectory", "round")}}
                else:
                    label = "clean" if row["label"] == "clean" else "trojan"
                    require(label == "clean" or row["validation"]["valid"] is True, "Positive control validity differs")
                    member = {"kind": kind, "run_id": run_id, "control_label": row["label"],
                              "repeat": row["repeat"], "call_id": row["call_id"]}
                if digest not in expected:
                    expected[digest] = {"circuit": row["circuit"], "label": label, "memberships": []}
                require(expected[digest]["circuit"] == row["circuit"] and expected[digest]["label"] == label,
                        "Conflicting DUT label/circuit")
                expected[digest]["memberships"].append(member)
    require(input_names <= set(corpus["source_sha256"]), "Corpus provenance omits original input files")
    cases = corpus["cases"]
    require(len(cases) == len(expected) == 33 and {c["netlist_sha256"] for c in cases} == set(expected), "Corpus coverage differs")
    require(len({c["case_id"] for c in cases}) == 33, "Duplicate case identifiers")
    case_checks = []
    for case in cases:
        case_id, digest, circuit = case["case_id"], case["netlist_sha256"], case["circuit"]
        require(case_id == digest[:16], "Case identifier differs from SHA prefix")
        prior = expected[digest]
        require(case["circuit"] == prior["circuit"] and case["label"] == prior["label"]
                and sorted(map(canonical, case["memberships"])) == sorted(map(canonical, prior["memberships"])), "Corpus membership differs")
        netpath = file_at(root, case["netlist_path"])
        require(sha(netpath) == digest and netpath.read_bytes() == file_at(root, case["original_netlist_path"]).read_bytes(), "Corpus DUT bytes changed")
        netlist = netpath.read_bytes().decode("utf-8")
        simulation = case["normal_simulation"]
        required_artifacts = {case["netlist_path"], *[simulation[key] for key in ("deck_path", "log_path", "trace_path", "summary_path")]}
        require(set(simulation["sha256"]) == required_artifacts, "Normal simulation hash coverage differs")
        hash_mapping(root, simulation["sha256"], "Normal simulation")
        nodes = independent_nodes(netlist)
        external = ["inp", "out"] if circuit == "opamp" else ["a", "b", "c", "d", "out"]
        require(nodes == simulation["probe_nodes"] and external == simulation["external_nodes"], "Generic probe list differs")
        vectors = [f"v({n})" for n in external] + [f"v(x1.{n})" for n in nodes] + ["i(vdd)"]
        normal = (benchmark._op_normal if circuit == "opamp" else benchmark._and_normal)(netlist, "normal")
        deck = file_at(root, simulation["deck_path"]).read_text()
        original_measurement = re.findall(r"(?m)^wrdata normal\.tsv .*$", normal)
        current_measurement = re.findall(r"(?m)^wrdata normal\.tsv .*$", deck)
        require(len(original_measurement) == len(current_measurement) == 1, "Ambiguous measurement command")
        require(current_measurement[0] == "wrdata normal.tsv " + " ".join(vectors), "Saved measurement order differs")
        require(deck.replace(current_measurement[0], original_measurement[0]) == normal, "Non-probe changes to original normal testbench")
        trace_path = file_at(root, simulation["trace_path"])
        with trace_path.open() as stream:
            header = stream.readline().split()
        require(header == ["time", *vectors] == simulation["trace_headers"], "Saved trace probe headers differ")
        data = np.loadtxt(trace_path, skiprows=1)
        log = file_at(root, simulation["log_path"]).read_text()
        logged_rows = re.findall(r"No\. of Data Rows\s*:\s*(\d+)", log)
        require(logged_rows == [str(len(data))] and "ngspice-47 done" in log, "Simulation log does not confirm saved trace rows/completion")
        summary = read(root / simulation["summary_path"])
        require(canonical(summary) == case["summary_text"] and text_sha(case["summary_text"]) == case["summary_sha256"], "Exact summary text/hash differs")
        compare_value(summary, independent_summary(circuit, data, external, nodes), case_id + "/normal summary")
        case_checks.append({"case_id": case_id, "passed": True, "internal_nodes": len(nodes), "trace_samples": len(data),
                            "logged_row_count_matches": True})
    require(sum(any(m["kind"] == "candidate" for m in c["memberships"]) for c in cases) == 29, "Observed-case coverage differs")
    return {"passed": True, "unique_cases": 33, "observed_cases": 29, "control_cases": 4,
            "input_source_files_checked": len(corpus["source_sha256"]), "original_source_snapshot_hashes_checked": original_hash_checks,
            "by_circuit": dict(Counter(c["circuit"] for c in cases)), "case_checks": case_checks}


def expected_tasks(root, config, corpus, system):
    tasks = []
    cases = sorted(corpus["cases"], key=lambda case: (case["circuit"], case["case_id"]))
    for index, case in enumerate(cases):
        netlist = file_at(root, case["netlist_path"]).read_bytes().decode("utf-8")
        for repetition in range(3):
            seed = config["seed_base"] + config["seed_stride"] * index + repetition
            for condition in CONDITIONS:
                user = SPECS[case["circuit"]] + "\nDUT NETLIST:\n" + netlist
                if condition == "normal_logs":
                    user += SEPARATOR + case["summary_text"]
                request = {"model": config["model"], "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                           "temperature": 0, "max_tokens": 1200, "seed": seed,
                           "response_format": {"type": "json_schema", "json_schema": {"name": "experiment_output", "strict": True, "schema": SCHEMA}}}
                upper = len(canonical(request).encode("utf-8")) + 2048
                reserve = round((upper * PRICES["input"] + 1200 * PRICES["output"]) / 1e6, 10)
                tasks.append({"call_id": RUN_ID + "_" + case["case_id"] + "_" + condition + "_r" + str(repetition),
                              "case_id": case["case_id"], "circuit": case["circuit"], "condition": condition,
                              "repetition": repetition, "seed": seed, "netlist_sha256": case["netlist_sha256"],
                              "summary_sha256": case["summary_sha256"] if condition == "normal_logs" else None,
                              "request": request, "request_sha256": text_sha(canonical({"request": request, "role": ROLE})),
                              "reservation_usd": reserve})
    random.Random(config["order_seed"]).shuffle(tasks)
    for index, task in enumerate(tasks):
        task["order_index"] = index
    return tasks


def audit_plan(root, config, corpus):
    folder = root / "results" / RUN_ID
    manifest, tasks = read(folder / "manifest.json"), read(folder / "tasks.json")
    require(config["protocol"] == config["run_id"] == RUN_ID and config["conditions"] == list(CONDITIONS)
            and config["repetitions"] == 3 and config["model"] == "gpt-4o-mini-2024-07-18"
            and config["temperature"] == 0 and config["max_tokens"] == 1200
            and config["prices_per_million"] == PRICES, "Fixed protocol settings differ")
    require(manifest["config"] == config and manifest["corpus_sha256"] == sha(root / config["corpus"]), "Manifest configuration/corpus differs")
    hash_mapping(root, manifest["source_sha256"], "Supplement frozen source")
    for name, digest in manifest["source_sha256"].items():
        require(sha(folder / "source_snapshot" / name) == digest, "Supplement snapshot changed: " + name)
    require(manifest["tasks_file_sha256"] == sha(folder / "tasks.json")
            and manifest["tasks_content_sha256"] == text_sha(canonical(tasks)), "Task file/hash differs")
    system = file_at(root, config["prompt"]).read_text()
    require(tasks == expected_tasks(root, config, corpus, system), "Frozen tasks differ from independently constructed paired requests")
    require(len(tasks) == 198 and len({t["call_id"] for t in tasks}) == 198, "Task coverage/IDs differ")
    require(manifest["planned_primary_requests"] == 198 and manifest["cases"] == 33
            and manifest["output_schema"] == SCHEMA, "Manifest allocation/schema differs")
    return manifest, tasks, {"passed": True, "cases": 33, "paired_case_repetitions": 99,
                             "planned_requests": 198, "same_system_model_temperature_and_seed_within_pair": True,
                             "exact_netlist_and_normal_only_summary_routing": True}


def usable_output(value):
    return (isinstance(value, dict) and set(value) == set(SCHEMA["required"])
            and type(value["is_trojan"]) is bool and type(value["confidence"]) in (int, float)
            and math.isfinite(value["confidence"]) and 0 <= value["confidence"] <= 1
            and isinstance(value["suspect_nodes"], list) and all(isinstance(x, str) for x in value["suspect_nodes"])
            and isinstance(value["feedback_text"], str))


def decode_response(response):
    choice = (response.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    if choice.get("finish_reason") != "stop" or message.get("refusal"):
        return None, "refusal" if message.get("refusal") else "finish_reason_" + str(choice.get("finish_reason"))
    try:
        value = json.loads(message["content"])
    except (KeyError, TypeError, ValueError):
        return None, "invalid_json"
    if not isinstance(value, dict):
        return None, "invalid_json_object"
    return value, None if usable_output(value) else "invalid_schema"


def actual_cost(usage):
    prompt, output = usage["prompt_tokens"], usage["completion_tokens"]
    cached = (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
    require(all(type(x) is int for x in (prompt, output, cached)) and 0 <= cached <= prompt and output >= 0,
            "Invalid token accounting")
    require(usage.get("total_tokens", prompt + output) == prompt + output, "Total token accounting differs")
    return round(((prompt - cached) * .15 + cached * .075 + output * .60) / 1e6, 10)


def audit_reviews(root, config, corpus, manifest, tasks):
    folder = root / "results" / RUN_ID
    completion, rows = read(folder / "completion.json"), read(folder / "reviews.json")
    require(completion["complete"] is True and completion["planned_reviews"] == completion["recorded_reviews"] == 198,
            "Reviews are incomplete")
    for key, name in (("manifest_sha256", "manifest.json"), ("tasks_sha256", "tasks.json"), ("reviews_sha256", "reviews.json")):
        require(completion[key] == sha(folder / name), "Completion hash differs: " + name)
    require([row["call_id"] for row in rows] == [task["call_id"] for task in tasks], "Review coverage/order differs")
    ledger = read(root / "results/cost_ledger.json")
    ledger_calls = {call_id: entry for call_id, entry in ledger["calls"].items()
                    if call_id.startswith(RUN_ID + "_") or entry.get("role") == ROLE}
    seen_calls, response_ids, request_ids = set(), set(), set()
    failures = Counter()
    billed_cost = 0.
    tokens = Counter()
    observed = {}
    frozen_time = datetime.fromisoformat(manifest["frozen_at_utc"])
    for task, row in zip(tasks, rows):
        for key in ("case_id", "circuit", "condition", "repetition", "seed", "request_sha256", "order_index"):
            require(row[key] == task[key], "Saved review task identity differs: " + key)
        ids = [task["call_id"], task["call_id"] + "_transport_retry1"]
        allocated = [call_id for call_id in ids if call_id in ledger_calls]
        require(allocated and allocated[0] == task["call_id"], "Review lacks its primary ledger event")
        require([record["call_id"] for record in row["api_records"]] == allocated, "Raw API membership differs")
        if len(allocated) == 2:
            first = ledger_calls[allocated[0]]
            require(first["status"] == "uncertain" and "http_status" not in first, "Recovery did not follow a transport-only uncertain event")
        final_value, final_error, final_raw = None, "missing_response", None
        for evidence, actual_id in zip(row["api_records"], allocated):
            require(actual_id not in seen_calls, "API event reused across review rows")
            seen_calls.add(actual_id)
            entry = ledger_calls[actual_id]
            path = file_at(root, evidence["record_path"])
            require(entry["record"] == evidence["record_path"] and sha(path) == evidence["sha256"], "Raw API file/hash differs")
            raw = read(path)
            require(raw["call_id"] == actual_id and raw["role"] == entry["role"] == ROLE, "Raw event identity differs")
            require(raw["request"] == task["request"] and raw["request_sha256"] == entry["request_sha256"] == task["request_sha256"],
                    "Actual API payload differs from paired plan")
            require(raw["created_at_utc"] == entry["created_at_utc"]
                    and datetime.fromisoformat(raw["created_at_utc"]) >= frozen_time, "API event predates freeze or timestamp differs")
            require(raw.get("result") == evidence.get("result") and raw.get("error") == evidence.get("error"), "Row's API evidence differs from raw record")
            require(entry["pricing_per_million"] == PRICES and raw["pricing_per_million"] == PRICES,
                    "Raw event prices differ")
            require(entry["reserved_usd"] == task["reservation_usd"] and entry["temperature"] == 0
                    and entry["requested_seed"] == task["seed"] and entry["seed_sent"] is True, "Ledger request/reservation metadata differs")
            if "response" not in raw:
                require(entry["status"] in {"uncertain", "rejected"} and raw.get("error"), "Missing response has no explicit failure")
                if actual_id != allocated[-1]:
                    require(entry["status"] == "uncertain" and "http_status" not in entry, "Invalid transport retry")
                final_value, final_error, final_raw = None, "request_error", raw
                continue
            require(actual_id == allocated[-1], "A returned response was followed by an unplanned retry")
            response, result = raw["response"], raw["result"]
            require(entry["status"] == "success" and response["model"] == result["model"] == config["model"], "Returned model/status differs")
            response_id = response.get("id")
            require(isinstance(response_id, str) and response_id and response_id not in response_ids, "Missing/reused response ID")
            response_ids.add(response_id)
            require(result["response_id"] == response_id and result["usage"] == response["usage"], "Raw result response/usage differs")
            if result.get("request_id"):
                require(result["request_id"] not in request_ids, "Reused HTTP request ID")
                request_ids.add(result["request_id"])
            cost = actual_cost(response["usage"])
            require(result["original_cost_usd"] == result["cost_usd"] == entry["actual_cost_usd"] == cost
                    and cost <= entry["reserved_usd"], "Raw billed cost differs from token accounting")
            require(result["pricing_per_million"] == PRICES and result["temperature"] == 0
                    and result["requested_seed"] == task["seed"] and result["seed_sent"] is True, "Result settings differ")
            value, error = decode_response(response)
            if error and error != "invalid_schema":
                require(result["output"] is None and result.get("output_error"), "Unusable completion was not retained honestly")
            else:
                require(result["output"] == value and not result.get("output_error"), "Parsed response differs from raw content")
            final_value, final_error, final_raw = value, error, raw
            billed_cost += cost
            tokens["prompt"] += response["usage"]["prompt_tokens"]
            tokens["completion"] += response["usage"]["completion_tokens"]
            tokens["cached_prompt"] += (response["usage"].get("prompt_tokens_details") or {}).get("cached_tokens", 0)
        usable = final_error is None and usable_output(final_value)
        require(row["usable"] is usable and row["output"] == (final_value if usable else None), "Review usability/label differs from independent raw parse")
        require((row.get("failure") is None) == usable, "Failure metadata does not match usability")
        if not usable:
            failures[final_error] += 1
        if row.get("api_metadata") is not None:
            require(final_raw is not None and "result" in final_raw, "API metadata lacks raw returned result")
            meta, returned = row["api_metadata"], final_raw["result"]
            require({k: v for k, v in meta.items() if k not in {"cache_hit", "cost_usd"}}
                    == {k: v for k, v in returned.items() if k not in {"cache_hit", "cost_usd"}}, "API metadata differs from raw result")
            require(meta["cost_usd"] == (0. if meta["cache_hit"] else returned["cost_usd"]), "Exact-ID resumption accounting differs")
        observed[task["case_id"], task["condition"], task["repetition"]] = (
            "positive" if usable and final_value["is_trojan"] else "negative" if usable else "unusable")
    require(seen_calls == set(ledger_calls), "Supplement ledger contains missing or extra API events")
    usable_count = sum(value != "unusable" for value in observed.values())
    require(completion["usable_reviews"] == usable_count and completion["unusable_reviews"] == 198 - usable_count,
            "Completion usable counts differ")
    spent = round(sum(entry.get("actual_cost_usd", 0) for entry in ledger_calls.values()), 10)
    held = round(sum(entry.get("reserved_usd", 0) for entry in ledger_calls.values() if entry["status"] in {"reserved", "uncertain"}), 10)
    require(spent == round(billed_cost, 10), "Supplement cost sum differs")
    project_committed = round(sum(entry.get("actual_cost_usd", 0) + (entry.get("reserved_usd", 0)
                              if entry["status"] in {"reserved", "uncertain"} else 0) for entry in ledger["calls"].values()), 10)
    require(round(spent + held, 10) == completion["budget"]["supplement_committed_usd"]
            and spent + held <= config["supplement_hard_cap_usd"] and project_committed <= config["project_hard_cap_usd"]
            and completion["budget"]["project_committed_usd"] <= project_committed,
            "Cumulative cost or cap differs")
    result = {"passed": True, "scheduled_reviews": 198, "usable_reviews": usable_count,
              "unusable_reviews": 198 - usable_count, "actual_api_events": len(seen_calls),
              "unique_response_ids": len(response_ids), "transport_recovery_events": len(seen_calls) - 198,
              "failure_categories": dict(failures), "token_usage": dict(tokens),
              "billed_cost_usd": spent, "held_reservations_usd": held,
              "project_committed_usd_at_completion": completion["budget"]["project_committed_usd"],
              "api_call_ids": sorted(seen_calls), "api_response_ids": sorted(response_ids)}
    return observed, result


def case_populations(case):
    names = {"observed_candidates" if item["kind"] == "candidate" else
             "clean_controls" if item["control_label"] == "clean" else "positive_controls" for item in case["memberships"]}
    return sorted(names)


def audit_analysis(root, config, corpus, observed):
    folder = root / "results" / RUN_ID
    analysis = read(folder / "analysis.json")
    hash_mapping(root, analysis["source_sha256"], "Analysis source")
    require(analysis["protocol"] == RUN_ID and analysis["complete"] is True and analysis["distinct_cases"] == 33
            and analysis["scheduled_reviews"] == 198, "Analysis allocation differs")
    require(analysis["usable_reviews"] == sum(v != "unusable" for v in observed.values())
            and analysis["unusable_reviews"] == sum(v == "unusable" for v in observed.values()), "Analysis usable counts differ")
    cases = {case["case_id"]: case for case in corpus["cases"]}
    labels = ("positive", "negative", "unusable")
    by_case = {}
    for case_id, case in cases.items():
        for condition in CONDITIONS:
            values = [observed[case_id, condition, rep] for rep in range(3)]
            counts = {label: values.count(label) for label in labels}
            majority = "unusable" if "unusable" in values else "positive" if counts["positive"] >= 2 else "negative"
            by_case[case_id, condition] = {
                "case_id": case_id, "circuit": case["circuit"], "condition": condition,
                "netlist_sha256": case["netlist_sha256"], "populations": case_populations(case),
                "scheduled_reviews": 3, **counts, "verdicts_by_repetition": values,
                "majority": majority, "unanimous_usable": "unusable" not in values and len(set(values)) == 1}
    actual_cases = {(row["case_id"], row["condition"]): row for row in analysis["per_case"]}
    require(len(actual_cases) == len(analysis["per_case"]) == 66 and actual_cases == by_case, "Analysis per-case recount differs")
    groups, pairs = {}, {}
    for circuit in ("and4", "opamp"):
        for population in ("observed_candidates", "clean_controls", "positive_controls"):
            members = [case_id for case_id, case in cases.items() if case["circuit"] == circuit and population in case_populations(case)]
            for condition in CONDITIONS:
                selected = [by_case[case_id, condition] for case_id in members]
                counts = {label: sum(row[label] for row in selected) for label in labels}
                n = len(members) * 3
                groups[circuit, population, condition] = {
                    "circuit": circuit, "population": population, "condition": condition, "distinct_cases": len(members),
                    "scheduled_reviews": n, **counts,
                    **{label + "_fraction_all_scheduled": counts[label] / n for label in labels},
                    "secondary_majority": {label: sum(row["majority"] == label for row in selected) for label in labels}}
            transitions = {a + "_to_" + b: 0 for a in labels for b in labels}
            for case_id in members:
                for rep in range(3):
                    transitions[observed[case_id, "netlist_only", rep] + "_to_" + observed[case_id, "normal_logs", rep]] += 1
            comparable = sum(value for key, value in transitions.items() if "unusable" not in key)
            delta = sum(observed[case_id, "normal_logs", rep] == "positive" for case_id in members for rep in range(3)) \
                - sum(observed[case_id, "netlist_only", rep] == "positive" for case_id in members for rep in range(3))
            pairs[circuit, population] = {"circuit": circuit, "population": population, "distinct_cases": len(members),
                                         "scheduled_pairs": len(members) * 3, "both_usable_pairs": comparable,
                                         "pairs_with_unusable": len(members) * 3 - comparable, "direction": "netlist_only to normal_logs",
                                         "transitions": transitions, "positive_verdict_delta": delta}
    actual_groups = {(row["circuit"], row["population"], row["condition"]): row for row in analysis["groups"]}
    actual_pairs = {(row["circuit"], row["population"]): row for row in analysis["paired"]}
    require(len(actual_groups) == len(analysis["groups"]) == 12 and actual_groups == groups, "Analysis grouped counts/fractions differ")
    require(len(actual_pairs) == len(analysis["paired"]) == 6 and actual_pairs == pairs, "Analysis paired transitions differ")
    for filename, records, keys in (("review_counts.csv", groups, ("circuit", "population", "condition")),
                                    ("per_case.csv", by_case, ("case_id", "condition")),
                                    ("paired_counts.csv", pairs, ("circuit", "population"))):
        with (folder / filename).open(newline="") as stream:
            flat = list(csv.DictReader(stream))
        require(len(flat) == len(records) and len({tuple(row[k] for k in keys) for row in flat}) == len(records), "CSV allocation differs")
        for row in flat:
            expected = records[tuple(row[k] for k in keys)]
            for key, actual in row.items():
                value = expected[key]
                rendered = json.dumps(value, separators=(",", ":")) if isinstance(value, (dict, list)) else str(value)
                require(actual == rendered, "CSV differs from raw recount: " + filename + "/" + key)
    return {"passed": True, "groups_recounted": 12, "paired_groups_recounted": 6, "case_conditions_recounted": 66,
            "csv_files_checked": 3, "groups": list(groups.values()), "paired": list(pairs.values())}


def audit_completed(root, config, corpus, manifest, tasks):
    """Read-only deterministic API/analysis audit, for the delivery checker."""
    observed, api = audit_reviews(root, config, corpus, manifest, tasks)
    analysis = audit_analysis(root, config, corpus, observed)
    return {"api": api, "analysis": analysis}


def _verify(root, preflight):
    root = Path(root)
    config = read(root / "configs/defense_comparison.json")
    corpus = read(root / config["corpus"])
    result = {"run_id": RUN_ID, "mode": "preflight" if preflight else "completed_run",
              "paid_api_calls": 0, "new_simulations": 0, "audit_script_sha256": sha(Path(__file__))}
    result["corpus"] = audit_corpus(root, corpus)
    manifest, tasks, result["request_plan"] = audit_plan(root, config, corpus)
    names = ["configs/defense_comparison.json", config["corpus"],
             f"results/{RUN_ID}/manifest.json", f"results/{RUN_ID}/tasks.json"]
    if not preflight:
        result.update(audit_completed(root, config, corpus, manifest, tasks))
        names += [f"results/{RUN_ID}/{name}" for name in
                  ("reviews.json", "completion.json", "analysis.json", "review_counts.csv", "per_case.csv", "paired_counts.csv")]
        names += ["scripts/defense/analyze.py"]
        # Bind immutable raw records directly; unrelated future API activity may
        # legitimately change the shared cost ledger, which is checked live.
        rows = read(root / "results" / RUN_ID / "reviews.json")
        names += [record["record_path"] for row in rows for record in row["api_records"]]
    result.update(passed=True, complete=not preflight,
                  source_sha256={name: sha(file_at(root, name)) for name in sorted(set(names))})
    return result


def verify(root=ROOT):
    """Return the complete deterministic audit; perform no writes/API/simulation."""
    return _verify(root, preflight=False)


def preflight(root=ROOT):
    """Return the deterministic corpus/frozen-request audit without paid records."""
    return _verify(root, preflight=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    folder = ROOT / "results" / RUN_ID
    try:
        result = preflight() if args.preflight else verify()
    except (ValueError, KeyError, TypeError, OSError, AssertionError) as error:
        result = {"run_id": RUN_ID, "mode": "preflight" if args.preflight else "completed_run",
                  "passed": False, "complete": False, "error": str(error),
                  "audit_script_sha256": sha(Path(__file__)), "paid_api_calls": 0, "new_simulations": 0}
    result["audited_at_utc"] = datetime.now(timezone.utc).isoformat()
    output = folder / ("preflight_audit.json" if args.preflight else "independent_audit.json")
    output.write_text(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    display = {key: result[key] for key in ("run_id", "mode", "passed", "complete")}
    display["output"] = str(output.relative_to(ROOT))
    if "error" in result:
        display["error"] = result["error"]
    if "api" in result:
        display.update({key: result["api"][key] for key in
                        ("scheduled_reviews", "usable_reviews", "unusable_reviews", "actual_api_events", "billed_cost_usd")})
    print(json.dumps(display, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
