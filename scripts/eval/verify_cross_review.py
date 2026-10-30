"""Offline provenance audit for model-extension and retrospective-review records.

No model or simulation calls are made. Raw API response fields, exact messages,
frozen source hashes, and independently reconstructed union membership are
checked rather than trusting the stored summary counters.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib
import itertools
import json
import math
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
STRONGER = "gpt-5.4-mini-2026-03-17"
BASELINE = "gpt-4o-mini-2024-07-18"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_verdict(value):
    require(isinstance(value, dict), "Verdict is not an object")
    require(set(value) == {"is_trojan", "confidence", "suspect_nodes", "feedback_text"}, "Verdict fields differ")
    require(type(value["is_trojan"]) is bool, "Verdict label is not Boolean")
    confidence = value["confidence"]
    require(type(confidence) in (int, float) and math.isfinite(confidence) and 0 <= confidence <= 1,
            "Invalid verdict confidence")
    require(isinstance(value["suspect_nodes"], list) and all(isinstance(x, str) for x in value["suspect_nodes"]),
            "Invalid suspect-node list")
    require(isinstance(value["feedback_text"], str), "Invalid verdict explanation")


def check_raw(raw, expected_model, expected_messages, expected_schema, expected_output, *, seed, max_tokens):
    request, response, result = raw["request"], raw["response"], raw["result"]
    require(request["model"] == expected_model, "Requested model differs")
    require(response["model"] == expected_model, "Actual response model differs")
    require(result["model"] == response["model"], "Result model differs from raw response")
    require(request["messages"] == expected_messages, "Actual prompt messages differ")
    require(request.get("temperature") == .3, "Temperature differs")
    require(request.get("max_completion_tokens", request.get("max_tokens")) == max_tokens, "Output-token cap differs")
    require(request["response_format"] == {"type": "json_schema", "json_schema": {
        "name": "experiment_output", "strict": True, "schema": expected_schema}}, "Output schema differs")
    choice = response["choices"][0]
    require(choice["finish_reason"] == "stop" and not choice["message"].get("refusal"), "Incomplete/refused response")
    require(json.loads(choice["message"]["content"]) == expected_output == result["output"], "Raw output mismatch")
    usage = response["usage"]
    require(usage == result["usage"], "Usage metadata differs")
    require(all(type(usage.get(k)) is int and usage[k] >= 0 for k in ["prompt_tokens", "completion_tokens"]),
            "Invalid raw token usage")
    if expected_model == STRONGER:
        require(request.get("reasoning_effort") == "none", "Reasoning effort differs")
        require("max_completion_tokens" in request and "max_tokens" not in request, "Completion cap parameter differs")
        require("seed" not in request and raw.get("seed_sent") is False and result.get("seed_sent") is False,
                "Unexpected stronger-model seed")
        require(raw.get("requested_seed") == seed == result.get("requested_seed"), "Requested seed metadata differs")
    else:
        require(request.get("seed") == seed, "Baseline seed differs")
        require("max_tokens" in request and "reasoning_effort" not in request, "Baseline generation settings differ")


def frozen_sources(root, manifest):
    for name, expected in manifest["source_hashes"].items():
        require(digest(root/name) == expected, "Frozen source changed: " + name)
    for name, expected in manifest["prompt_hashes"].items():
        require(digest(root/"configs/prompts"/name) == expected, "Frozen prompt changed: " + name)


def audit_adaptive(root, run_id):
    folder = root/"results"/run_id
    manifest, rows, completion = (read(folder/name) for name in ["manifest.json", "attempts.json", "completion.json"])
    config = manifest["config"]
    require(completion.get("complete") is True, "Adaptive run incomplete")
    frozen_sources(root, manifest)
    keys = [(r["circuit"], r["feedback"], r["trajectory"], r["round"]) for r in rows]
    expected = set(itertools.product(config["circuits"], config["feedback_levels"],
                                    range(config["trajectories"]), range(config["rounds_per_trajectory"])))
    require(len(keys) == len(set(keys)) and set(keys) == expected, "Adaptive allocation incomplete/duplicated")
    index = dict(zip(keys, rows))
    attacker = importlib.import_module("scripts.attacker.propose")
    reviewer = importlib.import_module("scripts.detector.review")
    records, unique = set(), {}
    for row in rows:
        previous = None if row["round"] == 0 else index[row["circuit"],row["feedback"],row["trajectory"],row["round"]-1]
        # Capture the actual frozen builder with all network entry points mocked.
        with patch.object(attacker, "json_call", return_value={}) as captured:
            attacker.propose(row["circuit"], "offline", row["seed"], previous, row["feedback"])
            args = captured.call_args.kwargs
        generation = read(root/row["attacker_record"])
        check_raw(generation, config.get("attacker_model", config["model"]), args["messages"], args["schema"],
                  row["parameters"], seed=row["seed"], max_tokens=args["max_tokens"])
        netlist = (root/row["netlist_path"]).read_text()
        require(hashlib.sha256(netlist.encode()).hexdigest() == row["netlist_sha256"], "DUT hash differs")
        with patch.object(reviewer, "json_call", return_value={}) as captured:
            reviewer.review(row["circuit"], netlist, "offline", row["seed"] + 100000)
            args = captured.call_args.kwargs
        review_raw = read(root/row["detector_record"])
        check_verdict(row["detector"])
        check_raw(review_raw, config.get("detector_model", config["model"]), args["messages"], args["schema"],
                  row["detector"], seed=row["seed"] + 100000, max_tokens=args["max_tokens"])
        require(row["success"] is bool(row["simulation"]["valid"] and not row["detector"]["is_trojan"]),
                "Success scoring differs")
        require(read(root/"results/simulations"/row["candidate_id"]/"validation.json") == row["simulation"],
                "Simulation record differs")
        records.update([row["attacker_record"], row["detector_record"]])
        unique[row["candidate_id"]] = row
    for record_key in ["attacker_record", "detector_record"]:
        response_ids = [read(root/r[record_key])["response"]["id"] for r in unique.values()]
        require(len(set(response_ids)) == len(unique), "Different candidate events reused a response ID")
    for circuit, trajectory in itertools.product(config["circuits"], range(config["trajectories"])):
        initial = [index[circuit,level,trajectory,0] for level in config["feedback_levels"]]
        require(len({r["candidate_id"] for r in initial}) == 1, "Initial candidate was not shared")
    return {"passed": True, "run_id": run_id, "attempt_rows": len(rows), "candidate_events": len(unique),
            "distinct_netlists": len({r["netlist_sha256"] for r in unique.values()}),
            "valid_events": sum(r["simulation"]["valid"] for r in unique.values()),
            "candidate_api_records_checked": len(records),
            "checks": ["source/prompt hashes", "actual returned models", "raw output/schema/usage", "temperature/reasoning/seed policy",
                       "exact frozen prompt builders including prior-candidate feedback", "balanced allocation", "DUT hashes", "simulation/scoring"]}


def expected_union(source_rows):
    """Build complete membership independently of review outcomes or validity."""
    groups = {}
    for run, rows in source_rows.items():
        for row in rows:
            sha = row.get("netlist_sha256")
            if not sha:
                continue
            members = groups.setdefault(sha, {})
            candidate_id = row["candidate_id"]
            if candidate_id in members:
                require(members[candidate_id][0] == run and members[candidate_id][1]["detector"] == row["detector"],
                        "Conflicting candidate identity")
            members[candidate_id] = (run, row)
    return groups


def check_union_reviews(source_rows, reviews):
    groups = expected_union(source_rows)
    hashes = [r["sha256"] for r in reviews]
    require(len(hashes) == len(set(hashes)) and set(hashes) == set(groups), "Cross-review omitted/duplicated union netlists")
    for result in reviews:
        members = groups[result["sha256"]]
        representative_id = min(members)
        representative = members[representative_id][1]
        require(result["representative_id"] == representative_id, "Representative is not lexicographically first")
        require(result["circuit"] == representative["circuit"], "Circuit identity differs")
        require(result["baseline_detector"] == representative["detector"], "Baseline verdict differs from frozen representative")
        require(result["valid"] == representative["simulation"]["valid"], "Representative validity differs")
        require(len({r[1]["simulation"]["valid"] for r in members.values()}) == 1, "Identical DUT has inconsistent physical validity")
        expected = {key: {"run": run, "id": key, "valid": row["simulation"]["valid"],
                          "baseline_flag": (row.get("detector") or {}).get("is_trojan")}
                    for key, (run, row) in members.items()}
        actual = {r["id"]: r for r in result["members"]}
        require(len(actual) == len(result["members"]) and actual == expected, "Union membership or baseline labels differ")
    return groups


def audit_cross_review(root, run_id):
    folder = root/"results"/run_id
    manifest, reviews, controls, completion, summary = (read(folder/name) for name in
        ["manifest.json", "reviews.json", "controls.json", "completion.json", "summary.json"])
    require(completion.get("complete") is True, "Cross-review incomplete")
    config = manifest["config"]
    require(digest(root/"scripts/eval/cross_review.py") == manifest["code_hash"], "Cross-review source changed")
    require(digest(root/"configs/prompts/detector_v2.txt") == manifest["prompt_hash"], "Cross-review prompt changed")
    source_rows = {}
    for run in config["source_runs"]:
        source = root/"results"/run
        require(read(source/"completion.json")["complete"], "Source run incomplete")
        require(digest(source/"attempts.json") == manifest["source_attempt_hashes"][run], "Frozen source attempts changed")
        frozen_sources(root, read(source/"manifest.json"))
        source_rows[run] = read(source/"attempts.json")
    groups = check_union_reviews(source_rows, reviews)
    require(len(groups) == manifest["unique_netlists"] == completion["unique_netlists"], "Distinct-DUT count differs")
    reviewer = importlib.import_module("scripts.detector.review")
    simulator = importlib.import_module("scripts.sim.benchmark")
    raw_ids = []
    for result in reviews:
        representative = groups[result["sha256"]][result["representative_id"]][1]
        netlist = (root/representative["netlist_path"]).read_text()
        require(hashlib.sha256(netlist.encode()).hexdigest() == result["sha256"], "Reviewed DUT bytes changed")
        with patch.object(reviewer, "json_call", return_value={}) as captured:
            reviewer.review(result["circuit"], netlist, "offline", None)
            args = captured.call_args.kwargs
        raw = read(root/result["api_record"])
        check_verdict(result["stronger_detector"])
        check_raw(raw, config["reviewer_model"], args["messages"], args["schema"], result["stronger_detector"], seed=None, max_tokens=args["max_tokens"])
        raw_ids.append(raw["response"]["id"])
    expected_controls = set(itertools.product(["opamp","and4"], ["clean","positive"], range(5)))
    keys = [(r["circuit"],r["label"],r["repeat"]) for r in controls]
    require(len(keys) == len(set(keys)) and set(keys) == expected_controls, "Control allocation differs")
    for row in controls:
        netlist = simulator.render_clean(row["circuit"]) if row["label"] == "clean" else simulator.render_candidate(
            row["circuit"], simulator.default_parameters(row["circuit"]))
        with patch.object(reviewer, "json_call", return_value={}) as captured:
            reviewer.review(row["circuit"], netlist, "offline", None)
            args = captured.call_args.kwargs
        check_verdict(row["detector"])
        check_raw(read(root/row["api_record"]), config["reviewer_model"], args["messages"], args["schema"], row["detector"], seed=None, max_tokens=args["max_tokens"])
    counters = {"unique_netlists": len(reviews), "valid_unique_netlists": sum(r["valid"] for r in reviews),
                "flagged": sum(r["stronger_detector"]["is_trojan"] for r in reviews),
                "valid_undetected": sum(r["valid"] and not r["stronger_detector"]["is_trojan"] for r in reviews),
                "verdict_disagreements": sum(r["baseline_detector"]["is_trojan"] != r["stronger_detector"]["is_trojan"] for r in reviews)}
    require(all(summary[key] == value for key,value in counters.items()), "Cross-review summary counters differ")
    require(len(set(raw_ids)) == len(raw_ids), "Distinct netlists reused a response ID")
    return {"passed": True, "run_id": run_id, **counters, "control_judgments_checked": len(controls),
            "source_candidate_events": sum(len(group) for group in groups.values()),
            "checks": ["complete unfiltered union", "deterministic representatives", "all prior candidate memberships",
                       "exact baseline verdicts", "raw returned model and prompt/schema/settings", "frozen source dependencies",
                       "raw unique response IDs", "control allocation", "recomputed summary counters"],
            "interpretation_limit": "Retrospective input-matched classification only; no stronger-attacker/stronger-reviewer adaptive run, population robustness, or independent held-out control claim."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adaptive")
    parser.add_argument("--cross-review")
    args = parser.parse_args()
    require(args.adaptive or args.cross_review, "Choose an adaptive or cross-review run")
    for run_id, audit in [(args.adaptive,audit_adaptive),(args.cross_review,audit_cross_review)]:
        if run_id:
            result = audit(ROOT,run_id)
            (ROOT/"results"/run_id/"independent_model_audit.json").write_text(json.dumps(result,indent=2)+"\n")
            print(json.dumps(result,indent=2))


if __name__ == "__main__":
    main()
