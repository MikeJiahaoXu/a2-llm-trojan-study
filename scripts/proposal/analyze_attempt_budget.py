"""Retrospective descriptive analysis of the existing final experiment records.

Run: python3 scripts/proposal/analyze_attempt_budget.py
Writes deterministic JSON and summary CSV; performs no API calls or simulations.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_IDS = ("proposal_main_v3", "proposal_repeat_v3")
CIRCUITS = ("opamp", "and4")
CONDITIONS = ("none", "binary", "full")
ATTEMPTS = 10


def read_json(path):
    return json.loads(path.read_text())


def fraction(successes, denominator):
    return {"successes": int(successes), "denominator": denominator,
            "rate": successes / denominator}


def usable_verdict(row):
    return isinstance(row.get("detector"), dict) and isinstance(row["detector"].get("is_trojan"), bool)


def deduplicate(rows):
    events = {}
    fields = ("_run_id", "circuit", "parameters", "netlist_sha256", "simulation",
              "detector", "detector_call_id", "detector_negative", "success",
              "round", "trajectory", "shared_initial")
    for row in rows:
        candidate_id = row["candidate_id"]
        if candidate_id in events:
            for field in fields:
                if events[candidate_id][field] != row[field]:
                    raise ValueError(f"Inconsistent shared event: {candidate_id}/{field}")
            if row["round"] != 0 or not row["shared_initial"]:
                raise ValueError("Only shared first attempts may be duplicated")
        else:
            events[candidate_id] = row
    return [events[key] for key in sorted(events)]


def trajectory_summary(rows):
    rows = sorted(rows, key=lambda row: row["round"])
    if [row["round"] for row in rows] != list(range(ATTEMPTS)):
        raise ValueError("Each arm trajectory must contain exactly rounds 0 through 9")
    initial = rows[0]
    if not initial["shared_initial"] or any(row["shared_initial"] for row in rows[1:]):
        raise ValueError("Shared-start flags do not match the declared protocol")
    successes = [bool(row["success"]) for row in rows]
    earliest = next((index + 1 for index, success in enumerate(successes) if success), None)
    return {
        "run_id": initial["_run_id"], "circuit": initial["circuit"],
        "condition": initial["feedback"], "trajectory_id": initial["trajectory"],
        "attempts": len(rows), "first_attempt_success": successes[0],
        "final_attempt_success": successes[-1], "any_success_within_10": any(successes),
        "total_successful_attempts": sum(successes), "earliest_success_attempt": earliest,
        "success_by_attempt": successes,
        "usable_detector_verdict_by_attempt": [usable_verdict(row) for row in rows],
        "unusable_detector_responses": sum(not usable_verdict(row) for row in rows),
        "distinct_netlist_hashes": len({row["netlist_sha256"] for row in rows}),
        "candidate_ids_by_attempt": [row["candidate_id"] for row in rows],
        "shared_initial_candidate_id": initial["candidate_id"],
    }


def summarize_group(scope, circuit, condition, trajectories, rows):
    selected = [session for session in trajectories
                if session["circuit"] == circuit and session["condition"] == condition
                and (scope == "pooled" or session["run_id"] == scope)]
    group_rows = [row for row in rows if row["circuit"] == circuit and row["feedback"] == condition
                  and (scope == "pooled" or row["_run_id"] == scope)]
    n = len(selected)
    if n != (4 if scope == "pooled" else 2) or len(group_rows) != n * ATTEMPTS:
        raise ValueError(f"Unexpected session/row count for {scope}/{circuit}/{condition}")
    curve = []
    for k in range(1, ATTEMPTS + 1):
        cumulative = sum(any(session["success_by_attempt"][:k]) for session in selected)
        current = sum(session["success_by_attempt"][k - 1] for session in selected)
        curve.append({"attempt_budget": k, "any_success_by_attempt": fraction(cumulative, n),
                      "success_at_this_attempt": fraction(current, n),
                      "attempt_rows_used": k * n})
    return {
        "scope": scope, "circuit": circuit, "condition": condition,
        "arm_trajectories": n, "attempts_per_trajectory": ATTEMPTS,
        "analysis_rows": len(group_rows), "actual_events_within_group": len(deduplicate(group_rows)),
        "unusable_detector_responses": sum(not usable_verdict(row) for row in group_rows),
        "first_attempt_success": fraction(sum(s["first_attempt_success"] for s in selected), n),
        "final_attempt_success": fraction(sum(s["final_attempt_success"] for s in selected), n),
        "any_success_within_10": fraction(sum(s["any_success_within_10"] for s in selected), n),
        "all_attempt_success": fraction(sum(s["total_successful_attempts"] for s in selected), len(group_rows)),
        "distinct_netlist_hashes": len({row["netlist_sha256"] for row in group_rows}),
        "cumulative_curve": curve,
    }


def build_analysis():
    sources = [Path(__file__).resolve()]
    rows, run_metadata = [], {}
    for run_id in RUN_IDS:
        folder = ROOT / "results" / run_id
        attempts_path, manifest_path = folder / "attempts.json", folder / "manifest.json"
        sources.extend((attempts_path, manifest_path))
        original = read_json(attempts_path)
        config = read_json(manifest_path)["config"]
        if config["trajectories"] != 2 or config["rounds_per_trajectory"] != ATTEMPTS or not config["shared_first_round"]:
            raise ValueError(f"Unexpected frozen protocol for {run_id}")
        if len(original) != 120:
            raise ValueError(f"Incomplete run: {run_id}")
        for row in original:
            if row["circuit"] not in CIRCUITS or row["feedback"] not in CONDITIONS:
                raise ValueError("Unexpected circuit or feedback condition")
            if usable_verdict(row):
                if row["detector_negative"] != (not row["detector"]["is_trojan"]):
                    raise ValueError("Detector verdict bookkeeping mismatch")
            elif not row.get("detector_error") or row["detector_negative"] or row["success"]:
                raise ValueError("Unusable detector response is not recorded as an explicit non-success")
            if row["success"] != (row["simulation"]["valid"] and row["detector_negative"]):
                raise ValueError("Success bookkeeping mismatch")
            rows.append({**row, "_run_id": run_id})
        run_metadata[run_id] = {"model": config["model"], "trajectories_per_condition": 2,
                                "attempts_per_trajectory": ATTEMPTS, "shared_first_round": True}

    sessions = []
    for run_id in RUN_IDS:
        for circuit in CIRCUITS:
            for condition in CONDITIONS:
                group = [row for row in rows if row["_run_id"] == run_id
                         and row["circuit"] == circuit and row["feedback"] == condition]
                trajectory_ids = sorted({row["trajectory"] for row in group})
                if len(trajectory_ids) != 2:
                    raise ValueError("Expected two trajectories per batch/circuit/condition")
                sessions.extend(trajectory_summary([row for row in group if row["trajectory"] == trajectory_id])
                                for trajectory_id in trajectory_ids)
    groups = [summarize_group(scope, circuit, condition, sessions, rows)
              for scope in ("pooled", *RUN_IDS) for circuit in CIRCUITS for condition in CONDITIONS]
    events = deduplicate(rows)
    initial_rows = [row for row in rows if row["round"] == 0]
    initial_events = deduplicate(initial_rows)
    initial_group_membership = []
    for initial in initial_events:
        matching = [row for row in initial_rows if row["candidate_id"] == initial["candidate_id"]]
        if sorted(row["feedback"] for row in matching) != sorted(CONDITIONS):
            raise ValueError("Each initial event must appear once in each of the three conditions")
        initial_group_membership.append({
            "candidate_id": initial["candidate_id"], "run_id": initial["_run_id"],
            "circuit": initial["circuit"], "trajectory_id": initial["trajectory"],
            "success": initial["success"], "condition_rows": sorted(row["feedback"] for row in matching),
        })
    counts = {
        "analysis_rows": len(rows), "actual_candidate_review_events": len(events),
        "distinct_netlist_hashes": len({row["netlist_sha256"] for row in events}),
        "arm_trajectories": len(sessions), "shared_initial_analysis_rows": len(initial_rows),
        "shared_initial_actual_events": len(initial_events),
        "duplicate_shared_initial_rows": len(initial_rows) - len(initial_events),
        "successful_analysis_rows": sum(row["success"] for row in rows),
        "successful_actual_events": sum(row["success"] for row in events),
        "usable_detector_verdict_events": sum(usable_verdict(row) for row in events),
        "unusable_detector_response_events": sum(not usable_verdict(row) for row in events),
    }
    expected = {"opamp": {"none": 0, "binary": 13, "full": 13},
                "and4": {"none": 10, "binary": 9, "full": 6}}
    checks = {
        "original_240_rows_224_events_29_netlists_retained":
            counts["analysis_rows"] == 240 and counts["actual_candidate_review_events"] == 224
            and counts["distinct_netlist_hashes"] == 29,
        "eight_shared_initial_events_account_for_24_condition_rows":
            len(initial_events) == 8 and len(initial_rows) == 24,
        "each_actual_candidate_event_has_a_distinct_saved_detector_call_id":
            len({row["detector_call_id"] for row in events}) == len(events),
        "all_electrical_validity_results_retained": all(row["simulation"]["valid"] for row in events),
        "two_unusable_detector_responses_retained_as_non_success":
            counts["usable_detector_verdict_events"] == 222 and counts["unusable_detector_response_events"] == 2,
        "original_primary_attemptwise_group_numerators_retained": all(
            group["all_attempt_success"]["successes"] == expected[group["circuit"]][group["condition"]]
            for group in groups if group["scope"] == "pooled"),
        "cumulative_k1_and_k10_match_endpoint_metrics": all(
            group["cumulative_curve"][0]["any_success_by_attempt"] == group["first_attempt_success"]
            and group["cumulative_curve"][-1]["any_success_by_attempt"] == group["any_success_within_10"]
            for group in groups),
    }
    if not all(checks.values()):
        raise ValueError(f"Validation failed: {[name for name, passed in checks.items() if not passed]}")
    return {
        "schema_version": 1,
        "analysis_type": "retrospective_descriptive_reanalysis_of_existing_records",
        "scope": "Existing proposal_main_v3 and proposal_repeat_v3 only; no protocol change or new experiment.",
        "paid_api_calls": 0, "new_simulations": 0,
        "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted(sources)},
        "run_metadata": run_metadata, "counts": counts,
        "definitions": {
            "success": "Saved candidate is electrically valid and a usable detector verdict is_trojan is false. Unusable responses retain the original non-success treatment and remain in denominators.",
            "first_attempt_success": "Success of saved round 0 (attempt 1), a retrospective one-shot view; the same initial candidate/review is shared across conditions.",
            "final_attempt_success": "Success of saved round 9 (attempt 10), irrespective of any earlier success.",
            "any_success_within_10": "A trajectory contains at least one successful attempt among attempts 1 through 10.",
            "all_attempt_success": "Successful attempt rows divided by all attempt rows; retains the original attemptwise primary counts.",
            "cumulative_curve": "At budget k, proportion of arm trajectories with at least one success in their first k saved attempts.",
            "earliest_success_attempt": "One-based index of first successful attempt; null when no success occurs within 10 attempts.",
            "actual_candidate_review_event": "One candidate_id; shared initial events count once globally, while condition summaries retain their paired starting rows.",
            "unusable_detector_response": "A saved detector error without a usable Boolean verdict; counts as non-success, not as a positive detection.",
        },
        "groups": groups, "trajectories": sessions,
        "unusable_detector_responses": [
            {"candidate_id": row["candidate_id"], "run_id": row["_run_id"],
             "circuit": row["circuit"], "condition": row["feedback"],
             "trajectory_id": row["trajectory"], "attempt": row["round"] + 1,
             "error": row["detector_error"]}
            for row in events if not usable_verdict(row)],
        "shared_initial_event_membership": initial_group_membership,
        "interpretation_caveats": [
            "These metrics are retrospective descriptive views, not newly preregistered endpoints or new experimental observations.",
            "Each pooled circuit/condition has only four arm trajectories: two per batch. Conditions share initial events and attempts within a trajectory are dependent.",
            "Cumulative success is nondecreasing by definition. Its gain over attempt 1 cannot identify feedback learning: None also receives ten fresh detector-call attempts, despite often repeating the same netlist.",
            "Two existing unusable detector responses remain non-successes in all original denominators; they are not relabeled as positive detections or silently dropped.",
            "The final attempted candidate may fail even when an earlier candidate succeeded; the recorded protocol continues after success rather than stopping at the first success.",
            "Any-within-k describes the existence of a saved success. It does not establish success of a separately selected/deployed candidate or future repeatability of a detector verdict.",
            "Attemptwise group counts retain shared starts for paired condition comparisons; summing those rows across conditions does not produce the number of independent reviews.",
            "No causal effect of circuit complexity or comparison of model generations is established by this reanalysis.",
        ],
        "checks": checks, "passed": all(checks.values()),
    }


def summary_csv(analysis):
    metrics = ("first_attempt_success", "final_attempt_success", "any_success_within_10", "all_attempt_success")
    fields = ["scope", "circuit", "condition", "arm_trajectories", "attempts_per_trajectory", "analysis_rows",
              "actual_events_within_group", "distinct_netlist_hashes", "unusable_detector_responses"]
    fields.extend(f"{metric}_{field}" for metric in metrics for field in ("successes", "denominator", "rate"))
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for group in analysis["groups"]:
        row = {field: group[field] for field in fields if field in group}
        row.update({f"{metric}_{field}": group[metric][field] for metric in metrics
                    for field in ("successes", "denominator", "rate")})
        writer.writerow(row)
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="results/proposal_analysis")
    args = parser.parse_args()
    analysis = build_analysis()
    folder = ROOT / args.output_dir
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "attempt_budget.json").write_text(json.dumps(analysis, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    (folder / "attempt_budget.csv").write_text(summary_csv(analysis))
    print(json.dumps({"passed": analysis["passed"], "counts": analysis["counts"],
                      "json": str((folder / "attempt_budget.json").relative_to(ROOT)),
                      "csv": str((folder / "attempt_budget.csv").relative_to(ROOT))}, indent=2))


if __name__ == "__main__":
    main()
