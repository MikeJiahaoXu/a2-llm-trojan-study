"""Reproduce descriptive AND statistics from saved final-run records only.

Run: python3 scripts/proposal/diagnose_and.py
No API requests, simulations, or changes to original experiment evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_IDS = ("proposal_main_v3", "proposal_repeat_v3")
ARMS = ("none", "binary", "full")


def read_json(path):
    return json.loads(path.read_text())


def unique_events(rows):
    events = {}
    fields = ("circuit", "parameters", "netlist_sha256", "simulation", "detector",
              "detector_call_id", "detector_negative", "success")
    for row in rows:
        candidate_id = row["candidate_id"]
        if candidate_id in events:
            for field in fields:
                if events[candidate_id][field] != row[field]:
                    raise ValueError(f"Inconsistent shared event: {candidate_id}/{field}")
        else:
            events[candidate_id] = row
    return [events[key] for key in sorted(events)]


def verdict_counts(rows):
    return {
        "count": len(rows),
        "flagged": sum(row["detector"]["is_trojan"] for row in rows),
        "detector_negative": sum(row["detector_negative"] for row in rows),
        "escapes": sum(row["success"] for row in rows),
        "electrically_valid": sum(row["simulation"]["valid"] for row in rows),
    }


def grouped_counts(rows, field):
    groups = defaultdict(list)
    for row in rows:
        groups[row["parameters"][field]].append(row)
    return {key: verdict_counts(groups[key]) for key in sorted(groups)}


def site_representation_counts(rows):
    groups = defaultdict(list)
    for row in rows:
        params = row["parameters"]
        groups[(params["insertion_site"], params["representation"])].append(row)
    return [{"insertion_site": site, "representation": representation,
             **verdict_counts(group)}
            for (site, representation), group in sorted(groups.items())]


def summarize(rows):
    events = unique_events(rows)
    return {
        "analysis_rows": verdict_counts(rows),
        "actual_events": verdict_counts(events),
        "duplicate_shared_rows": len(rows) - len(events),
        "shared_initial_analysis_rows": sum(row["shared_initial"] for row in rows),
        "shared_initial_actual_events": sum(row["shared_initial"] for row in events),
        "distinct_netlist_hashes": len({row["netlist_sha256"] for row in events}),
        "sites_by_analysis_row": grouped_counts(rows, "insertion_site"),
        "representations_by_analysis_row": grouped_counts(rows, "representation"),
        "site_representation_by_analysis_row": site_representation_counts(rows),
        "sites_by_actual_event": grouped_counts(events, "insertion_site"),
        "site_representation_by_actual_event": site_representation_counts(events),
    }


def build_diagnostic():
    sources = [Path(__file__).resolve()]
    runs, all_rows, event_runs = {}, [], {}
    for run_id in RUN_IDS:
        folder = ROOT / "results" / run_id
        attempts_path, manifest_path = folder / "attempts.json", folder / "manifest.json"
        sources.extend((attempts_path, manifest_path))
        rows = [row for row in read_json(attempts_path) if row["circuit"] == "and4"]
        config = read_json(manifest_path)["config"]
        for row in rows:
            if not isinstance(row["detector"]["is_trojan"], bool):
                raise ValueError(f"Missing Boolean detector verdict: {row['candidate_id']}")
            if row["detector_negative"] != (not row["detector"]["is_trojan"]):
                raise ValueError(f"Detector-negative bookkeeping mismatch: {row['candidate_id']}")
            if row["success"] != (row["simulation"]["valid"] and row["detector_negative"]):
                raise ValueError(f"Success bookkeeping mismatch: {row['candidate_id']}")
        events = unique_events(rows)
        for event in events:
            if event["candidate_id"] in event_runs:
                raise ValueError("Candidate identifiers must be distinct across runs")
            event_runs[event["candidate_id"]] = run_id
        arms = {arm: summarize([row for row in rows if row["feedback"] == arm])
                for arm in ARMS}
        runs[run_id] = {
            "model": config["model"], "trajectories_per_arm": config["trajectories"],
            "rounds_per_trajectory": config["rounds_per_trajectory"],
            "shared_first_round": config["shared_first_round"],
            **summarize(rows), "arms": arms,
        }
        all_rows.extend(rows)

    events = unique_events(all_rows)
    none_rows = [row for row in all_rows if row["feedback"] == "none"]
    none_hashes = {row["netlist_sha256"] for row in none_rows}
    if len(none_hashes) != 1:
        raise ValueError("Expected one common AND netlist across both none arms")
    common_hash = next(iter(none_hashes))
    common_events = [row for row in events if row["netlist_sha256"] == common_hash]
    internal = [row for row in events if row["parameters"]["insertion_site"] == "nand_node_pullup"]
    hash_groups = defaultdict(list)
    for row in events:
        hash_groups[row["netlist_sha256"]].append(row)
    frequencies = []
    for digest, group in sorted(hash_groups.items()):
        frequencies.append({
            "netlist_sha256": digest, "parameters": group[0]["parameters"],
            "actual_reviews": verdict_counts(group),
            "by_run": {run_id: verdict_counts([row for row in group
                                              if event_runs[row["candidate_id"]] == run_id])
                       for run_id in RUN_IDS},
            "candidate_ids": [row["candidate_id"] for row in group],
        })

    checks = {
        "and_analysis_rows_120": len(all_rows) == 120,
        "and_actual_events_112": len(events) == 112,
        "common_netlist_42_flags_in_60_actual_reviews":
            len(common_events) == 60 and verdict_counts(common_events)["flagged"] == 42,
        "all_40_internal_events_flagged": len(internal) == 40 and all(row["detector"]["is_trojan"] for row in internal),
        "none_common_netlist_10_escapes_in_40_reviews":
            len(none_rows) == 40 and verdict_counts(none_rows)["escapes"] == 10,
        "all_and_events_electrically_valid": all(row["simulation"]["valid"] for row in events),
        "binary_and_full_each_have_10_internal_rows_per_run": all(
            runs[run_id]["arms"][arm]["sites_by_analysis_row"]["nand_node_pullup"]["count"] == 10
            for run_id in RUN_IDS for arm in ("binary", "full")),
    }
    if not all(checks.values()):
        raise ValueError(f"Reference counts no longer match: {[key for key, value in checks.items() if not value]}")
    return {
        "schema_version": 1,
        "scope": "Descriptive AND statistics from saved final-run evidence; no new experiment.",
        "paid_api_calls": 0, "new_simulations": 0,
        "deduplication": "One actual event per candidate_id; each shared first-round event appears in three arm rows but is counted once in actual-event totals.",
        "definitions": {
            "flagged": "The saved detector verdict is_trojan is true.",
            "escape": "The saved electrical validation passes and the detector verdict is_trojan is false.",
            "actual_review": "One deduplicated candidate event with a saved detector result; excludes clean/positive controls.",
        },
        "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted(sources)},
        "runs": runs, "pooled": summarize(all_rows),
        "common_none_netlist": {
            "netlist_sha256": common_hash, "parameters": common_events[0]["parameters"],
            "actual_reviews_all_arms": verdict_counts(common_events),
            "none_arm_reviews": verdict_counts(none_rows),
            "by_run": {run_id: verdict_counts([row for row in common_events
                                              if event_runs[row["candidate_id"]] == run_id])
                       for run_id in RUN_IDS},
        },
        "internal_insertion_actual_reviews": verdict_counts(internal),
        "netlist_review_frequencies": frequencies,
        "checks": checks, "passed": all(checks.values()),
        "interpretation_caveats": [
            "There are only two trajectories per arm per run; sequential attempts and shared starts are not independent samples.",
            "Both none arms repeatedly review the same netlist; their escape counts primarily describe repeated detector outcomes for that input.",
            "The same netlist receives both verdicts; this establishes observed classification variability, not its underlying cause.",
            "These runs use the same fixed model version; they do not compare model generations or establish improvement over older papers.",
            "This is not a causal test of circuit complexity, insertion site, or component representation; choices and other parameters are confounded.",
            "Full and binary each use ten internal-site candidates per run; full does not select a larger internal-site fraction than binary.",
            "All observed internal-site candidates were flagged; this does not establish universal detectability of that insertion site.",
            "Saved nominal electrical validity does not establish silicon behavior or equivalence under all possible stimuli.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="results/proposal_analysis/and_diagnostics.json")
    args = parser.parse_args()
    result = build_diagnostic()
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps({"output": str(output.relative_to(ROOT)), "passed": result["passed"],
                      "checks": result["checks"]}, indent=2))


if __name__ == "__main__":
    main()
