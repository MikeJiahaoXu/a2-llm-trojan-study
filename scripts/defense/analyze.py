"""Descriptive paired results; repetitions are not independent circuit samples."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import llm_client as shared
from scripts.defense.experiment import CONDITIONS, populations, sha, validate_saved_rows


def verdict(row):
    if not row["usable"]:
        return "unusable"
    return "positive" if row["output"]["is_trojan"] else "negative"


def summarize(corpus, rows, repetitions=3):
    cases = {c["case_id"]: c for c in corpus["cases"]}
    index = {}
    for row in rows:
        key = (row["case_id"], row["condition"], row["repetition"])
        if key in index or key[0] not in cases or key[1] not in CONDITIONS or not 0 <= key[2] < repetitions:
            raise ValueError("Duplicate or unplanned review row")
        if row["circuit"] != cases[key[0]]["circuit"]:
            raise ValueError("Review circuit disagrees with corpus")
        index[key] = row
    expected = {(case_id, condition, rep) for case_id in cases for condition in CONDITIONS for rep in range(repetitions)}
    if set(index) != expected:
        raise ValueError("Analysis requires every scheduled review, including unusable replies")
    by_case = []
    for case_id, case in sorted(cases.items()):
        for condition in CONDITIONS:
            values = [verdict(index[(case_id, condition, rep)]) for rep in range(repetitions)]
            counts = {v: values.count(v) for v in ["positive", "negative", "unusable"]}
            # All three scheduled outputs must be usable for this secondary vote.
            majority = "unusable" if counts["unusable"] else ("positive" if counts["positive"] >= 2 else "negative")
            by_case.append({"case_id": case_id, "circuit": case["circuit"], "condition": condition,
                            "netlist_sha256": case["netlist_sha256"], "populations": populations(case),
                            "scheduled_reviews": repetitions, **counts, "verdicts_by_repetition": values,
                            "majority": majority, "unanimous_usable": counts["unusable"] == 0 and len(set(values)) == 1})
    groups, paired = [], []
    for circuit in sorted({c["circuit"] for c in cases.values()}):
        for population in ["observed_candidates", "clean_controls", "positive_controls"]:
            members = [c for c in cases.values() if c["circuit"] == circuit and population in populations(c)]
            member_ids = {c["case_id"] for c in members}
            for condition in CONDITIONS:
                case_stats = [c for c in by_case if c["case_id"] in member_ids and c["condition"] == condition]
                counts = {value: sum(c[value] for c in case_stats) for value in ["positive", "negative", "unusable"]}
                n = len(members)*repetitions
                groups.append({"circuit": circuit, "population": population, "condition": condition,
                               "distinct_cases": len(members), "scheduled_reviews": n,
                               **counts, "positive_fraction_all_scheduled": counts["positive"]/n if n else None,
                               "negative_fraction_all_scheduled": counts["negative"]/n if n else None,
                               "unusable_fraction_all_scheduled": counts["unusable"]/n if n else None,
                               "secondary_majority": {value: sum(c["majority"] == value for c in case_stats)
                                                       for value in ["positive", "negative", "unusable"]}})
            transitions = {left + "_to_" + right: 0 for left in ["positive", "negative", "unusable"]
                           for right in ["positive", "negative", "unusable"]}
            for case in members:
                for rep in range(repetitions):
                    left = verdict(index[(case["case_id"], "netlist_only", rep)])
                    right = verdict(index[(case["case_id"], "normal_logs", rep)])
                    transitions[left + "_to_" + right] += 1
            comparable = sum(transitions[a + "_to_" + b] for a in ["positive", "negative"] for b in ["positive", "negative"])
            paired.append({"circuit": circuit, "population": population, "distinct_cases": len(members),
                           "scheduled_pairs": len(members)*repetitions, "both_usable_pairs": comparable,
                           "pairs_with_unusable": len(members)*repetitions-comparable,
                           "direction": "netlist_only to normal_logs", "transitions": transitions,
                           "positive_verdict_delta": sum(transitions[a + "_to_positive"] for a in ["negative", "unusable"])
                                                     - sum(transitions["positive_to_" + b] for b in ["negative", "unusable"])})
    return {"protocol": corpus["protocol"], "complete": True, "distinct_cases": len(cases),
            "scheduled_reviews": len(rows), "usable_reviews": sum(r["usable"] for r in rows),
            "unusable_reviews": sum(not r["usable"] for r in rows),
            "groups": groups, "paired": paired, "per_case": by_case,
            "interpretation": {
                "population": "Fixed previously generated netlists, not an independently sampled Trojan population",
                "primary_unit": "Scheduled individual review, shown alongside distinct-netlist denominator",
                "pairing": "Same exact netlist and repetition seed; both conditions freshly reviewed",
                "controls": "Calibration-associated clean and known-positive controls reported separately",
                "unusable": "Neither positive nor negative; retained in scheduled-review denominators",
                "secondary_majority": "If any reply is unusable, the vote summary is unusable; otherwise at least two positive votes means positive and at least two negative votes means negative",
                "inference": "Descriptive only: repeated judgments are not independent circuit samples; no confidence intervals or calibrated probabilities"}}


def write_csv(path, records, fields):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for record in records:
            writer.writerow({key: json.dumps(record[key], separators=(",", ":"))
                             if isinstance(record[key], (list, dict)) else record[key] for key in fields})


def analyze(root=ROOT):
    config = json.loads((root / "configs/defense_comparison.json").read_text())
    out = root / "results" / config["run_id"]
    completion = json.loads((out / "completion.json").read_text())
    if not completion["complete"]:
        raise ValueError("Incomplete comparison cannot be summarized as completed")
    for key, filename in [("manifest_sha256", "manifest.json"), ("tasks_sha256", "tasks.json"), ("reviews_sha256", "reviews.json")]:
        if sha(out / filename) != completion[key]:
            raise ValueError("Completion evidence changed: " + filename)
    manifest = json.loads((out / "manifest.json").read_text())
    if sha(root / config["corpus"]) != manifest["corpus_sha256"]:
        raise ValueError("Frozen corpus changed")
    corpus = json.loads((root / config["corpus"]).read_text())
    tasks = json.loads((out / "tasks.json").read_text())
    rows = json.loads((out / "reviews.json").read_text())
    validate_saved_rows(rows, tasks, root)
    result = summarize(corpus, rows, config["repetitions"])
    result["source_sha256"] = {str(path.relative_to(root)): sha(path) for path in [
        root / "scripts/defense/analyze.py", root / config["corpus"],
        out / "manifest.json", out / "tasks.json", out / "reviews.json", out / "completion.json"]}
    shared._atomic_json(out / "analysis.json", result)
    write_csv(out / "review_counts.csv", result["groups"], ["circuit", "population", "condition", "distinct_cases",
              "scheduled_reviews", "positive", "negative", "unusable", "positive_fraction_all_scheduled", "secondary_majority"])
    write_csv(out / "per_case.csv", result["per_case"], ["case_id", "circuit", "condition", "populations", "scheduled_reviews",
              "positive", "negative", "unusable", "verdicts_by_repetition", "majority", "unanimous_usable"])
    write_csv(out / "paired_counts.csv", result["paired"], ["circuit", "population", "distinct_cases", "scheduled_pairs",
              "both_usable_pairs", "pairs_with_unusable", "transitions", "positive_verdict_delta"])
    return result


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    result = analyze()
    print(json.dumps({key: result[key] for key in ["complete", "distinct_cases", "scheduled_reviews", "usable_reviews", "unusable_reviews"]}, indent=2))
