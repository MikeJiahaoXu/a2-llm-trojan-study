"""Prepare/freeze, then execute the predeclared paired evidence comparison."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import llm_client as shared
from scripts.defense import client
from scripts.detector.review import SCHEMA, SPECS

CONFIG_PATH = "configs/defense_comparison.json"
RUNTIME_FILES = ["scripts/defense/__init__.py", "scripts/defense/client.py",
                 "scripts/defense/experiment.py", "scripts/defense/prepare.py",
                 "scripts/llm_client.py", "scripts/detector/review.py",
                 "scripts/request_recovery.py"]
CONDITIONS = ("netlist_only", "normal_logs")
SUMMARY_SEPARATOR = "\nNORMAL-OPERATION MEASUREMENT SUMMARY:\n"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def object_sha(value):
    return hashlib.sha256(shared._canonical(value).encode()).hexdigest()


def repo_path(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Evidence path escapes project root")
    return path


def populations(case):
    """Memberships are evaluation metadata; repeated source rows add no weight."""
    result = set()
    for membership in case["memberships"]:
        if membership["kind"] == "candidate":
            result.add("observed_candidates")
        elif membership["kind"] == "control":
            label = membership["control_label"]
            if label not in {"clean", "positive"}:
                raise ValueError("Unknown control label")
            result.add("clean_controls" if label == "clean" else "positive_controls")
        else:
            raise ValueError("Unknown corpus membership")
    if not result or ("clean_controls" in result and len(result) != 1):
        raise ValueError("Missing or contradictory evaluation membership")
    return sorted(result)


def validate_config(config):
    expected = {"protocol": "defense_comparison_v1", "run_id": "defense_comparison_v1",
                "conditions": list(CONDITIONS), "repetitions": 3,
                "model": client.MODEL, "temperature": 0, "max_tokens": 1200,
                "project_hard_cap_usd": shared.HARD_CAP_USD,
                "supplement_hard_cap_usd": client.SUPPLEMENT_CAP_USD,
                "prices_per_million": client.PRICES}
    for key, value in expected.items():
        if config.get(key) != value:
            raise ValueError("Unexpected fixed protocol setting: " + key)
    if set(config["circuits"]) != set(SPECS):
        raise ValueError("Exactly the two original circuits are required")
    if config["seed_stride"] < config["repetitions"]:
        raise ValueError("Repetition seeds would overlap")


def validate_corpus(root, config, corpus):
    if corpus["protocol"] != config["protocol"]:
        raise ValueError("Corpus protocol mismatch")
    cases = corpus["cases"]
    if len(cases) != config["expected_cases"]:
        raise ValueError("Corpus does not contain the predeclared number of cases")
    if len({c["case_id"] for c in cases}) != len(cases) or len({c["netlist_sha256"] for c in cases}) != len(cases):
        raise ValueError("Corpus case or exact netlist is duplicated")
    for case in cases:
        if case["circuit"] not in config["circuits"]:
            raise ValueError("Unexpected circuit")
        if sha(repo_path(root, case["netlist_path"])) != case["netlist_sha256"]:
            raise ValueError("Netlist content changed")
        if hashlib.sha256(case["summary_text"].encode()).hexdigest() != case["summary_sha256"]:
            raise ValueError("Measurement summary text changed")
        groups = populations(case)
        expected_label = "clean" if groups == ["clean_controls"] else "trojan"
        if case["label"] != expected_label:
            raise ValueError("Evaluation label conflicts with membership")
        for path, digest in case["normal_simulation"]["sha256"].items():
            if sha(repo_path(root, path)) != digest:
                raise ValueError("Normal simulation evidence changed: " + path)
    for path, digest in corpus["source_sha256"].items():
        if sha(repo_path(root, path)) != digest:
            raise ValueError("Original corpus source changed: " + path)
    for circuit in config["circuits"]:
        for group, expected_count in [
                ("observed_candidates", config["expected_observed_cases"][circuit]),
                ("clean_controls", config["expected_controls_per_circuit"]["clean"]),
                ("positive_controls", config["expected_controls_per_circuit"]["positive"])]:
            count = sum(c["circuit"] == circuit and group in populations(c) for c in cases)
            if count != expected_count:
                raise ValueError("Corpus membership count differs from fixed scope")


def build_messages(system, circuit, netlist, condition, summary_text):
    if condition not in CONDITIONS:
        raise ValueError("Unknown evidence condition")
    user = SPECS[circuit] + "\nDUT NETLIST:\n" + netlist
    if condition == "normal_logs":
        user += SUMMARY_SEPARATOR + summary_text
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_tasks(root, config, corpus, system):
    tasks = []
    for case_index, case in enumerate(sorted(corpus["cases"], key=lambda c: (c["circuit"], c["case_id"]))):
        netlist = repo_path(root, case["netlist_path"]).read_bytes().decode("utf-8")
        for repetition in range(config["repetitions"]):
            seed = config["seed_base"] + config["seed_stride"]*case_index + repetition
            for condition in config["conditions"]:
                messages = build_messages(system, case["circuit"], netlist, condition, case["summary_text"])
                request = client.payload_for(messages, SCHEMA, seed, config["max_tokens"])
                tasks.append({"call_id": config["run_id"] + "_" + case["case_id"] + "_" + condition + "_r" + str(repetition),
                              "case_id": case["case_id"], "circuit": case["circuit"],
                              "condition": condition, "repetition": repetition, "seed": seed,
                              "netlist_sha256": case["netlist_sha256"],
                              "summary_sha256": case["summary_sha256"] if condition == "normal_logs" else None,
                              "request": request, "request_sha256": client.request_identity(request),
                              "reservation_usd": client.reservation(request)[1]})
    random.Random(config["order_seed"]).shuffle(tasks)
    for index, task in enumerate(tasks):
        task["order_index"] = index
    return tasks


def freeze(root=ROOT):
    config = json.loads((root / CONFIG_PATH).read_text())
    validate_config(config)
    corpus = json.loads(repo_path(root, config["corpus"]).read_text())
    validate_corpus(root, config, corpus)
    system = repo_path(root, config["prompt"]).read_text()
    tasks = build_tasks(root, config, corpus, system)
    out = root / "results" / config["run_id"]
    manifest_path, tasks_path = out / "manifest.json", out / "tasks.json"
    source_paths = sorted(set(RUNTIME_FILES + [CONFIG_PATH, config["prompt"], config["protocol_document"]]))
    hashes = {path: sha(repo_path(root, path)) for path in source_paths}
    fixed = {"protocol": config["protocol"], "run_id": config["run_id"], "config": config,
             "source_sha256": hashes, "corpus_sha256": sha(repo_path(root, config["corpus"])),
             "tasks_content_sha256": object_sha(tasks), "planned_primary_requests": len(tasks),
             "cases": len(corpus["cases"]), "conditions": list(CONDITIONS), "repetitions": 3,
             "seed_rule": "seed_base + seed_stride * zero_based_sorted_circuit_case_index + zero_based_repetition",
             "order_seed": config["order_seed"], "output_schema": SCHEMA,
             "primary_reservation_bound_usd": round(sum(t["reservation_usd"] for t in tasks), 10),
             "one_transport_recovery_per_task_bound_usd": round(2*sum(t["reservation_usd"] for t in tasks), 10),
             "control_gate": "none; retain every scheduled control and observed-case result"}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        for key, value in fixed.items():
            if manifest.get(key) != value:
                raise ValueError("Frozen protocol changed: " + key)
        if not tasks_path.exists() or json.loads(tasks_path.read_text()) != tasks:
            raise ValueError("Frozen task list changed")
        if sha(tasks_path) != manifest["tasks_file_sha256"]:
            raise ValueError("Frozen task file bytes changed")
        for path, digest in hashes.items():
            if sha(out / "source_snapshot" / path) != digest:
                raise ValueError("Frozen source snapshot changed: " + path)
        return manifest, tasks, corpus
    if tasks_path.exists() or (out / "reviews.json").exists():
        raise ValueError("Unsealed task/result artifacts exist")
    with shared._locked():
        ledger = shared._read_ledger()
        if any(k.startswith(client.CALL_PREFIX) or e.get("role") == client.ROLE for k, e in ledger["calls"].items()):
            raise ValueError("Paid defense records exist before protocol freeze")
        state = client.budget_state(ledger)
    bound = fixed["one_transport_recovery_per_task_bound_usd"]
    if state["project_committed_usd"] + bound > shared.HARD_CAP_USD or state["supplement_committed_usd"] + bound > client.SUPPLEMENT_CAP_USD:
        raise client.BudgetExceeded("Worst-case reservations exceed available caps; prepare stopped without sending")
    for path in source_paths:
        target = out / "source_snapshot" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo_path(root, path), target)
    shared._atomic_json(tasks_path, tasks)
    manifest = dict(fixed, frozen_at_utc=shared._now(), budget_at_freeze=state,
                    tasks_file_sha256=sha(tasks_path), status="frozen_before_paid_requests")
    shared._atomic_json(manifest_path, manifest)
    return manifest, tasks, corpus


def valid_review(output):
    if not isinstance(output, dict) or set(output) != set(SCHEMA["required"]):
        return False
    return (type(output["is_trojan"]) is bool
            and type(output["confidence"]) in {int, float}
            and math.isfinite(output["confidence"]) and 0 <= output["confidence"] <= 1
            and isinstance(output["suspect_nodes"], list)
            and all(isinstance(node, str) for node in output["suspect_nodes"])
            and isinstance(output["feedback_text"], str))


def api_evidence(call_id):
    evidence = []
    for actual_id in [call_id, call_id + "_transport_retry1"]:
        path = client.record_path(actual_id)
        if path.exists():
            record = json.loads(path.read_text())
            evidence.append({"call_id": actual_id, "record_path": str(path.relative_to(shared.ROOT)),
                             "sha256": sha(path), "result": record.get("result"), "error": record.get("error")})
    return evidence


def validate_saved_rows(rows, tasks, root=ROOT):
    by_id = {task["call_id"]: task for task in tasks}
    if len({row["call_id"] for row in rows}) != len(rows):
        raise ValueError("Duplicate saved review")
    for row in rows:
        task = by_id.get(row["call_id"])
        if not task or any(row[k] != task[k] for k in ["case_id", "circuit", "condition", "repetition", "seed", "request_sha256", "order_index"]):
            raise ValueError("Saved review does not match frozen task")
        if row["usable"] != valid_review(row.get("output")):
            raise ValueError("Saved review usability differs from output")
        for record in row["api_records"]:
            if sha(repo_path(root, record["record_path"])) != record["sha256"]:
                raise ValueError("Saved raw API record changed")


def run(root=ROOT):
    manifest, tasks, corpus = freeze(root)
    out = root / "results" / manifest["run_id"]
    rows_path = out / "reviews.json"
    rows = json.loads(rows_path.read_text()) if rows_path.exists() else []
    validate_saved_rows(rows, tasks, root)
    completed = {row["call_id"] for row in rows}
    for task in tasks:
        if task["call_id"] in completed:
            continue
        request = task["request"]
        row = {key: task[key] for key in ["call_id", "case_id", "circuit", "condition", "repetition", "seed", "request_sha256", "order_index"]}
        row.update(started_at_utc=shared._now(), usable=False, output=None, failure=None)
        stop_error = None
        try:
            metadata = client.json_call(messages=request["messages"], schema=SCHEMA,
                                        call_id=task["call_id"], seed=task["seed"], max_tokens=request["max_tokens"])
            row["api_metadata"] = metadata
            if metadata["model"] != client.MODEL:
                raise client.APIRequestError("Returned model differs from fixed snapshot; operational stop")
            if valid_review(metadata["output"]):
                row.update(usable=True, output=metadata["output"])
            else:
                row["failure"] = {"kind": "invalid_schema", "message": "Response JSON does not satisfy the review schema"}
        except client.APIOutputError as error:
            row["failure"] = {"kind": "unusable_output", "message": str(error)}
        except client.APIRequestError as error:
            row["failure"] = {"kind": "request_error", "message": str(error)}
            stop_error = error
        row.update(api_records=api_evidence(task["call_id"]), finished_at_utc=shared._now())
        rows.append(row)
        shared._atomic_json(rows_path, rows)
        print(f"Defense reviews {len(rows)}/{len(tasks)}; usable={sum(r['usable'] for r in rows)}", flush=True)
        if stop_error:
            raise stop_error
    validate_saved_rows(rows, tasks, root)
    with shared._locked():
        budget = client.budget_state(shared._read_ledger())
    completion = {"complete": len(rows) == len(tasks), "protocol": manifest["protocol"],
                  "completed_at_utc": shared._now(), "planned_reviews": len(tasks),
                  "recorded_reviews": len(rows), "usable_reviews": sum(r["usable"] for r in rows),
                  "unusable_reviews": sum(not r["usable"] for r in rows),
                  "cases": len(corpus["cases"]), "manifest_sha256": sha(out / "manifest.json"),
                  "tasks_sha256": sha(out / "tasks.json"), "reviews_sha256": sha(rows_path),
                  "budget": budget}
    shared._atomic_json(out / "completion.json", completion)
    return completion


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--prepare", action="store_true", help="Freeze and validate; no API calls")
    modes.add_argument("--run", action="store_true", help="Execute/resume the frozen task list")
    args = parser.parse_args()
    if args.prepare:
        manifest, _, _ = freeze()
        print(json.dumps({key: manifest[key] for key in ["run_id", "cases", "planned_primary_requests",
                         "primary_reservation_bound_usd", "one_transport_recovery_per_task_bound_usd", "frozen_at_utc"]}, indent=2))
    else:
        print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
