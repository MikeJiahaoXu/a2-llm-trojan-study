"""Explicit, narrowly bounded continuation after the repeat's failed control gate.

The frozen experiment runner remains intact. This launcher retains the failed
controls and executes its unchanged trial schedule under a recorded deviation.
Preparation is offline. Only --execute can make API requests.
"""
from __future__ import annotations

import argparse
import ast
import copy
from datetime import datetime, timezone
import hashlib
import inspect
import json
from pathlib import Path
import random

from scripts.proposal import experiment, circuits, prompts
from scripts.eval.verify_cross_review import check_raw, require

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = "proposal_repeat_v3"
PRIMARY_ID = "proposal_main_v3"
SIDECAR = "control_gate_deviation.json"
candidate = experiment.candidate
save = experiment.save


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def continue_trials(config, run_id):
    folder = ROOT / "results" / run_id
    rows, state = [], {}
    base = config["run_seeds"][run_id]
    tasks = [(c, t) for c in config["circuits"] for t in range(config["trajectories"])]
    random.Random(base).shuffle(tasks)
    for circuit, trial in tasks:
        seed = base + config["circuits"].index(circuit)*1000 + trial*100
        row = candidate(circuit, f"{run_id}_{circuit}_t{trial}_shared_r0", seed, config)
        for level in config["feedback_levels"]:
            state[circuit, trial, level] = row
            rows.append(dict(copy.deepcopy(row), feedback=level, trajectory=trial, round=0, shared_initial=True, seed=seed))
        save(folder / "attempts.json", rows)
        print(f"{run_id}: initial {circuit} t{trial} valid={row['simulation']['valid']} success={row['success']}", flush=True)
    for round_index in range(1, config["rounds_per_trajectory"]):
        tasks = [(c,t,f) for c in config["circuits"] for t in range(config["trajectories"]) for f in config["feedback_levels"]]
        random.Random(base + round_index).shuffle(tasks)
        for circuit, trial, level in tasks:
            seed = base + config["circuits"].index(circuit)*1000 + trial*100 + round_index
            row = candidate(circuit, f"{run_id}_{circuit}_t{trial}_{level}_r{round_index}", seed, config,
                            state[circuit, trial, level], level)
            state[circuit, trial, level] = row
            rows.append(dict(copy.deepcopy(row), feedback=level, trajectory=trial, round=round_index, shared_initial=False, seed=seed))
            save(folder / "attempts.json", rows)
            print(f"{run_id}: {circuit} {level} t{trial} r{round_index} valid={row['simulation']['valid']} success={row['success']}", flush=True)
    expected = len(config["circuits"])*len(config["feedback_levels"])*config["trajectories"]*config["rounds_per_trajectory"]
    if len(rows) != expected:
        raise RuntimeError("Attempt count mismatch")
    save(folder / "completion.json", {"complete": True, "attempt_rows": len(rows),
                                      "unique_candidates": len({r["candidate_id"] for r in rows})})
    return rows


def trial_body_hash(root):
    source = ast.parse((root / "scripts/proposal/experiment.py").read_text())
    original = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == "run")
    continuation = ast.parse(inspect.getsource(continue_trials)).body[0]
    # Only the initial freeze, controls call, and controls-only branch are omitted.
    prefix = ast.parse("folder = freeze(config, run_id)\ncontrols(config, run_id)\nif controls_only:\n    return\n").body
    require([ast.dump(n) for n in original.body[:3]] == [ast.dump(n) for n in prefix],
            "Frozen runner no longer has the expected explicit control boundary")
    original_body = [ast.dump(n) for n in original.body[3:]]
    require(original_body == [ast.dump(n) for n in continuation.body[1:]],
            "Continuation changed the frozen trial schedule")
    return canonical_sha(original_body)


def base_evidence(root, run_id):
    require(run_id == RUN_ID, "Continuation is restricted to the existing proposal_repeat_v3")
    folder = root / "results" / run_id
    manifest = read(folder / "manifest.json")
    primary = read(root / "results" / PRIMARY_ID / "manifest.json")
    config = read(root / "configs/proposal_experiment.json")
    require(config == manifest["config"] == primary["config"] and config["protocol"] == "proposal_v3",
            "Frozen experiment configuration differs")
    require(config["run_seeds"] == {PRIMARY_ID: 110101, RUN_ID: 210101}, "Declared run identifiers or seeds changed")
    require(manifest["source_hashes"] == primary["source_hashes"], "Primary/repeat source identities differ")
    require(read(root / "results" / PRIMARY_ID / "completion.json")["complete"] is True, "Primary execution is incomplete")
    for name, digest in manifest["source_hashes"].items():
        require(sha(root / name) == sha(folder / "source_snapshot" / name) == digest, "Frozen source changed: " + name)
    controls = read(folder / "controls.json")
    keys = [(r["circuit"], r["label"], r["repeat"]) for r in controls]
    expected = {(c, label, i) for c in ("opamp", "and4") for label in ("clean", "positive") for i in range(5)}
    require(len(keys) == len(set(keys)) == 20 and set(keys) == expected, "Exactly the original 20 controls are required")
    counts = {}
    record_hashes = {}
    for circuit in ("opamp", "and4"):
        counts[circuit] = {label: sum(r["detector"]["is_trojan"] is True for r in controls
                                     if r["circuit"] == circuit and r["label"] == label)
                           for label in ("clean", "positive")}
        require(counts[circuit] == {"clean": 0, "positive": 3}, "Exception requires exactly 0/5 clean and 3/5 positive for both circuits")
    for row in controls:
        rawpath = root / row["detector_record"]
        raw = read(rawpath)
        netlist = (root / row["netlist_path"]).read_text()
        expected_netlist = circuits.render_clean(row["circuit"]) if row["label"] == "clean" else circuits.render(
            row["circuit"], circuits.known_positive_examples(row["circuit"])[0])
        require(netlist == expected_netlist and sha(root / row["netlist_path"]) == row["netlist_sha256"], "Control DUT changed")
        expected_seed = config["run_seeds"][run_id] + 50000 + config["circuits"].index(row["circuit"])*100 + row["repeat"]
        require(row["seed"] == expected_seed and raw["call_id"] in (row["call_id"], row["call_id"] + "_transport_retry1"),
                "Control event identity or seed differs")
        check_raw(raw, config["model"], prompts.detector_messages(row["circuit"], netlist),
                  prompts.DETECTOR_SCHEMA, row["detector"], seed=expected_seed, max_tokens=800)
        record_hashes[row["detector_record"]] = sha(rawpath)
    failure = read(folder / "control_gate_failure.json")
    require(failure == {"circuit": "opamp", "clean_flags": 0, "positive_flags": 3}, "Original failure marker changed")
    return config, {"source_hashes": manifest["source_hashes"], "manifest_sha256": sha(folder / "manifest.json"),
                    "primary_manifest_sha256": sha(root / "results" / PRIMARY_ID / "manifest.json"),
                    "controls_sha256": sha(folder / "controls.json"),
                    "original_failure_sha256": sha(folder / "control_gate_failure.json"),
                    "raw_control_record_sha256": record_hashes, "observed_control_flags": counts,
                    "launcher_sha256": sha(Path(__file__)), "unchanged_trial_body_sha256": trial_body_hash(root)}


def prepare(root, run_id):
    config, evidence = base_evidence(root, run_id)
    folder = root / "results" / run_id
    path = folder / SIDECAR
    if path.exists():
        return verify_deviation(root, run_id)
    attempts = folder / "attempts.json"
    require(not attempts.exists() or not read(attempts), "Deviation must be recorded before repeat attacks")
    require(not list((root / "results/candidates").glob(run_id + "_*.json")), "Repeat candidate events already exist")
    require(not [p for p in (root / "results/api").glob(run_id + "_*.json")
                 if not p.name.startswith(run_id + "_control_")], "Repeat attack API records already exist")
    payload = {"schema": "proposal_control_continuation_v1", "run_id": run_id,
               "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
               "decision_timing": "After the completed primary run and the repeat controls; before any repeat attack requests.",
               "type": "post_control_protocol_deviation", "original_gate_passed": False,
               "original_gate": {"maximum_clean_flags_per_five": 1, "minimum_positive_flags_per_five": 4},
               "decision": "Continue the already declared repeat exactly once without replacing or rerunning its controls.",
               "purpose": "Assess stability with the same frozen model, prompts, menu, seeds, feedback routing, and trial allocation despite variable detector controls.",
               "interpretation_limit": "The continuation rule changed after observing controls. This is a same-settings stability repeat, not an unqualified replication of the original stopping protocol or a passed control gate.",
               "repeat_attack_rows_at_decision": 0, "fixed_attempt_rows": 120, "fixed_candidate_events": 112,
               **evidence}
    sealed = {"deviation": payload, "integrity": {"algorithm": "sha256", "canonical_payload_sha256": canonical_sha(payload),
               "meaning": "Integrity seal binding recorded evidence; not an external author's digital signature."}}
    save(path, sealed)
    return sealed


def verify_deviation(root, run_id):
    _, evidence = base_evidence(root, run_id)
    sealed = read(root / "results" / run_id / SIDECAR)
    payload, integrity = sealed["deviation"], sealed["integrity"]
    require(integrity["algorithm"] == "sha256" and integrity["canonical_payload_sha256"] == canonical_sha(payload),
            "Deviation integrity seal differs")
    require(payload["run_id"] == run_id and payload["schema"] == "proposal_control_continuation_v1"
            and payload["type"] == "post_control_protocol_deviation" and payload["original_gate_passed"] is False
            and payload["repeat_attack_rows_at_decision"] == 0, "Deviation declaration differs")
    require(all(payload[name] == value for name, value in evidence.items()), "Deviation evidence or launcher changed")
    return sealed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, choices=[RUN_ID])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prepare", action="store_true")
    group.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if args.prepare:
        prepare(ROOT, args.run_id)
        print("Recorded explicit failed-control continuation deviation; no API requests made.")
    else:
        sealed = verify_deviation(ROOT, args.run_id)
        print("Continuing despite the retained failed control gate under recorded deviation: "
              + sealed["integrity"]["canonical_payload_sha256"], flush=True)
        continue_trials(read(ROOT / "configs/proposal_experiment.json"), args.run_id)


if __name__ == "__main__":
    main()
