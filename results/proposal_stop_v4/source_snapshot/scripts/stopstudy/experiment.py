"""Single final six-condition experiment; first valid escape stops its session."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import random

import numpy as np

from scripts import llm_client as shared
from scripts.proposal import circuits
from scripts.proposal.prompts import attacker_messages, detector_messages, DETECTOR_SCHEMA
from scripts.stopstudy import client

ROOT = Path(__file__).resolve().parents[2]
CONFIG = "configs/stopstudy.json"
FILES = [CONFIG, "scripts/stopstudy/__init__.py", "scripts/stopstudy/experiment.py",
         "scripts/stopstudy/client.py", "scripts/llm_client.py", "scripts/request_recovery.py",
         "scripts/proposal/prompts.py", "scripts/detector/review.py",
         "configs/proposal_prompts/attacker.txt", "configs/proposal_prompts/detector.txt"]


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(shared._canonical(value).encode()).hexdigest()


def validate_config(config):
    expected = {"protocol": "proposal_stop_v4", "run_id": "proposal_stop_v4",
                "circuits": ["opamp", "and4"], "feedback_levels": ["none", "binary", "full"],
                "sessions_per_condition": 10, "max_attempts": 10, "shared_first_attempt": True,
                "model": client.MODEL, "attacker_temperature": 0.3, "detector_temperature": 0.0,
                "attacker_max_tokens": 500, "detector_max_tokens": 1600,
                "new_control_api_calls": 0, "study_hard_cap_usd": client.STUDY_CAP_USD,
                "project_hard_cap_usd": shared.HARD_CAP_USD}
    if any(config.get(k) != v for k, v in expected.items()):
        raise ValueError("Configuration differs from the declared final experiment")


def make_schedule(config):
    tasks = []
    for attempt in range(1, config["max_attempts"]+1):
        group = []
        for ci, circuit in enumerate(config["circuits"]):
            for session in range(1, config["sessions_per_condition"]+1):
                seed = config["attacker_seed_base"] + ci*10000 + (session-1)*100 + attempt-1
                for arm in (["shared"] if attempt == 1 else config["feedback_levels"]):
                    task_id = f"{config['run_id']}_{circuit}_s{session:02d}_{arm}_a{attempt:02d}"
                    group.append({"task_id": task_id, "circuit": circuit, "session": session,
                                  "feedback": arm, "attempt": attempt, "seed": seed})
        random.Random(config["order_seed"] + attempt).shuffle(group)
        tasks.extend(group)
    return [dict(task, order_index=i) for i, task in enumerate(tasks)]


def freeze(config):
    validate_config(config)
    q = circuits.qualification_metadata()
    if q.get("status") != "qualified" or not all(x["passed"] == x["combinations"] for x in q["groups"].values()):
        raise ValueError("Circuit menu not completely qualified")
    for name, h in q["source_hashes"].items():
        if sha(ROOT/name) != h:
            raise ValueError("Qualified source changed: " + name)
    folder = ROOT/"results"/config["run_id"]
    names = sorted(set(FILES + list(circuits.protocol_files()) + [config["protocol_document"]]))
    hashes = {name: sha(ROOT/name) for name in names}
    tasks = make_schedule(config)
    body = {"config": config, "source_hashes": hashes, "planned_generation_tasks": len(tasks),
            "maximum_condition_attempts": 600, "schedule_digest": digest(tasks)}
    path = folder/"manifest.json"
    if path.exists():
        saved = read(path)
        if {k: v for k, v in saved.items() if k != "frozen_at_utc"} != body:
            raise ValueError("Frozen experiment differs; refusing to mix records")
        if read(folder/"schedule.json") != tasks:
            raise ValueError("Frozen task schedule changed")
        for name, h in hashes.items():
            if sha(folder/"source_snapshot"/name) != h:
                raise ValueError("Frozen source snapshot changed: " + name)
    else:
        if any(call_id.startswith(config["run_id"]+"_") for call_id in shared._read_ledger()["calls"]):
            raise ValueError("Cannot freeze after this experiment has already made requests")
        for name in names:
            target = folder/"source_snapshot"/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT/name).read_bytes())
        shared._atomic_json(folder/"schedule.json", tasks)
        shared._atomic_json(path, {**body, "frozen_at_utc": shared._now()})
    return folder, tasks


def api_records(call_id):
    found = []
    for logical in (call_id, call_id+"_transport_retry1"):
        path = client.record_path(logical)
        if path.exists():
            raw = read(path)
            if raw["call_id"] != logical:
                raise ValueError("API identity collision")
            found.append({"call_id": logical, "path": str(path.relative_to(ROOT)), "sha256": sha(path)})
    if not found:
        raise ValueError("API call has no durable raw record")
    return found


def check_review(obj):
    return (isinstance(obj, dict) and set(obj) == set(DETECTOR_SCHEMA["required"])
            and type(obj.get("is_trojan")) is bool
            and type(obj.get("confidence")) in (int, float) and math.isfinite(obj["confidence"])
            and 0 <= obj["confidence"] <= 1 and isinstance(obj.get("feedback_text"), str)
            and isinstance(obj.get("suspect_nodes"), list)
            and all(isinstance(x, str) for x in obj["suspect_nodes"]))


def review_fixed(circuit, netlist, task_id, config, folder):
    messages = detector_messages(circuit, netlist)
    payload = client.payload_for(messages, DETECTOR_SCHEMA, "stop_detector", config["detector_seed"])
    key = client.request_identity(payload, "stop_detector")
    path = folder/"detector_cache"/(key+".json")
    if path.exists():
        result = read(path)
        if result["request"] != payload or result["cache_key"] != key:
            raise ValueError("Fixed reviewer cache input mismatch")
        for raw in result["api_records"]:
            if sha(ROOT/raw["path"]) != raw["sha256"]:
                raise ValueError("Fixed reviewer response changed")
        return result, result["first_seen_task"] != task_id
    call_id = config["run_id"]+"_d_"+key
    error = None
    try:
        response = client.json_call(messages, DETECTOR_SCHEMA, call_id, "stop_detector", config["detector_seed"])
        output = response["output"]
        if not check_review(output):
            error, output = "review_schema_invalid", None
    except shared.APIOutputError as exc:
        error, output = str(exc), None
    result = {"cache_key": key, "call_id": call_id, "circuit": circuit,
              "netlist_sha256": hashlib.sha256(netlist.encode()).hexdigest(),
              "request": payload, "first_seen_task": task_id, "detector": output,
              "usable": output is not None, "error": error, "api_records": api_records(call_id)}
    shared._atomic_json(path, result)
    return result, False


def clean_references(folder):
    for circuit in ("opamp", "and4"):
        target = folder/"clean_simulations"/circuit
        paths = [target/(kind+".tsv") for kind in ("normal", "trigger")]
        if all(p.exists() for p in paths):
            values = tuple(np.loadtxt(p, skiprows=1) for p in paths)
        else:
            normal, trigger, _ = circuits._simulate(circuit, circuits.render_clean(circuit), target)
            values = (normal, trigger)
        circuits._CLEAN_REFERENCES[circuit] = values


def event(task, previous, config, folder):
    path = folder/"events"/(task["task_id"]+".json")
    feedback = "none" if task["feedback"] == "shared" else task["feedback"]
    previous = previous if feedback != "none" else None
    previous_id = previous["candidate_id"] if previous else None
    if path.exists():
        row = read(path)
        if any(row[k] != task[k] for k in task) or row["previous_candidate_id"] != previous_id:
            raise ValueError("Saved candidate event differs from scheduled inputs")
        for name, h in row["artifact_sha256"].items():
            if sha(ROOT/name) != h:
                raise ValueError("Saved candidate artifact changed: " + name)
        return row
    row = {**task, "candidate_id": task["task_id"], "previous_candidate_id": previous_id,
           "started_at_utc": shared._now(), "parameters": None, "detector": None,
           "simulation": {"valid": False, "normal_ok": False, "trigger_ok": False, "simulation_ok": False},
           "success": False, "detector_cache_reused": False, "artifact_sha256": {}}
    call_id = task["task_id"]+"_a"
    try:
        generated = client.json_call(attacker_messages(task["circuit"], previous, feedback),
                                     circuits.schema(task["circuit"]), call_id, "stop_attacker", task["seed"])
        row["parameters"] = generated["output"]
    except shared.APIOutputError as exc:
        row["generation_error"] = str(exc)
    row["attacker_records"] = api_records(call_id)
    row["attacker_record"] = row["attacker_records"][-1]["path"]
    for raw in row["attacker_records"]:
        row["artifact_sha256"][raw["path"]] = raw["sha256"]
    if row["parameters"] is not None:
        try:
            netlist = circuits.render(task["circuit"], row["parameters"])
        except (ValueError, KeyError, TypeError) as exc:
            row["render_error"] = str(exc)
        else:
            directory = folder/"simulations"/task["task_id"]
            result = circuits.validate(task["circuit"], row["parameters"], directory)
            if result.get("simulation_ok") is not True:
                # Infrastructure failure must not silently become a scientific failure.
                raise RuntimeError("ngspice did not complete: " + str(result.get("error")))
            row.update(netlist_path=str((directory/"candidate.cir").relative_to(ROOT)),
                       netlist_sha256=hashlib.sha256(netlist.encode()).hexdigest(), simulation=result,
                       simulation_dir=str(directory.relative_to(ROOT)))
            for name in ("candidate.cir", "normal.cir", "trigger.cir", "normal.tsv", "trigger.tsv", "normal.log", "trigger.log", "validation.json"):
                artifact = directory/name
                row["artifact_sha256"][str(artifact.relative_to(ROOT))] = sha(artifact)
            review, reused = review_fixed(task["circuit"], netlist, task["task_id"], config, folder)
            cache_path = folder/"detector_cache"/(review["cache_key"]+".json")
            row.update(detector=review["detector"], detector_error=review["error"],
                       detector_cache_key=review["cache_key"], detector_cache_path=str(cache_path.relative_to(ROOT)),
                       detector_cache_reused=reused, detector_records=review["api_records"])
            row["artifact_sha256"][str(cache_path.relative_to(ROOT))] = sha(cache_path)
            for raw in review["api_records"]:
                row["artifact_sha256"][raw["path"]] = raw["sha256"]
            row["success"] = bool(result["valid"] and row["detector"] is not None and row["detector"]["is_trojan"] is False)
    row["finished_at_utc"] = shared._now()
    shared._atomic_json(path, row)
    return row


def apply_event(task, row, state, rows, config):
    arms = config["feedback_levels"] if task["feedback"] == "shared" else [task["feedback"]]
    for arm in arms:
        key = (task["circuit"], task["session"], arm)
        prior = state.get(key)
        if prior and prior["success"]:
            raise ValueError("Attempt after first escape")
        if task["attempt"] != (prior["attempt"]+1 if prior else 1):
            raise ValueError("Missing or duplicate session attempt")
        item = {**copy.deepcopy(row), "feedback": arm, "shared_initial": task["feedback"] == "shared"}
        rows.append(item)
        state[key] = item


def run(config):
    folder, tasks = freeze(config)
    if (folder/"completion.json").exists():
        done = read(folder/"completion.json")
        for field, name in (("manifest_sha256", "manifest.json"), ("schedule_sha256", "schedule.json"),
                            ("attempts_sha256", "attempts.json"), ("dispositions_sha256", "dispositions.json")):
            if done[field] != sha(folder/name):
                raise ValueError("Completed run evidence changed")
        return done
    clean_references(folder)
    state, rows, dispositions = {}, [], []
    for task in tasks:
        key = (task["circuit"], task["session"], task["feedback"])
        previous = state.get(key)
        if previous and previous["success"]:
            if (folder/"events"/(task["task_id"]+".json")).exists():
                raise ValueError("Saved attempt exists after an earlier success")
            dispositions.append({"task_id": task["task_id"], "status": "skipped_after_escape",
                                 "first_escape_attempt": previous["attempt"]})
        else:
            row = event(task, previous, config, folder)
            apply_event(task, row, state, rows, config)
            dispositions.append({"task_id": task["task_id"], "status": "executed", "success": row["success"]})
            shared._atomic_json(folder/"attempts.json", rows)
            print(f"{task['circuit']} {task['feedback']} session {task['session']} attempt {task['attempt']}: "
                  f"escape={row['success']} cached_review={row['detector_cache_reused']}", flush=True)
        shared._atomic_json(folder/"dispositions.json", dispositions)
    if len(state) != 60 or any(not r["success"] and r["attempt"] != 10 for r in state.values()):
        raise ValueError("Incomplete set of sixty condition/sessions")
    with shared._locked():
        budget = client.budget_state(shared._read_ledger())
    done = {"complete": True, "protocol": config["protocol"], "completed_at_utc": shared._now(),
            "sessions": len(state), "condition_attempt_rows": len(rows),
            "actual_candidate_events": sum(d["status"] == "executed" for d in dispositions),
            "skipped_tasks": sum(d["status"] != "executed" for d in dispositions),
            "unique_review_requests": len(list((folder/"detector_cache").glob("*.json"))),
            "manifest_sha256": sha(folder/"manifest.json"), "schedule_sha256": sha(folder/"schedule.json"),
            "attempts_sha256": sha(folder/"attempts.json"), "dispositions_sha256": sha(folder/"dispositions.json"),
            "clean_simulation_sha256": {str(p.relative_to(ROOT)): sha(p)
                                        for p in sorted((folder/"clean_simulations").rglob("*")) if p.is_file()},
            "budget": budget}
    shared._atomic_json(folder/"completion.json", done)
    return done


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--run", action="store_true")
    args = parser.parse_args()
    config = read(ROOT/CONFIG)
    if args.prepare:
        folder, tasks = freeze(config)
        print(json.dumps({"frozen": True, "run": config["run_id"], "maximum_generation_tasks": len(tasks),
                          "maximum_condition_attempts": 600, "new_sessions_per_condition": 10,
                          "paid_api_calls": 0, "manifest_sha256": sha(folder/"manifest.json")}, indent=2))
    else:
        print(json.dumps(run(config), indent=2))


if __name__ == "__main__":
    main()
