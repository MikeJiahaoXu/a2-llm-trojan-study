"""Supplement: stronger attacker against the unchanged baseline reviewer.

The original prompt builder is injected with a different API backend in this
separate process. Frozen baseline files and completed records are not edited.
"""
import argparse
import copy
import hashlib
import json
import random
import importlib
from functools import partial
from pathlib import Path

from scripts.attacker.propose import propose
from scripts.detector.review import review
from scripts.llm_client import APIOutputError
from scripts.model_client import json_call as model_call
from scripts.sim.benchmark import (render_candidate, render_clean,
                                   validate_candidate, default_parameters)

ROOT = Path(__file__).resolve().parents[2]

def save(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(obj, indent=2, allow_nan=False) + "\n")
    temp.replace(path)

def check_output(result):
    output = result["output"]
    return output

def candidate(circuit, call_id, seed, previous=None, feedback="none"):
    target = ROOT / "results/candidates" / (call_id + ".json")
    if target.exists():
        return json.loads(target.read_text())
    try:
        generation = propose(circuit, call_id + "_a", seed, previous, feedback)
    except APIOutputError as exc:
        result = {"candidate_id": call_id, "circuit": circuit, "parameters": None,
                  "attacker_call_id": call_id + "_a", "prompt_version": "attacker_v1_detector_v2",
                  "simulation": {"valid": False, "normal_ok": False, "trigger_ok": False},
                  "detector": None, "detector_negative": False, "success": False,
                  "generation_error": str(exc)}
        save(target, result)
        return result
    params = check_output(generation)
    result = {"candidate_id": call_id, "circuit": circuit, "parameters": params,
              "attacker_call_id": call_id + "_a", "prompt_version": "attacker_v1_detector_v2",
              "attacker_record": generation['record_path']}
    try:
        netlist = render_candidate(circuit, params)
    except (ValueError, TypeError, KeyError) as exc:
        result.update(simulation={"valid": False, "normal_ok": False,
                                  "trigger_ok": False, "error": str(exc)},
                      detector=None, success=False, detector_negative=False)
        save(target, result)
        return result
    netpath = ROOT / "netlists/generated" / (call_id + ".cir")
    netpath.parent.mkdir(parents=True, exist_ok=True)
    netpath.write_text(netlist)
    simulation = validate_candidate(circuit, params, ROOT / "results/simulations" / call_id)
    try:
        response = review(circuit, netlist, call_id + "_d", seed + 100000)
        detection = check_output(response)
    except APIOutputError as exc:
        result.update(netlist_path=str(netpath.relative_to(ROOT)), simulation=simulation,
                      netlist_sha256=hashlib.sha256(netlist.encode()).hexdigest(),
                      detector=None, detector_call_id=call_id + "_d", detector_error=str(exc),
                      detector_negative=False, success=False)
        save(target, result)
        return result
    if not isinstance(detection.get("is_trojan"), bool) or not 0 <= detection["confidence"] <= 1:
        raise ValueError("Invalid detector output: " + call_id)
    result.update(netlist_path=str(netpath.relative_to(ROOT)),
                  netlist_sha256=hashlib.sha256(netlist.encode()).hexdigest(),
                  simulation=simulation, detector=detection, detector_call_id=call_id + "_d",
                  detector_record=response['record_path'],
                  detector_negative=not detection["is_trojan"],
                  success=bool(simulation["valid"] and not detection["is_trojan"]))
    save(target, result)
    return result

def controls(config, run_id):
    rows = []
    for circuit in config["circuits"]:
        params = default_parameters(circuit)
        validation = validate_candidate(circuit, params, ROOT / "results/controls" / circuit)
        if not validation["valid"]:
            raise RuntimeError("Positive control failed physical validation: " + circuit)
        for label, netlist in [("clean", render_clean(circuit)),
                               ("positive", render_candidate(circuit, params))]:
            for repeat in range(5):
                call_id = f"{run_id}_control_{circuit}_{label}_{repeat}"
                response = review(circuit, netlist, call_id, 5100 + repeat)
                rows.append({"circuit": circuit, "label": label, "repeat": repeat,
                             "call_id": call_id, "detector": check_output(response),
                             "validation": validation if label == "positive" else None})
                save(ROOT / "results" / run_id / "controls.json", rows)
                print(f"control {circuit} {label} {repeat+1}/5", flush=True)
    return rows

def run(config, run_id):
    importlib.import_module('scripts.attacker.propose').json_call = partial(
        model_call, model=config['attacker_model'])
    destination = ROOT / "results" / run_id
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {"config": config, "run_id": run_id,
                "prompt_hashes": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in sorted((ROOT / "configs/prompts").glob("*.txt"))},
                "source_hashes": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in [ROOT / name for name in [
                                      "scripts/llm_client.py", "scripts/model_client.py", "scripts/request_recovery.py", "scripts/attacker/propose.py",
                                      "scripts/detector/review.py", "scripts/eval/run_loop.py",
                                      "scripts/eval/run_stronger.py",
                                      "scripts/sim/benchmark.py", "netlists/templates/opamp.cir",
                                      "netlists/templates/and4.cir"]]}}
    manifest_path = destination / "manifest.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise RuntimeError("Run configuration changed; use a new explicit run id.")
    save(manifest_path, manifest)
    control_rows = controls(config, run_id)
    for circuit in config['circuits']:
        false_flags = sum(r['detector']['is_trojan'] for r in control_rows if r['circuit']==circuit and r['label']=='clean')
        true_flags = sum(r['detector']['is_trojan'] for r in control_rows if r['circuit']==circuit and r['label']=='positive')
        if false_flags > 1 or true_flags < 4:
            save(destination / 'control_gate_failure.json', {'circuit':circuit, 'clean_flags':false_flags, 'positive_flags':true_flags})
            raise RuntimeError('Control gate failed; no formal attack trials started.')
    rows, state = [], {}
    tasks = [(c, t) for c in config["circuits"] for t in range(config["trajectories"])]
    random.Random(config["base_seed"]).shuffle(tasks)
    for c, t in tasks:
        seed = config["base_seed"] + config["circuits"].index(c) * 1000 + t * 10
        result = candidate(c, f"{run_id}_{c}_t{t}_shared_r0", seed)
        for level in config["feedback_levels"]:
            state[c, t, level] = result
            rows.append(dict(copy.deepcopy(result), feedback=level, trajectory=t, round=0,
                             shared_initial=True, seed=seed))
        save(destination / "attempts.json", rows)
        print(f"initial {c} trajectory {t+1}: valid={result['simulation']['valid']} success={result['success']}", flush=True)
    for round_number in range(1, config["rounds_per_trajectory"]):
        tasks = [(c,t,l) for c in config["circuits"] for t in range(config["trajectories"])
                 for l in config["feedback_levels"]]
        random.Random(config["base_seed"] + round_number).shuffle(tasks)
        for c, t, level in tasks:
            seed = config["base_seed"] + config["circuits"].index(c)*1000 + t*10 + round_number
            result = candidate(c, f"{run_id}_{c}_t{t}_{level}_r{round_number}", seed,
                               state[c, t, level], level)
            state[c, t, level] = result
            rows.append(dict(copy.deepcopy(result), feedback=level, trajectory=t,
                             round=round_number, shared_initial=False, seed=seed))
            save(destination / "attempts.json", rows)
            print(f"{c} {level} trajectory {t+1} round {round_number+1}: valid={result['simulation']['valid']} success={result['success']}", flush=True)
    save(destination / "completion.json", {"complete": True, "attempt_rows": len(rows),
         "unique_candidates": len({r["candidate_id"] for r in rows})})
    return rows

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/stronger_experiment.json")
    parser.add_argument("--run-id", default="strong_attacker_v1")
    args = parser.parse_args()
    run(json.loads((ROOT / args.config).read_text()), args.run_id)

if __name__ == "__main__":
    main()
