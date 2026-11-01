"""Derive proposal tables/figures from saved evidence, without any API calls."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from scripts.eval.summarize import summarize, write_outputs, make_figures

ROOT = Path(__file__).resolve().parents[2]


def analyze(run_id):
    folder = ROOT / "results" / run_id
    completion = json.loads((folder / "completion.json").read_text())
    if completion.get("complete") is not True:
        raise RuntimeError("Run incomplete")
    manifest = json.loads((folder / "manifest.json").read_text())
    rows = json.loads((folder / "attempts.json").read_text())
    controls = json.loads((folder / "controls.json").read_text())
    config = manifest["config"]
    summary = summarize(rows, controls, config)
    summary["limitations"] = [
        "Adaptive rounds are dependent; attempt-level percentages are descriptive.",
        "The first candidate and judgment are shared across feedback arms within each circuit/start.",
        f"There are only {config['trajectories']} starts per circuit/condition in this run.",
        "None uses independent fresh proposals; binary/full also have preceding-candidate context, as specified in the proposal.",
        "Electrical feasibility of the permitted finite template space was qualified before generation; this is constrained selection, not unrestricted circuit synthesis.",
        "Repeated controls concern four fixed netlists and do not estimate a population false-positive rate or sensitivity.",
        "LATENT reports inserted-component localization evasion, not our whole-netlist valid-attack success rate.",
    ]
    summary["source_sha256"] = {name: hashlib.sha256((folder/name).read_bytes()).hexdigest()
                                for name in ["attempts.json", "controls.json", "manifest.json", "completion.json"]}
    unique = {r["candidate_id"]: r for r in rows}
    summary["distinct_generation_events"] = len(unique)
    summary["valid_generation_events"] = sum(r["simulation"]["valid"] for r in unique.values())
    summary["invalid_reasons"] = dict(Counter(
        "simulation_failure" if not r["simulation"].get("simulation_ok") else
        "normal_behavior" if not r["simulation"].get("normal_ok") else "payload_requirement"
        for r in unique.values() if not r["simulation"]["valid"]))
    summary["parameter_choices"] = {c: {field: dict(Counter(r["parameters"][field] for r in unique.values()
        if r["circuit"] == c and r.get("parameters")))
        for field in ["insertion_site", "representation", "trigger_profile", "strength"]}
        for c in config["circuits"]}
    write_outputs(summary, rows, folder)
    make_figures(summary, config, folder / "figures")
    print(json.dumps({"run_id": run_id, "attempts": len(rows), "actual_candidates": len(unique),
                      "distinct_netlists": summary["unique_netlists"],
                      "groups": [{k:g[k] for k in ["circuit", "feedback", "attempts", "valid", "valid_undetected"]}
                                 for g in summary["groups"]]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    analyze(parser.parse_args().run_id)
