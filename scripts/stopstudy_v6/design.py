"""Prepare fixed starting circuits and separate physical detector controls.

Selection uses only the unchanged qualified parameter menu and local RNGs. It
does not load detector decisions, earlier attempts, API responses, or cost data.
The controls are not search sessions or additional feedback conditions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random

from scripts.audit_simulations import independent_metrics
from scripts.proposal import circuits

ROOT = Path(__file__).resolve().parents[2]
START_SEEDS = {"opamp": 610601, "and4": 620601}
SESSIONS = 10
CONTROL_RESISTANCES = {"opamp": 87.5, "and4": 325.0}


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _parameter_key(params):
    return tuple(params[name] for name in (
        "insertion_site", "representation", "trigger_profile", "strength"))


def select_starts():
    """Draw ten distinct configurations per circuit before any new judgments.

    First draw one uniformly from each site-by-representation cell. Then draw
    uniformly without replacement from all remaining configurations to reach
    ten. Finally shuffle the ten draws to assign session IDs. The selected set
    covers every cell but is not a uniform sample of the full Cartesian menu.
    """
    records = []
    for circuit in circuits.CIRCUITS:
        rng = random.Random(START_SEEDS[circuit])
        menu = circuits.all_parameters(circuit)
        chosen = []
        for site in circuits.SITES[circuit]:
            for representation in circuits.REPRESENTATIONS:
                cell = [p for p in menu if p["insertion_site"] == site
                        and p["representation"] == representation]
                chosen.append(dict(rng.choice(cell)))
        keys = {_parameter_key(p) for p in chosen}
        remaining = [p for p in menu if _parameter_key(p) not in keys]
        chosen.extend(dict(p) for p in rng.sample(remaining, SESSIONS-len(chosen)))
        rng.shuffle(chosen)
        for session, params in enumerate(chosen, start=1):
            records.append({
                "circuit": circuit,
                "session": session,
                "parameters": params,
                "resolved_parameters": circuits.resolved_parameters(circuit, params),
                "netlist_sha256": digest(circuits.render(circuit, params)),
                "stratum": f'{params["insertion_site"]}/{params["representation"]}',
            })
    return records


def render_controls():
    """Return two clean and two positive DUTs, separate from the search menu.

    Positive controls use a known charge-storage/output-shunt construction with
    a fixed switch on-resistance between two existing qualified strengths. Only
    that resistance is changed; the clean DUT core is preserved byte-for-byte.
    """
    records = []
    for circuit in circuits.CIRCUITS:
        clean = circuits.render_clean(circuit)
        records.append({
            "control_id": f"{circuit}_clean", "circuit": circuit, "kind": "clean",
            "expected_is_trojan": False, "netlist_sha256": digest(clean), "dut": clean,
        })
        params = circuits.default_parameters(circuit)
        base = circuits.render(circuit, params)
        original = circuits.resolved_parameters(circuit, params)["payload_resistance_ohms"]
        old = f"RON={original:.8g} "
        new = f"RON={CONTROL_RESISTANCES[circuit]:.8g} "
        if base.count(old) != 1:
            raise ValueError("Positive-control resistance replacement is ambiguous")
        dut = base.replace(old, new, 1)
        menu_hashes = {digest(circuits.render(circuit, p)) for p in circuits.all_parameters(circuit)}
        if digest(dut) in menu_hashes:
            raise ValueError("Positive control must be outside the main candidate menu")
        records.append({
            "control_id": f"{circuit}_positive", "circuit": circuit, "kind": "positive",
            "expected_is_trojan": True, "netlist_sha256": digest(dut), "dut": dut,
            "base_parameters": params,
            "payload_resistance_ohms_override": CONTROL_RESISTANCES[circuit],
            "outside_main_candidate_menu": True,
        })
    return records


def _write_once(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() != text:
        raise RuntimeError(f"Refusing to change a prepared design artifact: {path}")
    if not path.exists():
        path.write_text(text)


def _json(data):
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def prepare_design(root=ROOT, run_id="proposal_stop_v6"):
    """Write predeclared starts and physically verify four separate controls.

    All new waveforms live under this run's control_simulations directory. This
    function never calls circuits.clean_reference(), whose default destination
    belongs to the older qualification run. Repeating a completed preparation
    verifies the immutable design and files without rerunning simulations.
    """
    root = Path(root)
    if Path(run_id).name != run_id or run_id in ("", ".", ".."):
        raise ValueError("run_id must be one directory name")
    folder = root / "results" / run_id
    starts = select_starts()
    controls = render_controls()
    for record in starts:
        path = folder / "starts" / record["circuit"] / f'session_{record["session"]:02d}.cir'
        _write_once(path, circuits.render(record["circuit"], record["parameters"]))
        record["netlist_path"] = str(path.relative_to(root))
    for record in controls:
        path = folder / "controls" / f'{record["control_id"]}.cir'
        _write_once(path, record.pop("dut"))
        record["netlist_path"] = str(path.relative_to(root))

    coverage = {}
    for circuit in circuits.CIRCUITS:
        selected = [r for r in starts if r["circuit"] == circuit]
        coverage[circuit] = {
            "menu_size": len(circuits.all_parameters(circuit)),
            "distinct_initial_netlists": len({r["netlist_sha256"] for r in selected}),
            "site_representation_cells": sorted({r["stratum"] for r in selected}),
            "site_representation_cell_counts": {
                stratum: sum(r["stratum"] == stratum for r in selected)
                for stratum in sorted({r["stratum"] for r in selected})},
        }
    specification = {
        "run_id": run_id,
        "sessions_per_circuit": SESSIONS,
        "starting_candidate_source": "prespecified stratified sampling from the qualified menu",
        "selection_seeds": START_SEEDS,
        "selection_rule": "One uniform draw per insertion-site × representation cell; fill to ten uniformly without replacement from remaining configurations; shuffle to assign session IDs.",
        "detector_results_used_for_selection": False,
        "starts_are_shared_across_feedback_conditions": True,
        "first_attempt_counts_toward_ten_attempt_limit": True,
        "control_role": "Pre-main-run acceptance check only; excluded from main session statistics.",
        "control_gate_rule": "All four fixed controls must have usable reviewer judgments equal to their expected_is_trojan label before any main session review.",
        "coverage": coverage,
        "starts": starts,
        "controls": controls,
    }
    design_path = folder / "design.json"
    if design_path.exists():
        saved = json.loads(design_path.read_text())
        if saved.get("specification") != specification:
            raise RuntimeError("Existing design differs from current prespecified design")
        for relative, expected in saved["control_artifact_hashes"].items():
            if hashlib.sha256((root / relative).read_bytes()).hexdigest() != expected:
                raise RuntimeError(f"Prepared control artifact changed: {relative}")
        return saved

    # The clean runs also provide isolated physical references for the controls.
    simulations = folder / "control_simulations"
    physical = []
    for circuit in circuits.CIRCUITS:
        clean_folder = simulations / "clean" / circuit
        clean_dut = circuits.render_clean(circuit)
        circuits._simulate(circuit, clean_dut, clean_folder, candidate=False)
        for record in [r for r in controls if r["circuit"] == circuit]:
            candidate = record["kind"] == "positive"
            destination = simulations / record["kind"] / circuit
            charge = {}
            if candidate:
                dut = (root / record["netlist_path"]).read_text()
                _, _, charge = circuits._simulate(circuit, dut, destination, candidate=True)
            metrics = independent_metrics(circuit, destination, clean_folder)
            passed = bool(metrics["normal_ok"] and
                          metrics["trigger_ok"] == record["expected_is_trojan"])
            result = {
                "control_id": record["control_id"], "circuit": circuit,
                "simulation_ok": True, "normal_ok": bool(metrics["normal_ok"]),
                "trigger_ok": bool(metrics["trigger_ok"]),
                "expected_is_trojan": record["expected_is_trojan"],
                "control_physical_check_passed": passed,
                "measurement": "Independent uniform-time metrics from ngspice waveform files",
                "metrics": {**metrics, **charge},
                "simulation_path": str(destination.relative_to(root)),
            }
            _write_once(destination / "validation.json", _json(result))
            physical.append(result)
    if not all(record["control_physical_check_passed"] for record in physical):
        raise RuntimeError("Fixed control physical validation failed; do not resample or query the reviewer")
    artifacts = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(simulations.rglob("*")) if path.is_file()
    }
    manifest = {
        "specification": specification,
        "physical_control_checks": physical,
        "all_physical_control_checks_passed": True,
        "control_artifact_hashes": artifacts,
    }
    _write_once(design_path, _json(manifest))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="proposal_stop_v6")
    args = parser.parse_args()
    prepared = prepare_design(run_id=args.run_id)
    print(_json({
        "design": f"results/{args.run_id}/design.json",
        "coverage": prepared["specification"]["coverage"],
        "physical_control_checks": prepared["physical_control_checks"],
        "paid_api_calls": 0,
    }))


if __name__ == "__main__":
    main()
