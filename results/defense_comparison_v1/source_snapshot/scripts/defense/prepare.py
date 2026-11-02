"""Prepare fixed DUTs and neutral normal-operation summaries, without API calls.

Run once before freezing the supplemental comparison:
    python -m scripts.defense.prepare
Check the generic parser and summary interface without simulations:
    python -m scripts.defense.prepare --self-test
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

import numpy as np

from scripts.sim import benchmark

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "defense_comparison_v1"
RUN_IDS = ("proposal_main_v3", "proposal_repeat_v3")
OUTPUT = ROOT / "results" / PROTOCOL
# Node counts of supported primitive device terminal lists. Unknown devices fail
# explicitly rather than silently omitting nodes. No node identifier is special.
TERMINAL_COUNTS = {"R": 2, "C": 2, "L": 2, "D": 2, "V": 2, "I": 2,
                   "B": 2, "M": 4, "S": 4, "E": 4, "G": 4, "F": 2, "H": 2, "J": 3}


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return sha_bytes(path.read_bytes())


def read(path):
    return json.loads(path.read_text())


def relative(path):
    return str(path.relative_to(ROOT))


def logical_lines(text):
    lines = []
    for raw in text.splitlines():
        line = re.split(r"[;$]", raw.strip(), maxsplit=1)[0].strip()
        if not line or line.startswith("*"):
            continue
        if line.startswith("+"):
            if not lines:
                raise ValueError("SPICE continuation without preceding statement")
            lines[-1] += " " + line[1:].strip()
        else:
            lines.append(line)
    return lines


def internal_nodes(netlist):
    """Collect all primitive-terminal nodes inside dut, excluding its ports/0."""
    active = False
    found = False
    ports = set()
    nodes = set()
    for line in logical_lines(netlist):
        tokens = line.split()
        command = tokens[0].lower()
        if command == ".subckt":
            if active:
                raise ValueError("Nested subcircuits are outside this corpus parser")
            if len(tokens) > 1 and tokens[1].lower() == "dut":
                if found:
                    raise ValueError("Duplicate dut subcircuit")
                active = found = True
                for token in tokens[2:]:
                    if token.lower() == "params:" or "=" in token:
                        break
                    ports.add(token.lower())
            continue
        if command == ".ends":
            active = False
            continue
        if not active or command.startswith("."):
            continue
        device = tokens[0][0].upper()
        if device not in TERMINAL_COUNTS:
            raise ValueError(f"Unsupported DUT device terminal grammar: {tokens[0]}")
        count = TERMINAL_COUNTS[device]
        if len(tokens) < count + 2:
            raise ValueError(f"Incomplete terminal list: {tokens[0]}")
        nodes.update(token.lower() for token in tokens[1:count + 1])
    if not found or active:
        raise ValueError("Missing or unterminated dut subcircuit")
    return sorted(nodes - ports - {"0"})


def measurement_deck(circuit, netlist):
    nodes = internal_nodes(netlist)
    if circuit == "opamp":
        external = ["inp", "out"]
        deck = benchmark._op_normal(netlist, "normal")
    elif circuit == "and4":
        external = ["a", "b", "c", "d", "out"]
        deck = benchmark._and_normal(netlist, "normal")
    else:
        raise ValueError("Unknown circuit")
    vectors = [f"v({node})" for node in external]
    vectors += [f"v(x1.{node})" for node in nodes] + ["i(vdd)"]
    deck, count = re.subn(r"^wrdata normal\.tsv .*$", "wrdata normal.tsv " + " ".join(vectors), deck, flags=re.M)
    if count != 1:
        raise ValueError("Normal testbench has no unique measurement statement")
    return deck, external, nodes


def number(value):
    value = float(value)
    if not np.isfinite(value):
        raise ValueError("Nonfinite measurement")
    rounded = float(f"{value:.7g}")
    return 0.0 if rounded == 0 else rounded


def stats(values):
    return {"min": number(np.min(values)), "max": number(np.max(values)), "mean": number(np.mean(values))}


def summarize(circuit, data, external, nodes):
    """Only normal trace values and the declared normal input enter this function."""
    if data.ndim != 2 or data.shape[1] != len(external) + len(nodes) + 2:
        raise ValueError("Trace columns do not match declared probes")
    if not np.isfinite(data).all() or np.any(np.diff(data[:, 0]) < 0):
        raise ValueError("Invalid trace values or time ordering")
    if circuit == "opamp":
        start_us, stop_us, step_ns = 20.0, 200.0, 100.0
        sample_us = np.arange(20.0, 200.01, 20.0)
        stimulus = "3.3 V supply; unity-follower connection; input 1.65 V + 0.05 V sin(2*pi*10 kHz*t); duration 200 us."
    elif circuit == "and4":
        start_us, stop_us, step_ns = 1.0, 360.0, 10.0
        sample_us = (np.arange(16) + 1) * 20.0 + 10.0
        stimulus = "3.3 V supply; inputs enumerate integer 0..15 with a as the least significant bit, one vector every 20 us from t=20 us; 100 ps edges; all inputs reset to 0 at 340 us; duration 360 us."
    else:
        raise ValueError("Unknown circuit")
    count = int(round((stop_us - start_us) * 1000 / step_ns)) + 1
    grid = start_us * 1e-6 + np.arange(count) * step_ns * 1e-9
    if data[0, 0] > grid[0] or data[-1, 0] < grid[-1] - 1e-14:
        raise ValueError("Trace does not cover the summary window")
    signals = np.array([np.interp(grid, data[:, 0], data[:, index])
                        for index in range(1, data.shape[1])]).T
    result = {
        "schema": "normal_operation_v1", "stimulus": stimulus,
        "statistics_sampling": {"method": "linear interpolation onto a uniform time grid; arithmetic statistics on grid values",
                                "start_us": start_us, "stop_us": stop_us, "step_ns": step_ns, "points": count},
        "external_voltage_V": {node: stats(signals[:, index]) for index, node in enumerate(external)},
        "internal_voltage_V": {node: stats(signals[:, len(external) + index]) for index, node in enumerate(nodes)},
        "supply_current_A": {"reference": "i(VDD); positive current enters the voltage source positive terminal",
                             **stats(signals[:, -1])},
        "normal_samples": {"columns": ["time_us", *[node + "_V" for node in external]],
                           "rows": [[number(time_us), *[number(np.interp(time_us * 1e-6, data[:, 0], data[:, index + 1]))
                                                         for index in range(len(external))]] for time_us in sample_us]},
    }
    if circuit == "opamp":
        error = signals[:, external.index("out")] - signals[:, external.index("inp")]
        result["follower_error_V"] = {"definition": "output minus input on the uniform grid",
                                       "mean": number(np.mean(error)), "max_abs": number(np.max(abs(error))),
                                       "rmse": number(np.sqrt(np.mean(error ** 2)))}
    return result


def self_test():
    fixture = """* neutral terminal parsing fixture
.subckt dut inp out vdd vss
M9 out gate vss vss NM W=2u L=1u
C7 inp coupler 1p
D7 coupler memory DM
R7 memory vss 2meg
B9 gate vss V={v(memory,vss)}
S7 out vss control vss SWM
R8 control memory 1meg
.ends dut
.model NM NMOS
"""
    assert internal_nodes(fixture) == ["control", "coupler", "gate", "memory"]
    clean_fixture = ".subckt dut inp out vdd vss\nR1 inp out 1k\n.ends dut\n"
    assert internal_nodes(clean_fixture) == []
    time = np.linspace(0, 200e-6, 2001)
    inp = 1.65 + .05 * np.sin(2 * np.pi * 1e4 * time)
    for nodes in ([], ["arbitrary_node"]):
        columns = [time, inp, inp + .001] + [np.full_like(time, .4) for _ in nodes] + [np.full_like(time, -.0003)]
        result = summarize("opamp", np.array(columns).T, ["inp", "out"], nodes)
        assert result["follower_error_V"]["rmse"] == .001
        assert result["supply_current_A"]["mean"] == -.0003
        text = json.dumps(result).lower()
        assert not any(word in text for word in ("trojan", "label", "trigger", "golden", "netlist_path", "candidate_id", "added_node"))
        if not nodes:
            clean_keys = set(result)
        else:
            assert set(result) == clean_keys
    # Nonuniform saved samples must be resampled, rather than equally weighted.
    data = np.array([[0, 1, 1, 0], [20e-6, 1, 1, 0], [199e-6, 1, 1, 1], [200e-6, 1, 1, 1]], dtype=float)
    result = summarize("opamp", data, ["inp", "out"], [])
    assert abs(result["supply_current_A"]["mean"] - .5028) < .001
    return {"generic_terminal_parser": True, "neutral_summary_fields": True,
            "same_schema_for_clean_and_extended_dut": True, "uniform_grid_statistics": True}


def collect():
    sources = {relative(Path(__file__).resolve()): sha(Path(__file__).resolve()),
               "scripts/defense/__init__.py": sha(ROOT / "scripts/defense/__init__.py"),
               "scripts/sim/benchmark.py": sha(ROOT / "scripts/sim/benchmark.py")}
    cases = {}
    candidate_ids = set()
    for run_id in RUN_IDS:
        manifest_path = ROOT / "results" / run_id / "manifest.json"
        manifest = read(manifest_path)
        if manifest["source_hashes"]["scripts/sim/benchmark.py"] != sources["scripts/sim/benchmark.py"]:
            raise ValueError("Normal-stimulus source differs from frozen experiment")
        sources[relative(manifest_path)] = sha(manifest_path)
        for kind, filename in (("candidate", "attempts.json"), ("control", "controls.json")):
            path = ROOT / "results" / run_id / filename
            sources[relative(path)] = sha(path)
            for row in read(path):
                name, digest = row["netlist_path"], row["netlist_sha256"]
                payload = (ROOT / name).read_bytes()
                if sha_bytes(payload) != digest:
                    raise ValueError("Original netlist hash mismatch: " + name)
                sources[name] = digest
                if kind == "candidate":
                    if row["simulation"]["valid"] is not True:
                        raise ValueError("Observed candidate is not electrically validated")
                    label = "trojan"
                    candidate_ids.add(row["candidate_id"])
                    membership = {"kind": kind, "run_id": run_id, "candidate_id": row["candidate_id"],
                                  "feedback": row["feedback"], "trajectory": row["trajectory"], "round": row["round"]}
                else:
                    label = "clean" if row["label"] == "clean" else "trojan"
                    if label == "trojan" and row["validation"]["valid"] is not True:
                        raise ValueError("Known positive control lacks electrical validation")
                    membership = {"kind": kind, "run_id": run_id, "control_label": row["label"],
                                  "repeat": row["repeat"], "call_id": row["call_id"]}
                if digest not in cases:
                    cases[digest] = {"case_id": digest[:16], "circuit": row["circuit"], "netlist_sha256": digest,
                                     "label": label, "memberships": [], "original_netlist_path": name}
                case = cases[digest]
                if case["circuit"] != row["circuit"] or case["label"] != label:
                    raise ValueError("Conflicting ground-truth/circuit metadata for identical netlist")
                case["memberships"].append(membership)
    if len(cases) != 33 or len(candidate_ids) != 224 or len({case["case_id"] for case in cases.values()}) != 33:
        raise ValueError("Expected 33 unique DUTs and 224 original candidate events")
    return sorted(cases.values(), key=lambda case: (case["circuit"], case["case_id"])), sources


def prepare():
    checks = self_test()
    corpus_path = OUTPUT / "corpus.json"
    if corpus_path.exists():
        raise ValueError("Prepared corpus already exists; audit it rather than overwrite frozen evidence")
    cases, sources = collect()
    for index, case in enumerate(cases, 1):
        folder = OUTPUT / "corpus" / case["case_id"]
        folder.mkdir(parents=True, exist_ok=True)
        payload = (ROOT / case["original_netlist_path"]).read_bytes()
        (folder / "dut.cir").write_bytes(payload)
        netlist = payload.decode("utf-8")
        deck, external, nodes = measurement_deck(case["circuit"], netlist)
        data, headers = benchmark._run(deck, folder, "normal")
        summary = summarize(case["circuit"], data, external, nodes)
        summary_text = json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        (folder / "summary.json").write_text(summary_text + "\n")
        case.update(netlist_path=relative(folder / "dut.cir"), summary_text=summary_text,
                    summary_sha256=sha_bytes(summary_text.encode("utf-8")),
                    normal_simulation={"deck_path": relative(folder / "normal.cir"),
                                       "log_path": relative(folder / "normal.log"),
                                       "trace_path": relative(folder / "normal.tsv"),
                                       "summary_path": relative(folder / "summary.json"),
                                       "probe_nodes": nodes, "external_nodes": external, "trace_headers": headers,
                                       "sha256": {relative(folder / name): sha(folder / name)
                                                  for name in ("dut.cir", "normal.cir", "normal.log", "normal.tsv", "summary.json")}})
        print(f"Prepared {index}/{len(cases)}: {case['circuit']} {case['case_id']} ({len(nodes)} internal nodes)", flush=True)
    counts = {"unique_cases": len(cases), "by_circuit": dict(Counter(case["circuit"] for case in cases)),
              "by_label": dict(Counter(case["label"] for case in cases)),
              "observed_candidate_netlists": sum(any(m["kind"] == "candidate" for m in case["memberships"]) for case in cases),
              "control_netlists": sum(any(m["kind"] == "control" for m in case["memberships"]) for case in cases),
              "historical_candidate_rows": sum(m["kind"] == "candidate" for case in cases for m in case["memberships"]),
              "historical_control_rows": sum(m["kind"] == "control" for case in cases for m in case["memberships"])}
    corpus = {"protocol": PROTOCOL, "source_sha256": dict(sorted(sources.items())), "cases": cases, "counts": counts,
              "paid_api_calls": 0, "normal_simulations": len(cases), "self_checks": checks,
              "summary_text_encoding": "UTF-8 compact sorted-key JSON without trailing newline; summary_sha256 hashes exactly summary_text",
              "summary_protocol": {"stimuli": "Unchanged benchmark._op_normal and benchmark._and_normal; measurement vectors extended only",
                                   "node_selection": "Every supported primitive terminal in dut, minus dut ports and node0; sorted case-insensitive identifiers; unknown device grammars rejected",
                                   "current_selection": "i(VDD) for every case",
                                   "statistics": "Linear interpolation to the explicit uniform grid; no adaptive-point-weighted means",
                                   "normal_inputs_only": True, "golden_reference_features": False,
                                   "classification_metadata_in_summary": False},
              "simulator": {"binary_sha256": sha(Path(benchmark._binary()))}}
    corpus_path.write_text(json.dumps(corpus, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps({"corpus": relative(corpus_path), "sha256": sha(corpus_path), "counts": counts}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), indent=2))
    else:
        prepare()


if __name__ == "__main__":
    main()
