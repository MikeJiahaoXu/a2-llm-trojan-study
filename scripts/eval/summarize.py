"""Summarize real experiment records without treating adaptive rounds as IID.

Run: python -m scripts.eval.summarize --run-id main_v2
The default refuses incomplete runs. No model calls or simulation runs occur.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[2]
LEVELS = ("none", "binary", "full")
CIRCUIT_LABELS = {"opamp": "Two-stage op-amp", "and4": "Four-input AND gate"}


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _mean(values):
    return statistics.mean(values) if values else None


def wilson95(successes, trials):
    """Use only for independent trajectory starts, never adaptive attempts."""
    if trials == 0:
        return [None, None]
    z = 1.959963984540054
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    half = z * math.sqrt(p * (1-p) / trials + z*z / (4*trials*trials)) / denominator
    return [max(0.0, center-half), min(1.0, center+half)]


def _valid(row):
    return row.get("simulation", {}).get("valid") is True


def _negative(row):
    return (row.get("detector") or {}).get("is_trojan") is False


def _success(row):
    return _valid(row) and _negative(row)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _trajectory_summary(rows, total_rounds):
    trials = {}
    for row in rows:
        trials.setdefault(row["trajectory"], []).append(row)
    successes = sum(any(_success(r) for r in trial) for trial in trials.values())
    cumulative = []
    for round_index in range(total_rounds):
        # In complete runs this denominator is five at every round. In a partial
        # run only starts observed through this round belong in its denominator.
        eligible = [trial for trial in trials.values()
                    if {r["round"] for r in trial}.issuperset(range(round_index+1))]
        count = sum(any(_success(r) and r["round"] <= round_index for r in trial)
                    for trial in eligible)
        cumulative.append({"round": round_index+1, "successful_trajectories": count,
                           "trajectories": len(eligible), "rate": _ratio(count, len(eligible))})
    return trials, successes, cumulative


def _group(rows, circuit, level, total_rounds):
    n = len(rows)
    valid = sum(_valid(r) for r in rows)
    success = sum(_success(r) for r in rows)
    reviewed = [r for r in rows if isinstance((r.get("detector") or {}).get("is_trojan"), bool)]
    detected = sum(r["detector"]["is_trojan"] for r in reviewed)
    confidence = [r["detector"]["confidence"] for r in reviewed
                  if isinstance(r["detector"].get("confidence"), (int, float))]
    trials, any_success, cumulative = _trajectory_summary(rows, total_rounds)
    complete_trials = [trial for trial in trials.values()
                       if {r["round"] for r in trial} == set(range(total_rounds))]
    complete_success = sum(any(_success(r) for r in trial) for trial in complete_trials)
    return {
        "circuit": circuit, "feedback": level, "attempts": n,
        "valid": valid, "invalid": n-valid, "valid_undetected": success,
        "valid_detected": sum(_valid(r) and (r.get("detector") or {}).get("is_trojan") is True for r in rows),
        "valid_unreviewed": sum(_valid(r) and not isinstance((r.get("detector") or {}).get("is_trojan"), bool) for r in rows),
        "detector_reviewed": len(reviewed), "detector_detected": detected,
        "detector_unreviewed": n-len(reviewed),
        "generation_output_failures": sum(bool(r.get("generation_error")) for r in rows),
        "detector_output_failures": sum(bool(r.get("detector_error")) for r in rows),
        "primary_rate": _ratio(success, n),
        "conditional_evasion_rate": _ratio(success, valid),
        "valid_fraction": _ratio(valid, n),
        "detected_fraction_all_attempts": _ratio(detected, n),
        "detected_fraction_reviewed": _ratio(detected, len(reviewed)),
        "confidence_mean": _mean(confidence), "confidence_count": len(confidence),
        "unique_parameters": len({_canonical(r["parameters"]) for r in rows if r.get("parameters") is not None}),
        "unique_netlists": len({r["netlist_sha256"] for r in rows if r.get("netlist_sha256")}),
        "unique_candidates": len({r["candidate_id"] for r in rows}),
        "trajectory_starts": len(trials), "trajectory_any_success": any_success,
        "trajectory_any_success_rate": _ratio(any_success, len(trials)),
        "complete_trajectories": len(complete_trials),
        "complete_trajectory_successes": complete_success,
        "trajectory_wilson95": wilson95(complete_success, len(complete_trials)),
        "cumulative_by_round": cumulative,
    }


def _control_summary(controls, circuits):
    summaries = []
    for circuit, label in itertools.product(circuits, ("clean", "positive")):
        selected = [r for r in controls if r["circuit"] == circuit and r["label"] == label]
        detected = sum(r["detector"]["is_trojan"] is True for r in selected)
        summaries.append({"circuit": circuit, "label": label, "judgments": len(selected),
                          "flagged": detected, "flagged_fraction": _ratio(detected, len(selected)),
                          "confidence_mean": _mean([r["detector"]["confidence"] for r in selected]),
                          "unit": "repeated judgments of one fixed netlist",
                          "interpretation": ("clean-control repeat flag frequency; not a population FPR"
                                             if label == "clean" else
                                             "positive-control repeat detection frequency; not population sensitivity")})
    return summaries


def _paired_comparisons(rows, circuits, levels, total_rounds):
    result = []
    index = {}
    for row in rows:
        index.setdefault((row["circuit"], row["trajectory"], row["feedback"]), []).append(row)
    for left, right in itertools.combinations(levels, 2):
        for scope in [*circuits, "pooled"]:
            pairs = []
            for circuit, trajectory in sorted({(r["circuit"], r["trajectory"]) for r in rows}):
                if scope != "pooled" and scope != circuit:
                    continue
                a = index.get((circuit, trajectory, left), [])
                b = index.get((circuit, trajectory, right), [])
                if not all({r["round"] for r in arm} == set(range(total_rounds)) for arm in (a, b)):
                    continue
                a_any, b_any = any(_success(r) for r in a), any(_success(r) for r in b)
                pairs.append({"circuit": circuit, "trajectory": trajectory,
                              "left_any_success": a_any, "right_any_success": b_any,
                              "any_success_difference": int(b_any)-int(a_any),
                              "attempt_rate_difference": (sum(_success(r) for r in b)-sum(_success(r) for r in a))/total_rounds})
            result.append({"scope": scope, "left": left, "right": right,
                           "difference_direction": "right minus left", "pairs": len(pairs),
                           "mean_attempt_rate_difference": _mean([p["attempt_rate_difference"] for p in pairs]),
                           "mean_any_success_difference": _mean([p["any_success_difference"] for p in pairs]),
                           "right_only_success": sum(p["any_success_difference"] == 1 for p in pairs),
                           "left_only_success": sum(p["any_success_difference"] == -1 for p in pairs),
                           "both_success": sum(p["left_any_success"] and p["right_any_success"] for p in pairs),
                           "neither_success": sum(not p["left_any_success"] and not p["right_any_success"] for p in pairs),
                           "trajectory_pairs": pairs,
                           "inference": "descriptive paired comparison; no p-value or independent-attempt interval"})
    return result


def summarize(rows, controls, config, allow_partial=False):
    circuits, levels = config["circuits"], config["feedback_levels"]
    trajectories, rounds = config["trajectories"], config["rounds_per_trajectory"]
    expected_keys = set(itertools.product(circuits, levels, range(trajectories), range(rounds)))
    actual_keys = [(r["circuit"], r["feedback"], r["trajectory"], r["round"]) for r in rows]
    if len(actual_keys) != len(set(actual_keys)):
        raise ValueError("Duplicate circuit/feedback/trajectory/round records")
    if set(actual_keys)-expected_keys:
        raise ValueError("Unexpected experiment rows outside the frozen configuration")
    expected_controls = set(itertools.product(circuits, ("clean", "positive"), range(5)))
    control_keys = [(r["circuit"], r["label"], r["repeat"]) for r in controls]
    if len(control_keys) != len(set(control_keys)) or set(control_keys)-expected_controls:
        raise ValueError("Duplicate or unexpected control records")
    complete = set(actual_keys) == expected_keys and set(control_keys) == expected_controls
    if not complete and not allow_partial:
        raise ValueError(f"Incomplete experiment: {len(rows)}/{len(expected_keys)} rows and "
                         f"{len(controls)}/{len(expected_controls)} controls. Use --allow-partial only for diagnostics.")
    for row in rows:
        if row.get("success") is not _success(row):
            raise ValueError("Stored success disagrees with recomputed physical-validity/detection outcome")
    if config.get("shared_first_round"):
        for circuit, trajectory in itertools.product(circuits, range(trajectories)):
            initial = [r for r in rows if r["circuit"] == circuit and r["trajectory"] == trajectory and r["round"] == 0]
            if len({r["candidate_id"] for r in initial}) > 1:
                raise ValueError("Initial candidates were not shared across conditions")
            # Catch accidental divergent copying of a shared initial judgment.
            if len({_canonical({k: r.get(k) for k in ("parameters", "simulation", "detector")}) for r in initial}) > 1:
                raise ValueError("Shared initial candidate results differ across conditions")
    groups = [_group([r for r in rows if r["circuit"] == circuit and r["feedback"] == level],
                     circuit, level, rounds) for circuit, level in itertools.product(circuits, levels)]
    return {
        "complete": complete, "attempt_rows": len(rows), "expected_attempt_rows": len(expected_keys),
        "unique_candidates": len({r["candidate_id"] for r in rows}),
        "unique_netlists": len({r["netlist_sha256"] for r in rows if r.get("netlist_sha256")}),
        "shared_initial_rows": sum(r.get("shared_initial", False) for r in rows),
        "groups": groups, "controls": _control_summary(controls, circuits),
        "paired_comparisons": _paired_comparisons(rows, circuits, levels, rounds),
        "metric_definitions": {
            "primary_rate": "valid AND detector negative / all attempts (descriptive)",
            "conditional_evasion_rate": "valid AND detector negative / valid attempts (descriptive)",
            "trajectory_any_success_rate": "independent starts producing at least one valid undetected candidate / starts",
            "confidence_mean": "mean model-reported confidence in its verdict; not calibrated probability",
            "trajectory_wilson95": "Wilson 95% interval across completed independent trajectory starts only",
        },
        "limitations": [
            "Adaptive rounds within each trajectory are dependent; attempt-level binomial intervals are intentionally omitted.",
            "The first round is shared across feedback arms; pooled row totals are not independent samples.",
            "Each control type repeats one netlist five times; the flag frequency is not a population FPR or sensitivity estimate.",
            "Only five independent starts per circuit; trajectory intervals are broad and conditional on this experimental setup.",
            "Paired differences are descriptive; pooling across two circuits does not establish broad hardware generalization.",
            "LATENT's published component-level evasion is not directly comparable to whole-netlist attempt success here.",
        ],
    }


def _write_csv(path, records):
    fields = list(dict.fromkeys(key for record in records for key in record))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)


def write_outputs(summary, rows, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, allow_nan=False)+"\n")
    flat_rows = []
    for row in sorted(rows, key=lambda r: (r["circuit"], LEVELS.index(r["feedback"]), r["trajectory"], r["round"])):
        detector, simulation = row.get("detector") or {}, row.get("simulation") or {}
        record = {key: row.get(key) for key in ["candidate_id", "circuit", "feedback", "trajectory", "round", "shared_initial", "seed", "prompt_version", "attacker_call_id", "detector_call_id", "netlist_path", "netlist_sha256", "generation_error", "detector_error"]}
        record.update(round_display=row["round"]+1, valid=_valid(row), success=_success(row),
                      detector_negative=_negative(row), is_trojan=detector.get("is_trojan"),
                      confidence=detector.get("confidence"), normal_ok=simulation.get("normal_ok"),
                      trigger_ok=simulation.get("trigger_ok"), simulation_ok=simulation.get("simulation_ok"),
                      simulation_error=simulation.get("error"),
                      parameters_json=_canonical(row.get("parameters")),
                      metrics_json=_canonical(simulation.get("metrics", {})),
                      suspect_nodes_json=_canonical(detector.get("suspect_nodes", [])),
                      feedback_text=detector.get("feedback_text"))
        flat_rows.append(record)
    _write_csv(output_dir / "attempts.csv", flat_rows)
    flat_groups = []
    for group in summary["groups"]:
        record = {k: v for k, v in group.items() if not isinstance(v, (dict, list))}
        record["trajectory_ci95_low"], record["trajectory_ci95_high"] = group["trajectory_wilson95"]
        flat_groups.append(record)
    _write_csv(output_dir / "groups.csv", flat_groups)
    _write_csv(output_dir / "controls.csv", summary["controls"])


def make_figures(summary, config, figure_dir):
    os.environ.setdefault("MPLCONFIGDIR", str(ROOT / "tmp" / "matplotlib"))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter, MaxNLocator
    import numpy as np

    figure_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "axes.labelcolor": "#28374A", "text.color": "#28374A",
                         "axes.edgecolor": "#B6BEC8", "savefig.facecolor": "white"})
    circuits, levels = config["circuits"], config["feedback_levels"]
    index = {(g["circuit"], g["feedback"]): g for g in summary["groups"]}
    fig, axes = plt.subplots(1, len(circuits), figsize=(9.5, 4.0), squeeze=False, sharey=True)
    categories = [("valid_undetected", "Valid + undetected", "#208C85"),
                  ("valid_detected", "Valid + detected", "#4C70A7"),
                  ("valid_unreviewed", "Valid + no verdict", "#D8A35C"),
                  ("invalid", "Physically invalid", "#D2D9E0")]
    for ax, circuit in zip(axes[0], circuits):
        x = np.arange(len(levels)); bottom = np.zeros(len(levels))
        for key, label, color in categories:
            values = np.array([_ratio(index[circuit, level][key], index[circuit, level]["attempts"]) or 0 for level in levels])
            ax.bar(x, values, bottom=bottom, width=.58, color=color, label=label, edgecolor="white", linewidth=.8)
            for xpos, value, base, level in zip(x, values, bottom, levels):
                if value >= .09:
                    ax.text(xpos, base+value/2, f'{index[circuit, level][key]}', ha="center", va="center", color="#28374A" if key=="invalid" else "white", fontsize=11, weight="bold")
            bottom += values
        ax.set_xticks(x, [level.capitalize() for level in levels])
        ax.set_title(CIRCUIT_LABELS.get(circuit, circuit), loc="left", fontsize=12, weight="bold", pad=12)
        ax.set_ylim(0, 1.04); ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.grid(axis="y", alpha=.15); ax.set_axisbelow(True)
        ax.set_xlabel("Detector feedback")
    axes[0, 0].set_ylabel("Share of all attempts")
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=4, frameon=False, bbox_to_anchor=(.5, .995), fontsize=8.6)
    counts = sorted({g["attempts"] for g in summary["groups"]})
    foot = f"Counts inside bars. Attempts per group: {', '.join(map(str, counts))}. Adaptive rounds are dependent; attempt rates are descriptive."
    if not summary["complete"]:
        foot = "INCOMPLETE RUN. " + foot
    fig.text(.5, .015, foot, ha="center", fontsize=8.1)
    fig.tight_layout(rect=(0, .07, 1, .91))
    for suffix in ("png", "pdf"):
        fig.savefig(figure_dir / f"attempt_outcomes.{suffix}", dpi=220)
    plt.close(fig)

    fig, axes = plt.subplots(1, len(circuits), figsize=(9.5, 4.0), squeeze=False, sharey=True)
    colors = {"none": "#697786", "binary": "#4C70A7", "full": "#208C85"}
    markers = {"none": "o", "binary": "s", "full": "^"}
    styles = {"none": "-", "binary": "--", "full": ":"}
    for ax, circuit in zip(axes[0], circuits):
        for level in levels:
            points = index[circuit, level]["cumulative_by_round"]
            x = [p["round"] for p in points]; y = [p["rate"] if p["rate"] is not None else np.nan for p in points]
            ax.plot(x, y, label=level.capitalize(), color=colors[level], marker=markers[level],
                    linestyle=styles[level], linewidth=1.8, markersize=6, markerfacecolor="white")
        ax.set_title(CIRCUIT_LABELS.get(circuit, circuit), loc="left", fontsize=12, weight="bold", pad=12)
        ax.set_ylim(-.035, 1.04); ax.yaxis.set_major_formatter(PercentFormatter(1))
        ax.xaxis.set_major_locator(MaxNLocator(integer=True)); ax.set_xlabel("Attempts allowed per trajectory")
        ax.grid(alpha=.15); ax.set_axisbelow(True)
        ax.set_xticks(range(1, config["rounds_per_trajectory"]+1))
    axes[0, 0].set_ylabel("Trajectories with at least one success")
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(.5, .995))
    fig.text(.5, .015, f"{config['trajectories']} independent starts per circuit. Round 1 is shared across arms. Success requires physical validity and a negative detector verdict.", ha="center", fontsize=8)
    fig.tight_layout(rect=(0, .07, 1, .91))
    for suffix in ("png", "pdf"):
        fig.savefig(figure_dir / f"trajectory_success.{suffix}", dpi=220)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="main_v2")
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args()
    output_dir = ROOT / "results" / args.run_id
    manifest = json.loads((output_dir / "manifest.json").read_text())
    config = manifest["config"]
    rows = json.loads((output_dir / "attempts.json").read_text())
    controls = json.loads((output_dir / "controls.json").read_text())
    summary = summarize(rows, controls, config, args.allow_partial)
    summary["source_sha256"] = {filename: hashlib.sha256((output_dir / filename).read_bytes()).hexdigest()
                                for filename in ("attempts.json", "controls.json", "manifest.json")}
    write_outputs(summary, rows, output_dir)
    figures = output_dir / "figures"
    make_figures(summary, config, figures)
    print(json.dumps({"complete": summary["complete"], "attempt_rows": summary["attempt_rows"],
                      "unique_candidates": summary["unique_candidates"],
                      "summary": str(output_dir / "summary.json"), "figures": str(figures)}, indent=2))


if __name__ == "__main__":
    main()
