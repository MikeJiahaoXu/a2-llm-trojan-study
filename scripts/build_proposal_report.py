#!/usr/bin/env python3
"""Build the proposal-scoped report from completed, audited experiment records.

This module never calls an API or runs a circuit simulation. It deliberately has
no fallback to earlier experiments and never manufactures missing results.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / "tmp/matplotlib"))
CIRCUITS = ("opamp", "and4")
LEVELS = ("none", "binary", "full")
NAMES = {"opamp": "Two-stage op-amp", "and4": "Four-input AND"}


def load_json(path):
    return json.loads(Path(path).read_text())


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fraction(numerator, denominator):
    return f"{numerator}/{denominator} ({100*numerator/denominator:.1f}%)" if denominator else "n/a"


def clean_text(text):
    text = re.sub(r'<link href="([^"]+)"[^>]*>(.*?)</link>', r'\2 (\1)', text)
    return html.unescape(re.sub("<[^>]+>", "", text.replace("<br/>", "\n")))


def load_run(run_id):
    """Recount raw records; a summary file alone is not accepted as evidence."""
    directory = ROOT / "results" / run_id
    completion = load_json(directory / "completion.json")
    if completion.get("complete") is not True:
        raise ValueError(f"Incomplete experiment: {run_id}")
    manifest = load_json(directory / "manifest.json")
    rows = load_json(directory / "attempts.json")
    controls = load_json(directory / "controls.json")
    config = manifest["config"]
    if set(config["circuits"]) != set(CIRCUITS) or set(config["feedback_levels"]) != set(LEVELS):
        raise ValueError("Report requires exactly the two proposed circuits and three feedback levels")
    if not rows or any(row["circuit"] not in CIRCUITS or row["feedback"] not in LEVELS for row in rows):
        raise ValueError("Missing or out-of-scope experiment records")
    expected_rows = completion.get("attempt_rows")
    if expected_rows is not None and expected_rows != len(rows):
        raise ValueError("Completion marker disagrees with raw record count")
    groups = []
    for circuit in CIRCUITS:
        for level in LEVELS:
            selected = [row for row in rows if row["circuit"] == circuit and row["feedback"] == level]
            if not selected:
                raise ValueError(f"Missing experimental group: {circuit}/{level}")
            for row in selected:
                simulation = row.get("simulation", {})
                detector = row.get("detector")
                expected_success = simulation.get("valid") is True and detector is not None and detector.get("is_trojan") is False
                if row.get("success") is not expected_success:
                    raise ValueError("Stored success disagrees with physical validity and review")
            valid = sum(row["simulation"].get("valid") is True for row in selected)
            successes = sum(row["success"] for row in selected)
            detected = sum(bool(row.get("detector", {}) and row["detector"].get("is_trojan") is True) for row in selected)
            trajectories = sorted({row["trajectory"] for row in selected})
            trajectory_successes = sum(any(row["success"] for row in selected if row["trajectory"] == trajectory) for trajectory in trajectories)
            groups.append({"circuit": circuit, "feedback": level, "attempts": len(selected), "valid": valid,
                           "successes": successes, "detected": detected,
                           "trajectories": len(trajectories), "trajectory_successes": trajectory_successes,
                           "distinct_netlists": len({row["netlist_sha256"] for row in selected if row.get("netlist_sha256")})})
    unique = {}
    for row in rows:
        identifier = row["candidate_id"]
        if identifier in unique:
            for key in ("netlist_sha256", "simulation", "detector", "success"):
                if row.get(key) != unique[identifier].get(key):
                    raise ValueError("A shared candidate has inconsistent evidence")
        unique[identifier] = row
    if completion.get("unique_candidates", len(unique)) != len(unique):
        raise ValueError("Completion marker disagrees with unique candidate count")
    for row in unique.values():
        if row.get("netlist_path") and file_hash(ROOT / row["netlist_path"]) != row["netlist_sha256"]:
            raise ValueError("Generated netlist changed after evaluation")
    control_groups = []
    for circuit in CIRCUITS:
        for label in ("clean", "positive"):
            selected = [row for row in controls if row["circuit"] == circuit and row["label"] == label]
            if not selected:
                raise ValueError("Missing detector controls")
            control_groups.append({"circuit": circuit, "label": label, "judgments": len(selected),
                                   "flagged": sum(row["detector"]["is_trojan"] is True for row in selected)})
    return {"run_id": run_id, "directory": directory, "config": config, "manifest": manifest,
            "rows": rows, "controls": controls, "groups": groups, "control_groups": control_groups,
            "unique_candidates": len(unique), "unique_rows": list(unique.values()),
            "distinct_netlists": len({row["netlist_sha256"] for row in unique.values() if row.get("netlist_sha256")}),
            "source_sha256": {name: file_hash(directory / name) for name in ("attempts.json", "controls.json", "manifest.json", "completion.json")}}


def group(run, circuit, level):
    return next(item for item in run["groups"] if item["circuit"] == circuit and item["feedback"] == level)


def load_qualification(primary, replication):
    path = ROOT / "results/proposal_validation/qualification_summary.json"
    data = load_json(path)
    if data.get("status") != "qualified" or data.get("all_independent_checks_passed") is not True:
        raise ValueError("Circuit-menu qualification is incomplete")
    if not all(item["passed"] == item["combinations"] for item in data["groups"].values()):
        raise ValueError("Not every permitted circuit configuration is qualified")
    if primary["manifest"]["source_hashes"] != replication["manifest"]["source_hashes"]:
        raise ValueError("The two experiments did not use identical frozen generation/review sources")
    for name, expected in primary["manifest"]["source_hashes"].items():
        if file_hash(primary["directory"] / "source_snapshot" / name) != expected:
            raise ValueError("Primary protocol snapshot changed: " + name)
        if file_hash(replication["directory"] / "source_snapshot" / name) != expected:
            raise ValueError("Replication protocol snapshot changed: " + name)
    frozen_hash = primary["manifest"]["source_hashes"].get(str(path.relative_to(ROOT)))
    if not frozen_hash or file_hash(path) != frozen_hash:
        raise ValueError("Qualification evidence differs from the frozen protocol")
    if not all(data["clean_results"][c]["passed"] for c in CIRCUITS):
        raise ValueError("A clean circuit failed validation")
    qualified = {record["netlist_sha256"] for record in data["records"] if record["passed"]}
    for run in (primary, replication):
        for row in run["unique_rows"]:
            if row.get("netlist_sha256") and row["netlist_sha256"] not in qualified:
                raise ValueError("Observed candidate is outside the qualified finite menu")
    return data


def load_audits(primary, replication):
    paths = []
    for run in (primary, replication):
        path = run["directory"] / "independent_audit.json"
        audit = load_json(path)
        if audit.get("passed") is not True or audit["run_id"] != run["run_id"]:
            raise ValueError("Independent protocol audit did not pass")
        if audit["attempt_rows"] != len(run["rows"]) or audit["candidate_events"] != run["unique_candidates"]:
            raise ValueError("Protocol audit disagrees with the current records")
        if audit["source_hashes"] != run["manifest"]["source_hashes"]:
            raise ValueError("Protocol audit has a different source manifest")
        paths.append(path)
    repeat_path = replication["directory"] / "replication_audit.json"
    repeat = load_json(repeat_path)
    if repeat.get("passed") is not True or repeat["runs"] != [primary["run_id"], replication["run_id"]]:
        raise ValueError("Independent replication audit did not pass")
    electrical_path = ROOT / "results/proposal_audit/audit.json"
    electrical = load_json(electrical_path)
    if electrical.get("complete") is not True or electrical.get("passed") is not True:
        raise ValueError("Electrical replay audit is incomplete or failed")
    if set(electrical["run_counts"]) != {primary["run_id"], replication["run_id"]}:
        raise ValueError("Electrical replay audit covers different runs")
    expected_netlists = len({row["netlist_sha256"] for run in (primary, replication) for row in run["unique_rows"] if row.get("netlist_sha256")})
    if electrical["distinct_netlists_freshly_simulated"] != expected_netlists or electrical["all_fresh_simulations_match"] is not True:
        raise ValueError("Electrical replay audit does not cover every observed distinct netlist")
    paths.extend([repeat_path, electrical_path])
    return {str(path.relative_to(ROOT)): file_hash(path) for path in paths}


def load_calibration(primary_id):
    match = re.fullmatch(r"proposal_main_v(\d+)", primary_id)
    if not match:
        raise ValueError("Unknown calibration lineage for requested experiment")
    paths = []
    records = []
    for version in range(1, int(match.group(1))):
        directory = ROOT / "results" / f"proposal_main_v{version}"
        path = directory / "controls.json"
        if not path.exists():
            continue
        if not (directory / "control_gate_failure.json").exists():
            raise ValueError("Earlier calibration records do not have the expected control-gate failure")
        attempts = directory / "attempts.json"
        if attempts.exists() and load_json(attempts):
            raise ValueError("Calibration disclosure must be revised: earlier stage includes attack trials")
        records.extend(load_json(path))
        paths.append(path)
    if not paths:
        raise ValueError("Expected calibration evidence is unavailable")
    return {"stages": len(paths), "records": records,
            "source_sha256": {str(path.relative_to(ROOT)): file_hash(path) for path in paths}}


def load_and_diagnostics(primary, replication):
    path = ROOT / "results/proposal_analysis/and_diagnostics.json"
    data = load_json(path)
    if data.get("passed") is not True or not all(data["checks"].values()):
        raise ValueError("Saved AND diagnostic checks did not pass")
    for name, expected in data["source_sha256"].items():
        if file_hash(ROOT / name) != expected:
            raise ValueError("AND diagnostic source changed: " + name)
    if set(data["runs"]) != {primary["run_id"], replication["run_id"]}:
        raise ValueError("AND diagnostics cover a different experiment")
    return data, path


def load_attempt_budget(primary, replication):
    """Validate the retrospective metrics against the unchanged trial records."""
    path = ROOT / "results/proposal_analysis/attempt_budget.json"
    data = load_json(path)
    if data.get("analysis_type") != "retrospective_descriptive_reanalysis_of_existing_records" or not all(data["checks"].values()):
        raise ValueError("Attempt-budget analysis is incomplete or failed")
    for name, expected in data["source_sha256"].items():
        if file_hash(ROOT / name) != expected:
            raise ValueError("Attempt-budget source changed: " + name)
    pooled = {(g["circuit"], g["condition"]): g for g in data["groups"] if g["scope"] == "pooled"}
    if set(pooled) != {(c, level) for c in CIRCUITS for level in LEVELS}:
        raise ValueError("Attempt-budget analysis has different experimental groups")
    for (circuit, level), recorded in pooled.items():
        sessions = []
        for run in (primary, replication):
            for start in range(run["config"]["trajectories"]):
                rows = sorted([r for r in run["rows"] if r["circuit"] == circuit
                               and r["feedback"] == level and r["trajectory"] == start], key=lambda r: r["round"])
                if [r["round"] for r in rows] != list(range(10)):
                    raise ValueError("A session is missing an attempt")
                sessions.append(rows)
        expected = {
            "first_attempt_success": (sum(s[0]["success"] for s in sessions), len(sessions)),
            "final_attempt_success": (sum(s[-1]["success"] for s in sessions), len(sessions)),
            "any_success_within_10": (sum(any(r["success"] for r in s) for s in sessions), len(sessions)),
            "all_attempt_success": (sum(r["success"] for s in sessions for r in s), sum(map(len, sessions))),
        }
        for key, (numerator, denominator) in expected.items():
            if recorded[key]["successes"] != numerator or recorded[key]["denominator"] != denominator:
                raise ValueError("Attempt-budget metric disagrees with raw records: " + key)
        for k, point in enumerate(recorded["cumulative_curve"], 1):
            if point["attempt_budget"] != k or point["any_success_by_attempt"]["successes"] != sum(any(r["success"] for r in s[:k]) for s in sessions):
                raise ValueError("Cumulative curve disagrees with raw records")
    events = [r for run in (primary, replication) for r in run["unique_rows"]]
    if data["counts"]["actual_candidate_review_events"] != len(events):
        raise ValueError("Attempt-budget event count disagrees with raw records")
    if data["counts"]["unusable_detector_response_events"] != sum(r.get("detector") is None for r in events):
        raise ValueError("Unusable review count disagrees with raw records")
    return data, pooled, path


def make_budget_figure(pooled, destination):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9,
                         "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(1, 2, figsize=(9.2, 2.65), sharey=True)
    styles = [("none", "#6F7A86", "-", "o"), ("binary", "#187F79", "--", "s"),
              ("full", "#55779C", ":", "^")]
    for axis, circuit in zip(axes, CIRCUITS):
        for level, color, line, marker in styles:
            values = pooled[circuit, level]["cumulative_curve"]
            axis.plot([v["attempt_budget"] for v in values],
                      [v["any_success_by_attempt"]["successes"] for v in values],
                      color=color, linestyle=line, marker=marker, markerfacecolor="white",
                      markersize=4.3, linewidth=1.8, label=level.capitalize())
        axis.set_title(NAMES[circuit], loc="left", fontsize=10, weight="bold")
        axis.set_xlabel("Attempts available per session")
        axis.set_xticks([1, 2, 4, 6, 8, 10]); axis.set_xlim(.7, 10.3)
        axis.set_ylim(-.15, 4.3); axis.set_yticks(range(5)); axis.grid(alpha=.15)
    axes[0].set_ylabel("Sessions with at least one escape (of 4)")
    axes[1].legend(frameon=False, fontsize=8, loc="lower right")
    fig.tight_layout(pad=1.1)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(destination, dpi=220)
    fig.savefig(destination.with_suffix(".pdf"))
    plt.close(fig)


def make_waveform_figure(primary, destination):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9,
                         "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(1, 2, figsize=(9.2, 2.45))
    for axis, circuit, limits in zip(axes, CIRCUITS, ((45, 65), (35, 40))):
        paths = [(ROOT / "results/proposal_validation/clean" / circuit / "trigger.tsv", "Clean", "#607389", "--"),
                 (primary["directory"] / "control_simulations" / circuit / "trigger.tsv", "Known positive", "#187F79", "-")]
        for path, label, color, style in paths:
            with path.open() as stream:
                columns = stream.readline().split()
            values = np.loadtxt(path, skiprows=1)
            t = values[:, 0]*1e6
            selection = (t >= limits[0]) & (t <= limits[1])
            axis.plot(t[selection], values[selection, columns.index("v(out)")], color=color, linestyle=style, linewidth=1.2, label=label)
        axis.set_title(NAMES[circuit], loc="left", fontsize=10, weight="bold")
        axis.set_xlabel("Time (us)"); axis.set_ylabel("Output (V)")
        axis.set_xlim(*limits); axis.grid(alpha=.15)
    axes[0].legend(frameon=False, fontsize=8)
    fig.tight_layout(pad=1.1)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(destination, dpi=220)
    fig.savefig(destination.with_suffix(".pdf"))
    plt.close(fig)


def make_results_figure(primary, replication, destination):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9,
                         "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(1, 2, figsize=(9.2, 2.6), sharey=True)
    for axis, circuit in zip(axes, CIRCUITS):
        x = np.arange(len(LEVELS))
        for offset, run, label, color in [(-.18, primary, "First run", "#187F79"), (.18, replication, "Repeat run", "#55779C")]:
            gs = [group(run, circuit, level) for level in LEVELS]
            rates = [100*g["successes"]/g["attempts"] for g in gs]
            bars = axis.bar(x+offset, rates, .34, color=color, label=label)
            for bar, g in zip(bars, gs):
                axis.text(bar.get_x()+bar.get_width()/2, bar.get_height()+2, f"{g['successes']}/{g['attempts']}", ha="center", va="bottom", fontsize=8)
        axis.set_title(NAMES[circuit], loc="left", fontsize=10, weight="bold")
        axis.set_xticks(x, [level.capitalize() for level in LEVELS])
        axis.set_ylim(0, 112); axis.set_yticks([0, 25, 50, 75, 100]); axis.grid(axis="y", alpha=.15)
        axis.set_axisbelow(True)
    axes[0].set_ylabel("Physically valid and unflagged (%)")
    axes[1].legend(frameon=False, fontsize=8, loc="upper right")
    fig.tight_layout(pad=1.2)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(destination, dpi=220)
    fig.savefig(destination.with_suffix(".pdf"))
    plt.close(fig)


class ReportLayout:
    """One source of content for the PDF and its editable text companion."""
    def __init__(self):
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        self.colors = colors
        self.ink = colors.HexColor("#20344B")
        self.muted = colors.HexColor("#5B6875")
        self.pale = colors.HexColor("#EFF4F7")
        self.styles = {}
        for name, size, leading, bold in [("title", 22, 26, True), ("h1", 16, 20, True),
                                          ("h2", 11, 14, True), ("body", 10, 13.5, False),
                                          ("small", 8, 10.5, False), ("cell", 8, 10.3, False),
                                          ("header", 8, 10.3, True)]:
            self.styles[name] = ParagraphStyle(name, fontName="Helvetica-Bold" if bold else "Helvetica",
                                              fontSize=size, leading=leading, spaceAfter=6 if name != "cell" else 0,
                                              textColor=colors.white if name == "header" else self.ink)
        self.story, self.text = [], []

    def p(self, content, style="body"):
        from reportlab.platypus import Paragraph
        self.story.append(Paragraph(content, self.styles[style]))
        self.text.append(clean_text(content))

    def new_page(self):
        from reportlab.platypus import PageBreak
        self.story.append(PageBreak())
        self.text.append("\n" + "="*60 + "\n")

    def table(self, headers, rows, widths):
        from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
        render = lambda value, style: Paragraph(html.escape(str(value)), self.styles[style])
        cells = [[render(value, "header") for value in headers]]
        cells.extend([[render(value, "cell") for value in row] for row in rows])
        table = Table(cells, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), self.ink),
                                   ("ROWBACKGROUNDS", (0, 1), (-1, -1), [self.colors.white, self.pale]),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 7),
                                   ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                                   ("TOPPADDING", (0, 0), (-1, -1), 6),
                                   ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        self.story.extend([table, Spacer(1, 7)])
        self.text.append(" | ".join(headers))
        self.text.extend(" | ".join(map(str, row)) for row in rows)

    def figure(self, path, width=516):
        from reportlab.lib.utils import ImageReader
        from reportlab.platypus import Image
        iw, ih = ImageReader(str(path)).getSize()
        self.story.append(Image(str(path), width=width, height=width*ih/iw))

    def save(self, destination):
        from reportlab.platypus import SimpleDocTemplate
        from pypdf import PdfReader
        destination.parent.mkdir(parents=True, exist_ok=True)
        def footer(canvas, document):
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(self.muted)
            canvas.drawString(48, 28, "A2 Trojans in the LLM Era | Informal project report")
            canvas.drawRightString(564, 28, str(document.page))
        document = SimpleDocTemplate(str(destination), pagesize=(612, 792), leftMargin=48,
                                     rightMargin=48, topMargin=40, bottomMargin=45,
                                     title="A2 Trojans in the LLM Era", author="Amber Tsao and Jiahao Xu")
        document.build(self.story, onFirstPage=footer, onLaterPages=footer)
        pages = len(PdfReader(str(destination)).pages)
        if not 3 <= pages <= 5:
            raise ValueError(f"Report is {pages} pages; requested range is 3-5")
        destination.with_suffix(".txt").write_text("\n\n".join(self.text)+"\n")
        return pages


def build(primary_id, replication_id, output):
    primary = load_run(primary_id)
    replication = load_run(replication_id)
    qualification = load_qualification(primary, replication)
    audits = load_audits(primary, replication)
    calibration = load_calibration(primary_id)
    from scripts.proposal.continue_after_controls import verify_deviation
    deviation_record = verify_deviation(ROOT, replication_id)
    deviation_path = replication["directory"] / "control_gate_deviation.json"
    deviation = deviation_record["deviation"]
    if deviation["original_gate_passed"] is not False or deviation["repeat_attack_rows_at_decision"] != 0:
        raise ValueError("Repeat continuation disclosure does not match the recorded deviation")
    config = primary["config"]
    if not config["protocol"].startswith("proposal_v") or config["trajectories"] != 2 or config["rounds_per_trajectory"] != 10:
        raise ValueError("Report prose requires the frozen two-start, ten-attempt proposal protocol")
    if set(config["run_seeds"]) != {primary_id, replication_id}:
        raise ValueError("Requested experiments differ from the predeclared run pair")
    if any(item["attempts"] != 20 for run in (primary, replication) for item in run["groups"]):
        raise ValueError("Each proposed group must contain all twenty attempts")
    assets = output.parent / "proposal_report_figures"
    waveform = assets / "physical_verification.png"
    comparison = assets / "feedback_comparison.png"
    make_waveform_figure(primary, waveform)
    make_results_figure(primary, replication, comparison)
    budget, budget_groups, budget_path = load_attempt_budget(primary, replication)
    budget_figure = assets / "attempt_budget.png"
    make_budget_figure(budget_groups, budget_figure)
    report = ReportLayout()
    p, table = report.p, report.table
    clean = qualification["clean_results"]
    aggregate = {}
    for circuit in CIRCUITS:
        for level in LEVELS:
            gs = [group(run, circuit, level) for run in (primary, replication)]
            aggregate[circuit, level] = {key: sum(g[key] for g in gs) for key in
                                        ("attempts", "valid", "successes", "trajectories", "trajectory_successes")}
    total_rows = len(primary["rows"])+len(replication["rows"])
    total_events = primary["unique_candidates"]+replication["unique_candidates"]
    distinct_union = len({row["netlist_sha256"] for run in (primary, replication) for row in run["unique_rows"] if row.get("netlist_sha256")})
    valid_rows = sum(row["simulation"]["valid"] for run in (primary, replication) for row in run["rows"])
    valid_events = sum(row["simulation"]["valid"] for run in (primary, replication) for row in run["unique_rows"])
    initial_successes = {c: sum(row["success"] for run in (primary, replication) for row in run["unique_rows"]
                                if row["circuit"] == c and row["round"] == 0) for c in CIRCUITS}

    diagnostics, diagnostic_path = load_and_diagnostics(primary, replication)
    common = diagnostics["common_none_netlist"]
    case = sorted([row for row in primary["unique_rows"]
                   if row.get("netlist_sha256") == common["netlist_sha256"] and row["success"]],
                  key=lambda row: row["candidate_id"])[0]
    case_quote = re.split(r"(?<=[.!?])\s+", case["detector"]["feedback_text"].strip())[0]
    metrics = case["simulation"]["metrics"]
    controls = {(run["run_id"], item["circuit"], item["label"]): item
                for run in (primary, replication) for item in run["control_groups"]}
    if any(controls[replication_id,c,"clean"]["flagged"] != 0
           or controls[replication_id,c,"positive"]["flagged"] != 3
           or controls[primary_id,c,"positive"]["flagged"] != 4 for c in CIRCUITS):
        raise ValueError("Control counts changed; revise the continuation disclosure")

    # Page 1: research question and the concrete information flow.
    p("A2 Trojans in the LLM Era", "title")
    p("Does Detection Feedback Help an Attacker?", "h2")
    p("Amber Tsao (cctsao) and Jiahao Xu (e1583425)<br/>Information Security course project | Experiments: November 1, 2026 | Revised: November 2, 2026", "small")
    p("Introduction", "h1")
    p("A2 demonstrated that a small analog modification can accumulate charge during unusual activity "
      "and trigger a harmful change [1]. Related work studies analog hardware Trojans from both sides: "
      "SPICED reviews analog/mixed-signal circuits for suspicious behavior [2], while LATENT uses "
      "detection feedback to guide Trojan insertion [3]. A useful explanation can help a designer "
      "understand a weakness, but exposing it may also tell an attacker what to change.")
    p("LATENT reports average evasion rising from 23.7% with one-shot prompting to 94.4% with iterative "
      "feedback. These are component-localization measures, not the fraction of whole circuits missed. "
      "Motivated by that result, we ask a narrower question: <b>does more detailed detector feedback "
      "help an attacker produce a working modification that the reviewer does not flag?</b> We compare "
      "no feedback, a Boolean verdict and a complete review on two small circuits.")
    p("Methodology", "h1")
    p(f"Both attacker and detector use <b>{html.escape(config['model'])}</b> at temperature "
      f"<b>{config['temperature']}</b>. The attacker follows a LATENT-inspired revision loop; the "
      "netlist-only detector is a minimal SPICED-inspired reviewer. This is not a full reproduction "
      "of either framework. We omit syntax-repair evaluation.")
    p("<b>One attempt has three steps.</b> First, the attacker receives the clean circuit, test "
      "conditions and a finite menu. It selects an insertion site, device representation, trigger "
      "profile and loading strength. Python turns these four choices into SPICE components. Second, "
      "ngspice checks that the circuit still works normally and misbehaves when activated. Third, "
      "the detector reads the candidate netlist and its nominal function, then returns a Trojan "
      "verdict, confidence, suspicious identifiers and explanation. It sees neither the clean "
      "reference nor simulation results. The simulation results are not sent to either LLM.")
    table(["Condition", "What the attacker receives for its next attempt"], [
        ["None", "A fresh task; no previous candidate or review."],
        ["Binary", "The preceding candidate's choices and the Boolean Trojan verdict."],
        ["Full", "The preceding choices and the complete review, including suspicious nodes and explanation."],
    ], [66, 450])
    p("Feedback goes only to the attacker. The detector is stateless: each review starts afresh with "
      "the same prompt and model, without previous judgments or an update to its weights. Its prompt "
      "was calibrated on controls before the attacks. Thus the experiment tests disclosure to an "
      "attacker, not a defender that learns alongside it.")
    p("Each session contains ten attempts: one initial proposal followed by nine further requests. "
      "We run two sessions per condition in each of two execution batches, for <b>four sessions and "
      "40 attempts per circuit/condition</b>. The batches use different predeclared seeds with the "
      "same model, prompts and circuit settings. The same initial candidate and review start all three "
      "conditions within a session. None continues with fresh requests; binary and full revise from "
      "the preceding attempt. No condition stops after an escape or restores a best-so-far candidate.")

    # Page 2: simple physical mechanism, rationale and evaluation criteria.
    report.new_page()
    p("Methodology (continued)", "h1")
    p("Circuits and permitted modifications", "h2")
    p("We use a two-stage op-amp and a four-input AND because they provide two readily checked kinds "
      "of behavior: continuous amplification and a digital truth table. Small circuits also keep "
      "simulation and manual inspection manageable. Both use 3.3 V supplies. Their clean versions "
      "are verified before any modification:")
    op = clean["opamp"]["metrics"]
    gate = clean["and4"]["metrics"]
    table(["Clean circuit", "Verification"], [
        ["Two-stage op-amp", f"Open-loop gain {op['dc_gain_db']:.2f} dB; -3 dB bandwidth {op['bandwidth_3db_hz']:.2f} Hz; unity-gain frequency {op['unity_gain_hz']/1e6:.3f} MHz; phase margin {op['phase_margin_deg']:.2f} degrees."],
        ["Four-input AND", f"{gate['truth_table_passed']}/16 logic cases pass. Rise delay {gate['rise_delay_ns']:.4f} ns; fall delay {gate['fall_delay_ns']:.4f} ns when all four inputs fall together (100 fF load, 100 ps edges)."],
    ], [112, 404])
    p("The trigger works like a leaky bucket. Input transitions add charge through a coupling "
      "capacitor and two diodes to a 10 pF reservoir; a resistor slowly drains it. Rapid activity "
      "can raise the reservoir above a threshold, enabling an extra branch that pulls an output "
      "or internal node toward a supply rail. The intended pattern is ordinary behavior while "
      "dormant and an output disturbance after activation. This captures A2's charge-accumulation "
      "idea, using simulation models rather than fabricated hardware.")
    p("The attacker chooses among three op-amp sites (output, gain node or mirror-reference node) "
      "and two AND sites (final output or the NAND node feeding its inverter). Each site has three "
      "branch representations, three RC/threshold profiles and three strengths: <b>81 op-amp and "
      "54 AND configurations</b>. The representations are a switch, smooth conductance and MOSFET; "
      "the MOSFET option uses an ideal reservoir comparator. This bounded menu makes the experiment "
      "about selecting and revising effective modifications, without mixing in arbitrary netlist "
      "syntax failures.")
    p("Electrical checks and their purpose", "h2")
    p("A candidate must pass two checks to count as an escape. <b>Normal behavior:</b> the op-amp "
      "follower stays within 20 mV of its clean reference; AND retains all 16 logic cases and stays "
      "within 0.2 V at settled outputs. <b>Activation:</b> the op-amp output falls at least 0.3 V "
      "below its reference, and AND's high output falls by at least 0.8 V. A harmless added branch "
      "or a permanently broken circuit would therefore not qualify merely because the LLM missed it.")
    p("The op-amp changes from 1.65 V +/- 50 mV at 10 kHz to a 0.6-2.7 V, 1 MHz burst at 5-45 us; "
      "the output drop is measured at absolute time 50-60 us. Both amplitude and frequency change, "
      "so frequency alone is not isolated. AND receives a 1 MHz burst on input a while b, c and d "
      "are high. All 135 allowed configurations passed the declared tests before the LLM runs, and "
      "each generated candidate was simulated again. Validity therefore measures selection from "
      "a qualified menu, not unrestricted LLM circuit-design ability.")
    report.figure(waveform)
    p("Figure 1. Clean and known-positive outputs: op-amp after the burst and AND during the burst. "
      "These traces establish electrical effects; the detector does not receive them.", "small")

    # Page 3: clearly distinguish original per-attempt results from post-hoc budgets.
    report.new_page()
    p("Results", "h1")
    p(f"The six groups contain {total_rows} analysis rows: 2 circuits x 3 conditions x 4 sessions x "
      f"10 attempts. Eight shared initial events each appear in three conditions, giving 16 reused "
      f"rows and {total_events} actual candidate/review events. Repeated choices reduce these to "
      f"{distinct_union} distinct netlists. All {valid_events}/{total_events} candidate events pass the "
      "electrical tests. Two reviews are unusable because their responses were truncated; they "
      "remain non-successes in the per-attempt denominators, not positive detections. One subsequent "
      "binary request retained the preceding choices without a verdict.")
    p("An <b>escape</b> requires electrical validity and a usable negative Trojan verdict. The "
      "original outcome is escapes per attempt. To separate one request from a larger request "
      "budget, we also retrospectively summarize the saved first attempt and whether any of ten "
      "attempts escaped. These additional summaries use existing records; no new experiments "
      "were performed.")
    table(["Circuit", "Feedback", "First attempt", "Any within 10", "All attempts"], [
        [NAMES[c], level,
         f"{budget_groups[c,level]['first_attempt_success']['successes']}/4",
         f"{budget_groups[c,level]['any_success_within_10']['successes']}/4",
         fraction(aggregate[c,level]["successes"], 40)] for c in CIRCUITS for level in LEVELS],
        [122, 66, 94, 104, 130])
    p("Table 1. First-attempt and any-within-ten columns count sessions (four per group); the "
      "original all-attempt column counts requests (40 per group). Initial outcomes are shared "
      "across conditions. Repeated netlists and unsuccessful reviews are retained.", "small")
    report.figure(budget_figure)
    p("Figure 2. Retrospective cumulative opportunity to observe at least one escape. Each curve "
      "summarizes four sessions. More opportunities can reveal a "
      "miss even without a design change; this is not a measure of learning alone.", "small")
    p("For the op-amp, both revision conditions have 13/40 escapes while none has 0/40. Binary "
      "finds an escape in all four sessions and full in three. For AND, the per-attempt order is "
      "none 10/40, binary 9/40 and full 6/40; none and binary each find an escape in all four "
      "sessions. Detailed explanation therefore does not consistently improve either measure.")
    p("Finding one escape is also different from retaining it. At attempt ten, op-amp binary and "
      "full each escape in only 1/4 sessions; AND binary and full are both 0/4. The loop continues "
      "after an escape and may replace a previously successful design. With only four sessions and "
      "dependent steps within them, these proportions are descriptive rather than evidence of "
      "statistical superiority.")

    # Page 4: retain batch/control evidence and explain the revealing AND case.
    report.new_page()
    p("Results (continued)", "h1")
    p("Consistency between execution batches", "h2")
    table(["Circuit", "Batch 1: none / binary / full", "Batch 2: none / binary / full"], [
        [NAMES[c], " / ".join(str(group(primary,c,l)["successes"]) for l in LEVELS),
         " / ".join(str(group(replication,c,l)["successes"]) for l in LEVELS)] for c in CIRCUITS],
        [122, 197, 197])
    p("Table 2. Escape counts, each out of 20 attempts. Both batches contain two ten-attempt "
      "sessions per group; neither batch is a one-shot condition.", "small")
    p("Full slightly exceeds binary for the op-amp in batch 1, but binary exceeds full in batch 2. "
      "AND also changes between batches. Pooling increases the number of observations; it does "
      "not remove this variation or establish a general none &lt; binary &lt; full ordering.")
    p("Detector controls", "h2")
    p("Two prompt refinements using recorded control results preceded every attack in the final "
      "experiment. Final controls reuse those benchmark designs and are <b>not held out</b>. "
      "They test repeated judgments of four particular circuits, not general detector accuracy. "
      "We set a gate of at most one clean flag and at least four known-positive flags in five "
      "reviews of each design. Batch 1 has 0/5 clean flags and 4/5 positive flags for both circuits.")
    p("Batch 2 again has 0/5 clean flags but only <b>3/5</b> positive flags for each circuit, failing "
      "the unchanged gate. After batch 1 results and batch 2 controls were known, an explicit "
      "continuation-rule <b>deviation</b> was recorded before batch 2 attacks. Prompts, seeds, "
      "menus and attempt counts were unchanged, and controls were not rerun. Batch 2 is therefore "
      "a same-settings stability assessment, not confirmation that passed the original gate.")
    p("Why repeat a request with no feedback?", "h2")
    p("Fresh model calls can select different configurations or give different reviews of the same "
      "configuration. The no-feedback condition gives this repeated sampling the same ten-request "
      "budget as the revision conditions. In fact, both AND no-feedback groups chose exactly the "
      "same output-to-ground MOSFET, trigger profile p2 and medium strength on every attempt. "
      "This design escaped 4/20 times in batch 1 and 6/20 in batch 2 without being modified.")
    p(f"The design is electrically effective: normal output differs by only "
      f"{metrics['normal_settled_max_deviation_v']*1e6:.3f} microvolts, while activation lowers its "
      f"high output by {metrics['trigger_output_drop_v']:.3f} V. Across all conditions, this identical "
      f"netlist is flagged in {common['actual_reviews_all_arms']['flagged']}/"
      f"{common['actual_reviews_all_arms']['count']} actual reviews. A negative review describes the "
      "extra components as not altering the intended function, contrary to the simulated disturbance. "
      "Repeated misses here reflect inconsistent interpretation of the same circuit, not successive "
      "improvements to it.")
    p("The revision conditions also change which designs are reviewed. Binary and full each select "
      "the internal NAND node for 10/20 attempts in <i>each</i> batch. All 40 actual reviews of "
      "those internal-site candidates flag a Trojan; these are repeated events, not 40 distinct "
      "designs. Thus both spend half their attempts on consistently detected choices. Full does "
      "not use this site more often than binary, so that alone cannot explain their difference.")

    # Page 5: concise interpretation, comparison and balanced security conclusion.
    report.new_page()
    p("Discussion", "h1")
    p("What may account for the results?", "h2")
    p("The op-amp no-feedback requests repeatedly select one configuration and produce no escape "
      "(39 flags and one unusable review). The revision conditions explore other sites and "
      "representations. Conditioning on the preceding proposal and verdict may help leave that "
      "default, but our comparison does not separate candidate history from feedback. For AND, "
      "an unchanged output-shunt design is already missed intermittently, while revisions often "
      "move to detected internal-node changes. Pulling the NAND node high directly forces the "
      "following inverter's output low; that interference may be easier to recognize. We did not "
      "isolate this mechanism experimentally. Nor did we vary circuit complexity independently "
      "of the 54-choice AND and 81-choice op-amp menus.")
    p("Why this differs from the papers", "h2")
    p("<b>Metric and evidence.</b> LATENT's 23.7% and 94.4% figures summarize the proportion of "
      "inserted components escaping localization in resulting designs [3, Table I]. A design can "
      "score highly on that measure while still being flagged through one detected component. "
      "Our whole-candidate verdict is stricter in this sense, and our per-attempt denominator "
      "includes all requests. SPICED gives the reviewer voltage/current logs, specifications and "
      "few-shot anomaly rules as well as the netlist [2, Sec. IV and Table III]. Our netlist-only "
      "reviewer must infer behavior from structure, which may help explain why an electrically "
      "harmful branch can be described as harmless.")
    p("<b>Search and activation.</b> LATENT permits broader component/node edits, uses simulation-informed "
      "diagnosis and reverts to a previous undetected configuration after detection. It reports "
      "6-12 iterations and studies DC-activated Trojans [3, Secs. IV-V]. We use ten fixed attempts, "
      "a qualified finite menu, preceding-review feedback and no rollback, with transient charge "
      "accumulation. Our retrospective one-versus-ten comparison is therefore a request-budget "
      "summary, not a reproduction of LATENT's one-shot comparison. LATENT also uses GPT-4o-mini "
      "at temperature 0.3 for both roles; these results do not test whether a newer model improves "
      "attack or defense.")
    p("Does the LLM help the attacker or defender more?", "h2")
    p("The evidence supports a limited answer. Reviews often identify our effective modifications, "
      "but misses and inconsistent judgments prevent relying on the reviewer alone. Exposed "
      "feedback is associated with more op-amp escapes, yet detailed explanations do not outperform "
      "Boolean verdicts consistently and do not improve AND's per-attempt result. A designer could "
      "use explanations and simulation to investigate suspicious behavior; an attacker can use "
      "the same clues to choose revisions. We tested only feedback disclosure against a fixed "
      "reviewer. Without a non-LLM comparison or a defender that learns from reviews, we cannot "
      "quantify which side gains more overall.")
    p("The conclusions are bounded by four sessions per group, repeated netlists, calibrated "
      "controls and the repeat gate deviation. Electrical validity covers the declared nominal "
      "stimuli, not process variation or silicon. The main finding is that more feedback detail "
      "does not guarantee more evasion: search choices, repeated-review variation and the definition "
      "of success all matter.")
    p("References", "h2")
    p('[1] K. Yang et al. "A2: Analog Malicious Hardware." IEEE S&amp;P, 2016, pp. 18-37. '
      '<link href="https://doi.org/10.1109/SP.2016.10">doi:10.1109/SP.2016.10</link>.', "small")
    p('[2] J. Chaudhuri et al. "SPICED: Syntactical Bug and Trojan Pattern Identification in A/MS Circuits using LLM-Enhanced Detection." 2024. '
      '<link href="https://arxiv.org/abs/2408.16018v1">arXiv:2408.16018v1</link>.', "small")
    p('[3] J. Chaudhuri, A. Chaudhuri and K. Chakrabarty. "LATENT: LLM-Augmented Trojan Insertion and Evaluation Framework for Analog Netlist Topologies." 2025. '
      '<link href="https://arxiv.org/abs/2505.06364v1">arXiv:2505.06364v1</link>.', "small")
    p('Code and evidence: <link href="https://github.com/MikeJiahaoXu/a2-llm-trojan-study">github.com/MikeJiahaoXu/a2-llm-trojan-study</link>. '
      "AI tools assisted implementation and writing; measurements come from saved responses and simulations.", "small")
    pages = report.save(output)
    provenance = {"primary_run": primary_id, "replication_run": replication_id, "pages": pages,
                  "source_sha256": {primary_id: primary["source_sha256"], replication_id: replication["source_sha256"]},
                  "qualification_sha256": file_hash(ROOT / "results/proposal_validation/qualification_summary.json"),
                  "calibration_controls_sha256": calibration["source_sha256"],
                  "audit_sha256": audits,
                  "analysis_sha256": {str(diagnostic_path.relative_to(ROOT)): file_hash(diagnostic_path),
                                      str(budget_path.relative_to(ROOT)): file_hash(budget_path)},
                  "protocol_deviation_sha256": {str(deviation_path.relative_to(ROOT)): file_hash(deviation_path)},
                  "pdf_sha256": file_hash(output), "text_sha256": file_hash(output.with_suffix(".txt"))}
    output.with_suffix(".provenance.json").write_text(json.dumps(provenance, indent=2)+"\n")
    return {"output": str(output), "text": str(output.with_suffix('.txt')), "pages": pages,
            "word_count": len(" ".join(report.text).split())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--replication-id")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "output/pdf/A2_Trojan_LLM_Informal_Report.pdf")
    args = parser.parse_args()
    if args.validate_only:
        runs = [load_run(identifier) for identifier in (args.run_id, args.replication_id) if identifier]
        print(json.dumps([{key: run[key] for key in ("run_id", "unique_candidates", "distinct_netlists", "groups")} for run in runs], indent=2))
    elif args.replication_id is None:
        parser.error("--replication-id is required for the final report")
    else:
        print(json.dumps(build(args.run_id, args.replication_id, args.output), indent=2))


if __name__ == "__main__":
    main()
