#!/usr/bin/env python3
"""Build the proposal-scoped report from completed, audited experiment records.

This module never calls an API or runs a circuit simulation. It deliberately has
no fallback to earlier experiments and never manufactures missing results.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import html
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
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


def observed_case(primary, replication):
    """Select a trace deterministically, without manufacturing a useful example."""
    candidates = []
    for run_index, run in enumerate((primary, replication)):
        for row in run["unique_rows"]:
            if row["success"]:
                candidates.append((run_index, row["candidate_id"], row))
    if candidates:
        run_index, _, row = sorted(candidates, key=lambda value: (value[0], value[1]))[0]
        parameters = row["parameters"]
        metrics = row["simulation"]["metrics"]
        drop_key = "trigger_recovery_drop_v" if row["circuit"] == "opamp" else "trigger_output_drop_v"
        normal_key = "normal_max_deviation_v" if row["circuit"] == "opamp" else "normal_settled_max_deviation_v"
        rationale = re.split(r"(?<=[.!?])\s+", row["detector"]["feedback_text"].strip())[0]
        words = rationale.split()
        if len(words) > 28:
            rationale = " ".join(words[:28])+" ..."
        repeated = [other for run in (primary, replication) for other in run["unique_rows"]
                    if other.get("netlist_sha256") == row["netlist_sha256"] and other.get("detector")]
        flagged = sum(other["detector"]["is_trojan"] is True for other in repeated)
        circuit_name = "AND4" if row["circuit"] == "and4" else "op-amp"
        representation = "MOSFET" if parameters["representation"] == "mosfet" else parameters["representation"]
        return (f"One unflagged {circuit_name} candidate uses "
                f"{html.escape(parameters['insertion_site'].replace('_', ' '))}, {representation}, "
                f"profile {parameters['trigger_profile']} and {parameters['strength']} strength. Its output "
                f"disturbance is {metrics[drop_key]:.3f} V; normal deviation is {metrics[normal_key]*1e6:.3f} "
                f"microvolts. The review states: &quot;{html.escape(rationale)}&quot; Across both runs, this "
                f"exact netlist is flagged in {flagged}/{len(repeated)} recorded candidate reviews. "
                "These are repeated judgments of one circuit, not additional circuit families "
                "or proof that feedback caused the miss.")
    return ("No physically valid candidate received a negative review in either run. Consequently, there "
            "is no observed successful trajectory to explain as feedback-driven concealment. The relevant "
            "negative finding is that this search over the qualified menu did not reveal an escape from "
            "the fixed reviewer within the recorded attempts; it does not establish that other circuits, "
            "larger edit spaces, or differently trained reviewers would behave the same way.")


def comparison_sentence(run):
    """A data-dependent description, without enforcing the proposed hypothesis."""
    statements = []
    for circuit in CIRCUITS:
        gs = [group(run, circuit, level) for level in LEVELS]
        rates = [g["successes"] / g["attempts"] for g in gs]
        counts = ", ".join(f"{level}: {g['successes']}/{g['attempts']}" for level, g in zip(LEVELS, gs))
        if rates[0] < rates[1] < rates[2]:
            interpretation = "The observed rates follow the proposed increasing order"
        elif len(set(rates)) == 1:
            interpretation = "The three observed rates are equal, so this comparison does not identify a feedback advantage"
        else:
            interpretation = "The observed rates do not follow a strictly increasing none-to-binary-to-full order"
        statements.append(f"{NAMES[circuit]} ({counts}). {interpretation}.")
    return " ".join(statements)


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
                                          ("h2", 11, 14, True), ("body", 9.3, 13, False),
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
    initial_successes = {c: sum(row["success"] for run in (primary, replication) for row in run["unique_rows"]
                                if row["circuit"] == c and row["round"] == 0) for c in CIRCUITS}

    # Page 1: research question and controlled comparison.
    p("A2 Trojans in the LLM Era", "title")
    p("Do More Detailed Detector Responses Help an Attacker?", "h2")
    p("Amber Tsao (cctsao) and Jiahao Xu (e1583425)<br/>Information Security course project | November 1, 2026", "small")
    p("Research question", "h2")
    p("A circuit-security reviewer may explain a suspicious modification so that a designer can investigate it. "
      "An attacker who receives the same explanation may instead use it to revise the modification. We study "
      "this tension through the proposal's minimal LLM-A2 loop: two compact circuits, a constrained attacker, "
      "a fixed detector, and three levels of detector feedback. The question is whether giving the attacker "
      "more detailed feedback increases the rate of electrically effective modifications that the detector does not flag.")
    p("A2 demonstrates malicious hardware using analog charge accumulation [1]. SPICED uses LLMs to identify "
      "Trojan components and affected nodes [2], while LATENT iteratively modifies netlists using detector "
      "feedback [3]. Our project implements their attacker-detector interaction at course-project scale using "
      "ngspice, a two-stage op-amp and a four-input AND gate. It omits syntax-repair evaluation and uses "
      "the proposal's permitted JSON-to-verified-template implementation.")
    p("Exactly three feedback conditions", "h2")
    table(["Condition", "Information available when proposing the next candidate"], [
        ["None", "Circuit, test conditions and permitted edits. Every attempt is a fresh proposal; no previous candidate or review is shown."],
        ["Binary", "The same task information, the preceding candidate's parameters and only the preceding is_trojan verdict."],
        ["Full", "The same task information and preceding parameters, plus the complete reviewer JSON: verdict, confidence, suspicious identifiers and explanation/suggestion."],
    ], [70, 446])
    p(f"Both roles use {html.escape(config['model'])} at temperature {config['temperature']}; no model is fine-tuned. "
      "Each circuit/condition has two ten-attempt starts, or 20 recorded opportunities. The first candidate "
      "and its review are shared across conditions within a start. Binary and full subsequently revise their "
      "own immediately preceding candidate; none continues independent generation. Thus each run has 120 "
      "condition rows but 112 actual candidate-generation/review events. A predeclared second run uses "
      "new seeds and the same generation/review settings. Its changed control-continuation rule is "
      "disclosed on page 4; both run identifiers and seeds were fixed before the first experiment.")
    p("The detector is stateless and sees only the nominal circuit function and candidate netlist. It receives "
      "no clean reference, true label, simulation traces or attack history. No arm receives simulator feedback. "
      "All allowed circuit choices are electrically qualified beforehand, and each generated candidate is "
      "simulated again. Prompts and circuit code are frozen across both runs; there is no success-based early stopping.")

    # Page 2: what is physically verified, and what is abstracted.
    report.new_page()
    p("Circuit verification and permitted edits", "h1")
    op = clean["opamp"]["metrics"]
    gate = clean["and4"]["metrics"]
    table(["Clean benchmark", "Measured behavior at the nominal operating point"], [
        ["Two-stage op-amp", f"DC gain {op['dc_gain_db']:.2f} dB; -3 dB bandwidth {op['bandwidth_3db_hz']:.2f} Hz; unity-gain frequency {op['unity_gain_hz']/1e6:.3f} MHz; phase margin {op['phase_margin_deg']:.2f} degrees."],
        ["Four-input AND", f"{gate['truth_table_passed']}/16 truth-table cases pass. Rise delay {gate['rise_delay_ns']:.4f} ns; fall delay {gate['fall_delay_ns']:.4f} ns when all four inputs fall together. Load: 100 fF; input edge: 100 ps."],
    ], [112, 404])
    p("Both circuits operate at 3.3 V with pedagogical transistor models. The inserted trigger uses input "
      "transitions, a coupling capacitor, two diodes, a 10 pF charge reservoir and a bleed resistor. When the "
      "reservoir crosses a threshold, an added branch disturbs the output or an internal bias/gain node. "
      "This is an A2-inspired simulation abstraction, not the fabricated A2 processor or a layout-level attack.")
    p("The attacker selects four categorical JSON fields: insertion site, device representation, trigger "
      "profile and loading strength. Op-amp sites are the output, first-stage gain node and PMOS mirror "
      "reference node; AND sites are the final output and internal NAND output. Three representations "
      "implement a thresholded resistive switch, smooth state-dependent conductance, or an added MOSFET "
      "driven by an ideal reservoir comparator. Three fixed RC/threshold profiles and three strengths "
      "complete the menu. Identifiers are fixed, and the original circuit core cannot be edited.")
    p("Electrical acceptance", "h2")
    p("The op-amp must remain within 20 mV of the clean follower during normal operation and produce at "
      "least 0.3 V output reduction at absolute time 50-60 us. The activating burst lasts from 5 to 45 us. "
      "Normal input is 1.65 V +/- 50 mV at 10 kHz; the burst spans 0.6-2.7 V at 1 MHz, so both swing and "
      "frequency change. The AND must preserve all 16 truth-table cases and settled output within 0.2 V, "
      "then reduce its high output by at least 0.8 V during the late 1 MHz burst with the other inputs high.")
    records = qualification["records"]
    minima = {c: min(record["validation"]["metrics"]["trigger_recovery_drop_v" if c == "opamp" else "trigger_output_drop_v"] for record in records if record["circuit"] == c) for c in CIRCUITS}
    p(f"All {qualification['groups']['opamp']['passed']}/{qualification['groups']['opamp']['combinations']} op-amp and "
      f"{qualification['groups']['and4']['passed']}/{qualification['groups']['and4']['combinations']} AND menu combinations "
      "pass both dormant and activated checks, including an independent uniformly sampled waveform check. "
      f"The smallest output disturbances are {minima['opamp']:.3f} V and {minima['and4']:.3f} V, respectively. "
      "This qualification covers the complete finite menu under the stated nominal stimuli; it does not "
      "cover arbitrary component values, process/voltage/temperature variation, or silicon behavior.")
    report.figure(waveform)
    p("Figure 1. Existing ngspice traces for the clean circuit and known-positive control. Left: op-amp "
      "recovery after the burst. Right: AND output during late burst activity. These controls illustrate "
      "the electrical effect; the LLM reviewer is not given these traces.", "small")

    # Page 3: primary six-group results and control evidence.
    report.new_page()
    p("Six-group experiment: first run", "h1")
    p("We define successful evasion as a candidate that passes both electrical checks and receives "
      "is_trojan=false. The primary rate divides this count by every recorded attempt. The conditional "
      "rate divides by physically valid attempts only. A missing or malformed output, failed simulation, "
      "or ineffective payload remains an unsuccessful attempt; a negative review alone is insufficient.")
    table(["Circuit", "Feedback", "Valid", "Evades / all", "Evades / valid", "Distinct netlists"], [
        [NAMES[g["circuit"]], g["feedback"], f"{g['valid']}/{g['attempts']}",
         fraction(g["successes"], g["attempts"]), fraction(g["successes"], g["valid"]), g["distinct_netlists"]]
        for g in primary["groups"]], [101, 61, 48, 108, 108, 90])
    p("Table 1. Every group has 20 opportunities. Distinct-netlist counts use exact netlist hashes; "
      "repeated proposals and the shared first attempt remain visible in the experiment counts.", "small")
    p(comparison_sentence(primary))
    p("Detector controls", "h2")
    control_lookup = {(item["circuit"], item["label"]): item for item in primary["control_groups"]}
    table(["Circuit", "Clean design flagged", "Known positive flagged"], [
        [NAMES[c], f"{control_lookup[c,'clean']['flagged']}/{control_lookup[c,'clean']['judgments']}",
         f"{control_lookup[c,'positive']['flagged']}/{control_lookup[c,'positive']['judgments']}"] for c in CIRCUITS], [180, 168, 168])
    p(f"During control calibration, {calibration['stages']} prompt refinements used recorded control results "
      "to address clean false flags and known-positive misses, clarifying ordinary circuit motifs, SPICE "
      "connectivity and internal conditional state. Both preceded every attack in the final experiment. "
      "Final controls reuse these benchmark designs and are not held out.")
    p("The prespecified gate requires at most one clean flag and at least four known-positive flags "
      "across five judgments of each circuit. These repetitions assess four specific designs, not general "
      "false-positive or recall rates over unseen designs. Reviewer confidence is self-reported and uncalibrated.")
    p("What the comparison can identify", "h2")
    p(f"The first run contains {primary['unique_candidates']} actual candidate events and "
      f"{primary['distinct_netlists']} distinct netlist texts. Shared starting candidates improve comparability, "
      "but adaptive attempts within a start depend on preceding responses. We therefore treat the rates "
      "as descriptive observations and do not attach independent-binomial significance tests to the "
      "20 attempt rows. None versus the feedback conditions also changes access to the preceding "
      "candidate; binary versus full more directly compares the amount of reviewer detail.")
    p(observed_case(primary, replication))

    # Page 4: same-settings stability run with a disclosed continuation deviation.
    report.new_page()
    p("Stability of the same three conditions", "h1")
    repeat_controls = {(item["circuit"], item["label"]): item for item in replication["control_groups"]}
    if any(repeat_controls[c, "clean"]["flagged"] != 0 or repeat_controls[c, "positive"]["flagged"] != 3
           or control_lookup[c, "positive"]["flagged"] != 4 for c in CIRCUITS):
        raise ValueError("Actual control results changed; revise the specific continuation disclosure")
    p("The second run uses new API requests and seeds with the same model, prompts, finite circuit menu, "
      "stimuli, electrical acceptance thresholds and ten-attempt structure. Its clean controls have "
      "0/5 flags for each circuit, but known positives are flagged only 3/5 times each, below the "
      "prespecified 4/5 requirement and the first run's 4/5 results. After observing the first-run results "
      "and repeat controls, an explicit continuation-rule deviation was recorded before second-run "
      "attack trials. No prompt, seed or circuit setting was "
      "changed and controls were not rerun. This is a same-settings stability assessment, not confirmation "
      "that passed the original control gate.")
    table(["Circuit", "Feedback", "First run", "Repeat run", "Combined", "Starts with evasion"], [
        [NAMES[c], level, f"{group(primary,c,level)['successes']}/20", f"{group(replication,c,level)['successes']}/20",
         fraction(aggregate[c,level]["successes"], 40),
         f"{aggregate[c,level]['trajectory_successes']}/{aggregate[c,level]['trajectories']}"]
        for c in CIRCUITS for level in LEVELS], [101, 61, 72, 72, 107, 103])
    p("Table 2. Counts are physically valid, unflagged attempts. The last column counts starts containing "
      "at least one such result. For none, a start simply groups ten fresh independent proposals. Shared "
      "first attempts create cross-condition dependence; combined rates summarize the observations "
      "without making the individual rows independent.", "small")
    report.figure(comparison)
    p("Figure 2. Primary evasion rates in the first and repeat runs, with raw counts. The vertical scale "
      "is common to both circuits. The paper's component-localization percentages are not plotted as "
      "directly comparable reference bars.", "small")
    p(comparison_sentence(replication))
    p(f"Before any feedback, {initial_successes['opamp']}/4 op-amp and {initial_successes['and4']}/4 AND "
      "starting candidates already receive a negative review. These shared initial outcomes contribute "
      "to all three conditions and cannot be attributed to feedback.")
    p(f"Across both runs there are {total_rows} condition rows, {total_events} actual candidate events "
      f"and {distinct_union} distinct netlists. Electrical validity is {valid_rows}/{total_rows}. "
      "High validity reflects selection from a qualified menu, not evidence that an LLM can reliably "
      "synthesize arbitrary malicious transistor circuits.")

    # Page 5: bounded interpretation and primary-source references.
    report.new_page()
    p("Interpretation and limitations", "h1")
    pooled = [f"{NAMES[c]}: " + ", ".join(f"{level} {aggregate[c,level]['successes']}/40" for level in LEVELS)
              for c in CIRCUITS]
    full_advantage = all(group(run,c,"full")["successes"] > group(run,c,"binary")["successes"]
                         for run in (primary,replication) for c in CIRCUITS)
    comparison = ("Full feedback has a consistent observed advantage over binary feedback in these runs. "
                  if full_advantage else "Full feedback has no consistent observed advantage over binary feedback. ")
    p("The combined observations are " + "; ".join(pooled) + ". " + comparison
      + "Four starts per circuit/condition across two runs provide limited evidence about stability, "
      "and cannot establish general statistical superiority or a universal ordering of none, binary "
      "and full feedback. The repeat's positive-control failure weakens any claim of confirmation "
      "and shows that reviewer sensitivity varies even for fixed known-positive designs.")
    if all(row["success"] is False for run in (primary, replication) for row in run["unique_rows"]):
        p("The observations do not show feedback-assisted evasion. At this detection ceiling, equal zero "
          "rates cannot tell whether detailed feedback is intrinsically unhelpful or the allowed designs "
          "all retain a recognizable mechanism. The appropriate conclusion is that no benefit was "
          "identified within the stated experiment, rather than that defensive feedback is safe to disclose in general.")
    else:
        p("An effective circuit receiving a negative review demonstrates a detector miss within this "
          "experiment. A greater count in an adaptive condition is consistent with feedback helping "
          "selection, but small samples, repeated netlists and stochastic judgments limit that "
          "interpretation. A single miss does not demonstrate reliable concealment. We retain the "
          "complete condition results rather than selecting only trajectories that support the proposed trend.")
    p("Relationship to SPICED and LATENT", "h2")
    p("SPICED's detector uses voltage/current simulation logs, specifications and anomaly rules with "
      "few-shot examples [2, Sec. IV and Table III]. Our netlist-only reviewer follows the minimal detector "
      "specified in the project plan, so it tests structural reasoning rather than reproducing SPICED's "
      "complete detection pipeline. Its explanations may contain errors even when its Boolean label is "
      "correct; explanation quality is not independently scored here.")
    p("LATENT permits component-type and insertion-node changes, uses simulation-informed diagnosis "
      "and reversion, and reports 6-12 iterations in Table I [3]. It describes DC-activated Trojans, "
      "whereas our tests use transient charge accumulation. Most importantly, its 23.7% one-shot and "
      "94.4% iterative figures average the proportion of inserted Trojan components escaping "
      "localization in resulting designs, not successful whole-candidate attempts. Those figures motivate "
      "the feedback question but are not numerical targets or acceptance criteria for this project.")
    p("Scope of the conclusion", "h2")
    p("The finite menu improves electrical interpretability while limiting attack diversity. Qualification "
      "covers the exact nominal tests, not rare-input coverage, process variation or fabricated hardware. "
      "Op-amp activation changes amplitude and frequency together, so it is not a frequency-only causal "
      "experiment. The same model family supplies both roles, and control examples are specific to the "
      "two benchmarks. These choices support a reproducible course-scale comparison of feedback detail, "
      "not a general evaluation of LLM hardware-security assurance.")
    p("References and availability", "h2")
    p('[1] K. Yang, M. Hicks, Q. Dong, T. Austin and D. Sylvester. "A2: Analog Malicious Hardware." IEEE S&amp;P, 2016, pp. 18-37. '
      '<link href="https://doi.org/10.1109/SP.2016.10">doi:10.1109/SP.2016.10</link>.', "small")
    p('[2] J. Chaudhuri, D. Thapar, A. Chaudhuri, F. Firouzi and K. Chakrabarty. "SPICED: Syntactical Bug and Trojan Pattern Identification in A/MS Circuits using LLM-Enhanced Detection." 2024. '
      '<link href="https://arxiv.org/abs/2408.16018">arXiv:2408.16018</link>.', "small")
    p('[3] J. Chaudhuri, A. Chaudhuri and K. Chakrabarty. "LATENT: LLM-Augmented Trojan Insertion and Evaluation Framework for Analog Netlist Topologies." 2025. '
      '<link href="https://arxiv.org/abs/2505.06364">arXiv:2505.06364</link>.', "small")
    p('Code, prompts, netlists and recorded evidence: <link href="https://github.com/MikeJiahaoXu/a2-llm-trojan-study">github.com/MikeJiahaoXu/a2-llm-trojan-study</link>. '
      "AI tools assisted implementation and report preparation; experimental quantities are computed from recorded API responses and simulator outputs.", "small")
    pages = report.save(output)
    provenance = {"primary_run": primary_id, "replication_run": replication_id, "pages": pages,
                  "source_sha256": {primary_id: primary["source_sha256"], replication_id: replication["source_sha256"]},
                  "qualification_sha256": file_hash(ROOT / "results/proposal_validation/qualification_summary.json"),
                  "calibration_controls_sha256": calibration["source_sha256"],
                  "audit_sha256": audits,
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
