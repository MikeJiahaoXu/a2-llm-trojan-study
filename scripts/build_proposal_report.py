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

    # Page 1: explain what an actual trial does before presenting results.
    p("A2 Trojans in the LLM Era", "title")
    p("Does Detector Feedback Help an Attacker?", "h2")
    p("Amber Tsao (cctsao) and Jiahao Xu (e1583425)<br/>Information Security course project | Experiments: November 1, 2026 | Revised: November 2, 2026", "small")
    p("A useful security review explains why a circuit looks suspicious. That explanation can help a "
      "designer fix a problem, but it can also tell an attacker what to change. We investigate this "
      "possibility by connecting an LLM that proposes circuit modifications to an LLM that reviews "
      "them, then varying how much of the review is returned to the attacker.")
    p("The project draws on A2's analog charge-accumulation trigger [1], SPICED's LLM-based detection [2] "
      "and LATENT's feedback-guided insertion loop [3]. We use ngspice and two small circuits: a "
      "two-stage op-amp and a four-input AND gate. Following the proposal's bounded implementation, "
      "the attacker chooses JSON parameters for verified templates; it does not write an unrestricted "
      "netlist. We omit syntax-repair evaluation.")
    p("One attempt, from proposal to feedback", "h2")
    p("First, the attacker receives the clean netlist, normal and activating test conditions, and a menu "
      "of permitted changes. It returns four choices: an insertion site, a device representation, a "
      "trigger profile and a loading strength. For example, an AND proposal can select a MOSFET branch "
      "from the output to ground, with trigger profile p2 and medium strength. Python translates these "
      "choices into actual SPICE components while preserving the original circuit.")
    p("Next, ngspice runs the modified circuit under normal inputs and an activating burst. Separately, "
      "the detector receives only the candidate netlist and its nominal function. It returns a Boolean "
      "Trojan verdict, confidence, suspicious identifiers and an explanation. The detector sees neither "
      "the clean reference nor simulation results. We count an escape only if the circuit passes both "
      "electrical checks and the detector returns is_trojan=false. Simulator results are recorded for "
      "evaluation but are not fed to either LLM.")
    table(["Condition", "Input to the next attacker request"], [
        ["None", "A fresh task with no preceding candidate or reviewer response."],
        ["Binary", "The preceding candidate's parameters and only the Boolean verdict."],
        ["Full", "The preceding parameters and complete review, including suspicious nodes and explanation."],
    ], [70, 446])
    p("Each request produces a complete next configuration. The loop does not retain a best-so-far "
      "candidate or stop after an escape; it continues for the fixed number of attempts. Thus feedback "
      "can lead to a useful revision, an unnecessary change, or a return to an earlier design.")
    p(f"Both roles use {html.escape(config['model'])} at temperature {config['temperature']}. Each circuit/condition "
      "has two starts of ten attempts, giving 20 opportunities per run. The first candidate and review "
      "are shared across the three conditions within a start. A second run uses new seeds with the "
      "same model, prompts and circuit settings; its failed control gate and continuation decision are "
      "reported on page 3. Together the runs contain 240 table entries, 224 actual proposal/review "
      "events and 29 distinct netlists.")

    # Page 2: physical mechanism and what qualification establishes.
    report.new_page()
    p("What the circuit modifications do", "h1")
    p("The added trigger senses input transitions through a coupling capacitor. Two diodes charge a "
      "10 pF reservoir, while a bleed resistor lets the charge decay. Closely spaced transitions can "
      "raise the reservoir above a threshold and turn on an added branch. The branch then pulls an "
      "output or internal node toward a supply rail. Under ordinary activity it should remain dormant; "
      "under the activating stimulus it should change the circuit's output.")
    p("The op-amp permits three insertion sites: its output, first-stage gain node and PMOS mirror "
      "reference node. The AND permits two: the final output and the intermediate NAND output that "
      "feeds its inverter. Each site has three device representations (switch, smooth conductance or "
      "MOSFET), three RC/threshold profiles and three loading strengths. This gives 81 op-amp and "
      "54 AND choices. The MOSFET version uses an ideal reservoir comparator; all versions are "
      "A2-inspired simulation models rather than fabricated A2 hardware.")
    op = clean["opamp"]["metrics"]
    gate = clean["and4"]["metrics"]
    table(["Clean circuit", "Verification at 3.3 V"], [
        ["Two-stage op-amp", f"DC gain {op['dc_gain_db']:.2f} dB; -3 dB bandwidth {op['bandwidth_3db_hz']:.2f} Hz; unity-gain frequency {op['unity_gain_hz']/1e6:.3f} MHz; phase margin {op['phase_margin_deg']:.2f} degrees."],
        ["Four-input AND", f"{gate['truth_table_passed']}/16 truth-table cases pass. Rise delay {gate['rise_delay_ns']:.4f} ns and simultaneous four-input fall delay {gate['fall_delay_ns']:.4f} ns, with a 100 fF load and 100 ps input edges."],
    ], [112, 404])
    p("For the modified op-amp, normal follower output must remain within 20 mV of the clean reference. "
      "The activating burst runs from 5 to 45 us, and output must fall at least 0.3 V below the reference "
      "during recovery at absolute time 50-60 us. Normal input is 1.65 V +/- 50 mV at 10 kHz; the burst "
      "spans 0.6-2.7 V at 1 MHz. Because both amplitude and frequency change, this test does not isolate "
      "frequency as the cause of activation.")
    p("The modified AND must preserve all 16 logic cases and settled output within 0.2 V of the reference. "
      "During a 1 MHz burst on input a with b, c and d high, its high output must be reduced by at least "
      "0.8 V. These checks distinguish an effective hidden modification from a circuit that merely looks unusual.")
    records = qualification["records"]
    minima = {c: min(record["validation"]["metrics"]["trigger_recovery_drop_v" if c == "opamp" else "trigger_output_drop_v"] for record in records if record["circuit"] == c) for c in CIRCUITS}
    p(f"All 81 op-amp and 54 AND choices passed these tests before the LLM runs; the smallest activating "
      f"output changes were {minima['opamp']:.3f} V and {minima['and4']:.3f} V. Every generated candidate "
      "was simulated again. Consequently, high validity means that the LLM selected from an electrically "
      "qualified menu, not that it learned to synthesize arbitrary working Trojans.")
    report.figure(waveform)
    p("Figure 1. Clean and known-positive control waveforms: op-amp recovery after the burst (left) "
      "and AND output during the burst (right). The reviewer is not given these traces.", "small")

    # Page 3: consolidate counts so the discussion has room for mechanisms.
    report.new_page()
    p("Results of the six-group comparison", "h1")
    p(f"Electrical checks passed for {valid_events}/{total_events} actual candidate events and "
      f"{valid_rows}/{total_rows} table entries, so the escape rate and the rate conditional on validity "
      "are equal here. The table retains every attempt, "
      "including repeated netlists and shared first attempts. The combined column is a descriptive "
      "summary; adaptive steps within a start are not independent samples.")
    table(["Circuit", "Feedback", "First run", "Repeat run", "Combined"], [
        [NAMES[c], level, f"{group(primary,c,level)['successes']}/20", f"{group(replication,c,level)['successes']}/20",
         fraction(aggregate[c,level]["successes"], 40)] for c in CIRCUITS for level in LEVELS],
          [130, 76, 92, 92, 126])
    p("Table 1. Physically valid candidates receiving a negative Trojan verdict. Each run has the "
      "same two circuits and three feedback conditions.", "small")
    report.figure(comparison)
    p("Figure 2. Escape rates and raw counts for the first and repeat runs. Both panels use the same scale.", "small")
    p("The op-amp shows more escapes with either form of feedback than with none, but binary and full "
      "tie at 13/40 after combining the runs. For AND, the combined order is reversed: none 10/40, "
      "binary 9/40 and full 6/40. The proposed none &lt; binary &lt; full trend therefore does not "
      "reproduce across the two circuits and runs.")
    p("Controls and the repeat's limitation", "h2")
    p(f"We set a control gate of at most one clean flag and at least four known-positive flags in five "
      "judgments of each design. In the first run, both clean circuits were flagged 0/5 times and both "
      "known positives 4/5. The repeat again had 0/5 clean flags, but only 3/5 positive flags for each "
      "circuit, failing the gate. After the first-run results and repeat controls were known, an explicit "
      "continuation-rule deviation was recorded before repeat attacks. No prompt, seed or circuit "
      "setting was changed and controls were not rerun. The repeat is therefore a stability assessment "
      "with the same model and prompts, not confirmation that passed the original gate.")
    p(f"Two prompt refinements using recorded control results preceded every attack in the final "
      "experiment. Final controls reuse those benchmark designs and are not held out. Their "
      "counts describe repeated judgments of four designs, not general detector accuracy.")

    # Page 4: explain the AND outcome with actual choices and repeated judgments.
    report.new_page()
    p("Why did more feedback not help AND?", "h1")
    p("The AND result becomes clearer when we examine the actual choices. Both no-feedback groups "
      "produced the same configuration on every attempt: output_shunt, mosfet, trigger profile p2, "
      "medium strength. This adds a reservoir-controlled MOSFET from the output to ground. Profile p2 "
      "uses a 0.5 pF coupling capacitor, a 40 us decay constant and a 1.0 V threshold. When active, the "
      "extra MOSFET draws current from an output that should be high.")
    p(f"This circuit preserves normal output within {metrics['normal_settled_max_deviation_v']*1e6:.3f} "
      f"microvolts and reduces the activated high output by {metrics['trigger_output_drop_v']:.3f} V. "
      "It is therefore an effective modification under the stated tests. Yet the first no-feedback "
      "group escaped 4/20 times and the repeat escaped 6/20 times without changing the design. Across "
      f"all conditions, the identical netlist was flagged in {common['actual_reviews_all_arms']['flagged']}/"
      f"{common['actual_reviews_all_arms']['count']} actual reviews. Repeated sampling of the same "
      "input can therefore produce both labels; these misses are not evidence of successive improvements "
      "to the circuit.")
    p(f"One negative review called the additional components harmless: &quot;{html.escape(case_quote)}&quot; "
      "The simulated output disturbance contradicts that assessment. This illustrates "
      "the distinction between an LLM's structural interpretation of a netlist and an electrical check "
      "of what it does.")
    p("Where the feedback conditions spent their attempts", "h2")
    site_rows = []
    for label, run in (("First", primary), ("Repeat", replication)):
        for level in ("binary", "full"):
            rows = [row for row in run["rows"] if row["circuit"] == "and4" and row["feedback"] == level]
            internal = [row for row in rows if row["parameters"]["insertion_site"] == "nand_node_pullup"]
            output_rows = [row for row in rows if row["parameters"]["insertion_site"] == "output_shunt"]
            site_rows.append([label, level, f"{len(internal)}/{len(rows)}",
                              f"{sum(row['success'] for row in internal)}/{len(internal)}",
                              f"{sum(row['success'] for row in output_rows)}/{len(output_rows)}"])
    table(["Run", "Feedback", "Internal-site choices", "Internal-site escapes", "Output-site escapes"],
          site_rows, [60, 72, 128, 128, 128])
    p("Table 2. AND choices by insertion site. Binary and full each use the internal NAND node for "
      "10/20 attempts in each run. All 40 actual candidate-review events at that site returned a "
      "Trojan flag; repeated netlists are included.", "small")
    p("The internal branch pulls the NAND output high; the following inverter then drives the final "
      "AND output low. This is a direct interference with the logic path. It may be easier for the "
      "reviewer to recognize, but we did not isolate insertion site in a controlled comparison. What "
      "the records establish is that both feedback conditions spent half their attempts on choices "
      "that never escaped, while none kept sampling an occasionally missed output-shunt design.")
    p("This explains part of the difference from none. It does not explain full's lower rate by a "
      "larger share of internal insertions: that share is identical in binary and full. Their remaining "
      "choices differ in representation and parameters, and the same netlist can receive different "
      "judgments. The loop also keeps proposing revisions after an escape rather than preserving "
      "the successful candidate. These factors can erase a benefit from extra explanation; this small "
      "study cannot separate their individual causal effects.")

    # Page 5: contrast the op-amp, then answer the research question in scope.
    report.new_page()
    p("Interpretation and relation to prior work", "h1")
    op_none_unique = len({row["netlist_sha256"] for run in (primary,replication) for row in run["rows"]
                         if row["circuit"] == "opamp" and row["feedback"] == "none"})
    if op_none_unique != 1:
        raise ValueError("Op-amp baseline diversity changed; revise the interpretation")
    p("The op-amp provides a useful contrast. Its no-feedback groups also repeatedly chose "
      "one netlist configuration, which was always detected. Binary and full explored "
      "output, gain-node and mirror-reference modifications, and each produced 13 escapes in 40 "
      "attempts. A plausible reading is that conditioning on a preceding proposal and review helped "
      "the attacker move away from an easily recognized default. The explanations themselves did "
      "not show a repeatable advantage over the Boolean verdict: full was slightly ahead in the "
      "first run, and binary was ahead in the repeat.")
    p("This is a comparison of the complete feedback conditions, not a clean separation of memory "
      "from explanation. None sees no preceding candidate, whereas binary and full do. The finite "
      "menus also constrain exploration: AND has 54 possible choices and the op-amp 81. A smaller "
      "menu may leave fewer alternatives, but circuit complexity and menu size were not varied "
      "independently. We cannot conclude that AND's simplicity caused its result. Repeated netlists "
      "and only four starts per circuit/condition further limit inference from the attempt counts.")
    p("Why the paper percentages are different", "h2")
    p("SPICED combines netlists with voltage/current logs, specifications and few-shot anomaly rules "
      "[2, Sec. IV and Table III]. Our netlist-only detector follows the minimal implementation in "
      "the project plan. LATENT allows broader component and node changes, uses simulation-informed "
      "diagnosis and reversion, and reports 6-12 iterations [3, Table I]. Our attacker selects from "
      "a finite menu and receives only the preceding review; there is no best-candidate rollback.")
    p("LATENT's reported 23.7% one-shot and 94.4% iterative values measure the proportion of inserted "
      "Trojan components escaping localization in resulting designs. Our rate counts electrically "
      "valid whole candidates receiving a negative verdict. LATENT also describes DC-activated "
      "Trojans, while our tests use transient charge accumulation. Its numbers motivate the question "
      "but are not comparable targets for this experiment.")
    p("What we learned", "h2")
    p("The loop demonstrates that a circuit can pass normal checks, activate a substantial disturbance "
      "and still be missed by an LLM reviewer. The op-amp revision conditions explored more alternatives, "
      "but detailed feedback did not consistently outperform a binary verdict. The AND "
      "case shows why more explanation need not improve evasion: revisions can move toward "
      "consistently detected choices, while repeated reviews of an unchanged design can already yield "
      "misses. We therefore found neither reliable protection from the reviewer nor a general increase "
      "in attack success with feedback detail.")
    p("These conclusions apply to the fixed model, prompts and nominal circuit tests. Electrical "
      "qualification does not cover process variation or silicon behavior. The repeat's failed "
      "positive-control gate also prevents treating it as a clean confirmation. A larger study would "
      "need more independent starts and controlled changes to individual design choices before "
      "assigning causes to the observed differences.")
    p("References", "h2")
    p('[1] K. Yang, M. Hicks, Q. Dong, T. Austin and D. Sylvester. "A2: Analog Malicious Hardware." IEEE S&amp;P, 2016, pp. 18-37. '
      '<link href="https://doi.org/10.1109/SP.2016.10">doi:10.1109/SP.2016.10</link>.', "small")
    p('[2] J. Chaudhuri, D. Thapar, A. Chaudhuri, F. Firouzi and K. Chakrabarty. "SPICED: Syntactical Bug and Trojan Pattern Identification in A/MS Circuits using LLM-Enhanced Detection." 2024. '
      '<link href="https://arxiv.org/abs/2408.16018v1">arXiv:2408.16018v1</link>.', "small")
    p('[3] J. Chaudhuri, A. Chaudhuri and K. Chakrabarty. "LATENT: LLM-Augmented Trojan Insertion and Evaluation Framework for Analog Netlist Topologies." 2025. '
      '<link href="https://arxiv.org/abs/2505.06364v1">arXiv:2505.06364v1</link>.', "small")
    p('Code and recorded evidence: <link href="https://github.com/MikeJiahaoXu/a2-llm-trojan-study">github.com/MikeJiahaoXu/a2-llm-trojan-study</link>. '
      "AI tools assisted implementation and writing; reported quantities come from saved API responses and simulations.", "small")
    pages = report.save(output)
    provenance = {"primary_run": primary_id, "replication_run": replication_id, "pages": pages,
                  "source_sha256": {primary_id: primary["source_sha256"], replication_id: replication["source_sha256"]},
                  "qualification_sha256": file_hash(ROOT / "results/proposal_validation/qualification_summary.json"),
                  "calibration_controls_sha256": calibration["source_sha256"],
                  "audit_sha256": audits,
                  "analysis_sha256": {str(diagnostic_path.relative_to(ROOT)): file_hash(diagnostic_path)},
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
