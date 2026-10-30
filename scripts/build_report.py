#!/usr/bin/env python3
"""Build a professor-facing informal report from completed local evidence.

No API calls, simulations, placeholder results, or edits to experiment records.
Run after the main experiment and summary: python -m scripts.build_report
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
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / "tmp" / "matplotlib"))


def read_json(path):
    return json.loads(path.read_text())


def pct(value, digits=0):
    return "n/a" if value is None else f"{100*value:.{digits}f}%"


def number(value, digits=2):
    return "n/a" if value is None else f"{value:.{digits}f}"


def _load_evidence(run_id):
    run_dir = ROOT / "results" / run_id
    completion = read_json(run_dir / "completion.json")
    if completion.get("complete") is not True:
        raise ValueError("Main experiment is not complete; report generation refused")
    summary = read_json(run_dir / "summary.json")
    if summary.get("complete") is not True:
        raise ValueError("Summary is incomplete; report generation refused")
    for name, expected in summary["source_sha256"].items():
        if hashlib.sha256((run_dir / name).read_bytes()).hexdigest() != expected:
            raise ValueError("Summary is stale: " + name)
    manifest = read_json(run_dir / "manifest.json")
    if summary["attempt_rows"] != 120 or summary["unique_candidates"] != 100:
        raise ValueError("Report layout expects the frozen 120-row, 100-candidate design")
    clean = read_json(ROOT / "results/validation/clean/summary.json")
    positive = {c: read_json(ROOT / "results/validation/positive" / c / "validation.json")
                for c in ("opamp", "and4")}
    if not all(clean[c]["passed"] and positive[c]["valid"] for c in clean):
        raise ValueError("Circuit verification is incomplete or failed; report generation refused")
    version = (ROOT / "results/environment/ngspice_version.txt").read_text()
    match = re.search(r"ngspice-([\w.]+)", version)
    return summary, manifest, clean, positive, match.group(1) if match else "version recorded in repository"


def _load_supplement(baseline_run):
    strong_dir = ROOT / "results/strong_attacker_v1"
    cross_dir = ROOT / "results/cross_review_v1"
    for folder in (strong_dir, cross_dir):
        if read_json(folder / "completion.json").get("complete") is not True:
            raise ValueError("Supplement is incomplete: " + folder.name)
    strong = read_json(strong_dir / "summary.json")
    cross = read_json(cross_dir / "summary.json")
    if strong.get("complete") is not True or cross.get("complete") is not True:
        raise ValueError("Supplementary summaries are incomplete")
    for filename, expected in strong["source_sha256"].items():
        if hashlib.sha256((strong_dir / filename).read_bytes()).hexdigest() != expected:
            raise ValueError("Strong-attacker summary is stale: " + filename)
    cross_manifest = read_json(cross_dir / "manifest.json")
    for run, expected in cross_manifest["source_attempt_hashes"].items():
        if hashlib.sha256((ROOT / "results" / run / "attempts.json").read_bytes()).hexdigest() != expected:
            raise ValueError("Cross-review source changed: " + run)
    if baseline_run not in cross_manifest["source_attempt_hashes"]:
        raise ValueError("Cross-review does not include the requested baseline")
    reviews = read_json(cross_dir / "reviews.json")
    if len(reviews) != cross["unique_netlists"]:
        raise ValueError("Cross-review summary and records disagree")
    stability_path = ROOT / "results/evasion_recheck_v1/summary.json"
    stability = read_json(stability_path)
    if stability.get("complete") is not True:
        raise ValueError("Post-hoc stability check is incomplete")
    return {"strong_summary": strong, "strong_config": read_json(strong_dir / "manifest.json")["config"],
            "strong_attempts": read_json(strong_dir / "attempts.json"),
            "cross_summary": cross, "reviews": reviews, "stability": stability}


def make_waveform_figure(destination):
    """Plot only existing clean/positive simulator traces, preserving their data."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    def load(circuit, kind):
        path = ROOT / "results/validation" / kind / circuit / "trigger.tsv"
        with path.open() as stream:
            columns = stream.readline().split()
        data = np.loadtxt(path, skiprows=1)
        return data[:, 0] * 1e6, data[:, columns.index("v(out)")]

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9,
                         "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(1, 2, figsize=(9.3, 2.55))
    for ax, circuit, limits, title in zip(axes, ("opamp", "and4"), ((45, 65), (35, 40)),
                                         ("Op-amp: recovery after the burst", "AND gate: output during the burst")):
        for kind, label, color, style in [("clean", "Clean circuit", "#607389", "--"),
                                           ("positive", "Positive control", "#218C85", "-")]:
            t, output = load(circuit, kind)
            select = (t >= limits[0]) & (t <= limits[1])
            ax.plot(t[select], output[select], color=color, label=label, linewidth=1.35, linestyle=style)
        ax.set_title(title, loc="left", fontsize=10, weight="bold")
        ax.set_xlabel("Time (us)"); ax.set_ylabel("Output (V)")
        ax.set_xlim(*limits); ax.grid(alpha=.16)
    axes[0].legend(frameon=False, fontsize=8, loc="best")
    fig.tight_layout(pad=1.3)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(destination, dpi=220)
    fig.savefig(destination.with_suffix(".pdf"))
    plt.close(fig)


def build(run_id="main_v2"):
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.utils import ImageReader
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, Image, PageBreak)
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    summary, manifest, clean, positive, spice_version = _load_evidence(run_id)
    supplement = _load_supplement(run_id)
    config = manifest["config"]
    attempts = read_json(ROOT / "results" / run_id / "attempts.json")
    groups = {(g["circuit"], g["feedback"]): g for g in summary["groups"]}
    controls = {(c["circuit"], c["label"]): c for c in summary["controls"]}
    clean_flags = sum(controls[c, "clean"]["flagged"] for c in config["circuits"])
    positive_flags = sum(controls[c, "positive"]["flagged"] for c in config["circuits"])
    prior_controls_path = ROOT / "results/main_v1/controls.json"
    prior_clean_flags = prior_clean_count = 0
    if run_id != "main_v1" and prior_controls_path.exists():
        prior_controls = [r for r in read_json(prior_controls_path) if r["label"] == "clean"]
        prior_clean_count = len(prior_controls)
        prior_clean_flags = sum(r["detector"]["is_trojan"] is True for r in prior_controls)
    out = ROOT / "output/pdf"
    out.mkdir(parents=True, exist_ok=True)
    waveform = out / "report_waveform_verification.png"
    make_waveform_figure(waveform)
    from scripts.eval.summarize import make_figures
    baseline_figures = out / "baseline_figures"
    make_figures(summary, config, baseline_figures)

    font = "Helvetica"
    bold = "Helvetica-Bold"
    candidates = [(Path("/System/Library/Fonts/Supplemental/Arial.ttf"), Path("/System/Library/Fonts/Supplemental/Arial Bold.ttf")),
                  (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"))]
    for regular_path, bold_path in candidates:
        if regular_path.exists() and bold_path.exists():
            pdfmetrics.registerFont(TTFont("ReportSans", str(regular_path)))
            pdfmetrics.registerFont(TTFont("ReportSansBold", str(bold_path)))
            pdfmetrics.registerFontFamily("ReportSans", normal="ReportSans", bold="ReportSansBold", italic="ReportSans", boldItalic="ReportSansBold")
            font, bold = "ReportSans", "ReportSansBold"
            break

    ink = colors.HexColor("#20344B")
    teal = colors.HexColor("#187F79")
    muted = colors.HexColor("#5B6875")
    pale = colors.HexColor("#EFF4F7")
    styles = {
        "title": ParagraphStyle("title", fontName=bold, fontSize=22, leading=26, textColor=ink, spaceAfter=8),
        "subtitle": ParagraphStyle("subtitle", fontName=font, fontSize=9, leading=12, textColor=muted, spaceAfter=12),
        "h1": ParagraphStyle("h1", fontName=bold, fontSize=16, leading=20, textColor=ink, spaceAfter=12),
        "h2": ParagraphStyle("h2", fontName=bold, fontSize=11.1, leading=14, textColor=teal, spaceBefore=7, spaceAfter=4),
        "body": ParagraphStyle("body", fontName=font, fontSize=9.3, leading=13, textColor=ink, spaceAfter=6),
        "small": ParagraphStyle("small", fontName=font, fontSize=8, leading=10.5, textColor=muted, spaceAfter=5),
        "caption": ParagraphStyle("caption", fontName=font, fontSize=8, leading=10.7, textColor=muted, spaceAfter=9),
        "cell": ParagraphStyle("cell", fontName=font, fontSize=8, leading=10.5, textColor=ink),
        "header": ParagraphStyle("header", fontName=bold, fontSize=8, leading=10.5, textColor=colors.white),
        "callout": ParagraphStyle("callout", fontName=font, fontSize=10, leading=14, textColor=ink),
    }
    story, text_blocks = [], []

    def plain(text):
        text = re.sub(r'<link href="([^"]+)"[^>]*>(.*?)</link>', r'\2 (\1)', text)
        return html.unescape(re.sub("<[^>]+>", "", text.replace("<br/>", "\n")))

    def p(text, style="body"):
        story.append(Paragraph(text, styles[style]))
        text_blocks.append(plain(text))

    def table(headers, rows, widths):
        rendered = [[Paragraph(html.escape(str(x)), styles["header"]) for x in headers]]
        rendered += [[Paragraph(html.escape(str(x)), styles["cell"]) for x in row] for row in rows]
        tab = Table(rendered, colWidths=widths, repeatRows=1, hAlign="LEFT")
        tab.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ink),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, pale]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, -1), (-1, -1), .5, colors.HexColor("#CFD8E0")),
        ]))
        story.extend([tab, Spacer(1, 7)])
        text_blocks.append(" | ".join(headers))
        text_blocks.extend(" | ".join(map(str, row)) for row in rows)

    def figure(path, width=516, height=None):
        iw, ih = ImageReader(str(path)).getSize()
        story.append(Image(str(path), width=width, height=height or width*ih/iw))

    def new_page():
        story.append(PageBreak())
        text_blocks.append("\n" + "="*60 + "\n")

    totals = {level: sum(groups[c, level]["valid_undetected"] for c in config["circuits"])
              for level in config["feedback_levels"]}
    valid_totals = {level: sum(groups[c, level]["valid"] for c in config["circuits"])
                    for level in config["feedback_levels"]}
    any_totals = {level: sum(groups[c, level]["trajectory_any_success"] for c in config["circuits"])
                  for level in config["feedback_levels"]}
    all_zero = sum(totals.values()) == 0
    no_valid_candidates = sum(valid_totals.values()) == 0
    full_delta = (totals["full"] - totals["none"]) / 40
    unique_attempts = {r["candidate_id"]: r for r in attempts}
    flagged_events = sum((r.get("detector") or {}).get("is_trojan") is True for r in unique_attempts.values())
    supplement_events = {r["candidate_id"]: r for r in supplement["strong_attempts"]}
    supplement_escapes = [r for r in supplement_events.values()
                         if r["simulation"]["valid"] and (r.get("detector") or {}).get("is_trojan") is False]
    if no_valid_candidates:
        takeaway = "No candidate satisfied both electrical validity criteria. This exploratory experiment therefore cannot identify the effect of detector feedback on evasion."
    elif all_zero and supplement_escapes:
        takeaway = (f"No valid candidate escaped in the baseline. A model-swap follow-up produced {len(supplement_escapes)} valid evasion event "
                    "against the same reviewer. This exploratory exception does not establish that more detailed feedback improves evasion.")
    elif all_zero:
        takeaway = (f"In the baseline, the reviewer flagged all {flagged_events} candidate-generation events, representing {summary['unique_netlists']} distinct netlist texts. "
                    "Feedback sometimes weakened the simulated payload, but the detection ceiling prevents identifying whether richer feedback improves evasion.")
    else:
        takeaway = (f"Full versus no feedback differed by {100*full_delta:+.1f} percentage points in valid evasion. "
                    "This exploratory comparison is conditional on two small circuits, a fixed attack template and five trajectories per condition.")

    # PAGE 1: question, protocol, and explicit endpoints.
    p("A2 Trojans in the LLM Era", "title")
    p("Does Detection Feedback Help an Attacker?<br/>An exploratory study of A2-inspired modifications in small circuit netlists", "subtitle")
    p("Amber Tsao (cctsao)  |  Jiahao Xu (e1583425)<br/>Information Security course project  |  30 October 2026", "subtitle")
    box = Table([[Paragraph(takeaway, styles["callout"])]], colWidths=[516])
    box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), pale),
                            ("BOX", (0, 0), (-1, -1), .5, colors.HexColor("#CAD9E2")),
                            ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                            ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    story.extend([box, Spacer(1, 9)]); text_blocks.append(takeaway)
    p("Research question", "h2")
    p("Diagnostic explanations help a designer locate suspicious circuitry, but the same explanation may tell an attacker what to change. We ask whether increasing access to an LLM reviewer's feedback helps an LLM produce a functioning circuit modification that the reviewer accepts. The distinction between functioning and merely unflagged matters: an attacker can make a circuit less conspicuous by weakening the very behavior it is meant to induce.")
    p("A2 [1] motivates an analog-state trigger that accumulates charge from signal transitions. SPICED [2] motivates LLM-assisted Trojan detection, and LATENT [3] motivates feedback-guided modification. We study a deliberately narrower setting with a two-stage operational amplifier and a four-input AND gate. Two simplifications define the experiment: the attacker selects parameters for a <b>fixed charge-pump/output-load template</b>, and the reviewer performs <b>netlist-only analysis</b>. This is not a reproduction of the original hardware or complete published frameworks.")
    p("Controlled feedback comparison", "h2")
    p("In the baseline, attacker and reviewer both use gpt-4o-mini-2024-07-18 at temperature 0.3, without fine-tuning. The attacker receives the clean circuit, parameter bounds, test conditions and one verified starting example. Its objective is to preserve normal behavior while inducing a disturbance. The reviewer receives only the candidate netlist and intended function. Separate stateless reviews keep attacker instructions and condition labels out of its input.")
    p("For each circuit, five separately seeded trajectories contain four attempts in each of three conditions. <b>None</b> generates each proposal without prior feedback. <b>Binary</b> receives the preceding parameters and a Boolean detection verdict. <b>Full</b> additionally receives confidence, suspect nodes and diagnostic text. The first candidate and verdict are shared across the three conditions. Later attempts use the same opportunity count and receive no simulation results. The comparison comprises 120 condition-specific rows from 100 generation events.")
    p("Binary versus full isolates feedback detail within the same revision procedure. Comparisons with none also change access to the preceding candidate, so they combine feedback and memory effects. Prompts are fixed during the final experiment, condition order is shuffled reproducibly, and all four attempts are retained. Repeated netlists are counted as repeated generations, not as additional circuit families.")
    p("Evaluation endpoints", "h2")
    p("The primary endpoint is <b>electrically valid AND reviewer-negative candidates / all attempts</b>. Validity requires acceptable behavior under the normal stimulus and a sufficient output disturbance under the activation stimulus. Secondary measures are evasion conditional on validity and at least one valid evasion within a trajectory. Invalid candidates remain failures. Because adaptive rounds are dependent, attempt proportions are descriptive; trajectory-level intervals use five starts and require an independence assumption.")

    # PAGE 2: grounded circuit checks and actual waveform artifacts.
    new_page()
    p("Circuit model and electrical validation", "h1")
    p(f"Simulation uses ngspice {spice_version}, 3.3 V and generic LEVEL=1 MOS models. The op-amp has two gain stages with Miller compensation; AND4 is a NAND4 followed by an inverter. Clean circuits and manually specified positive controls establish the intended normal and disturbed behavior. These are simulation measurements, not device characterization.")
    cm, cp = clean["opamp"]["metrics"], positive["opamp"]["metrics"]
    am, ap = clean["and4"]["metrics"], positive["and4"]["metrics"]
    dormant_opamp = "<0.001 mV" if cp['normal_max_deviation_v']*1e3 < .001 else f"{cp['normal_max_deviation_v']*1e3:.3f} mV"
    verification_rows = [
        ["Op-amp gain / bandwidth", f"{cm['dc_gain_db']:.2f} dB / {cm['bandwidth_3db_hz']:.1f} Hz", "Clean small-signal AC response"],
        ["Unity gain / phase margin", f"{cm['unity_gain_hz']/1e6:.2f} MHz / {cm['phase_margin_deg']:.1f} degrees", "Clean compensated feedback behavior"],
        ["Follower RMS error", f"{cm['follower_rmse_v']*1e3:.3f} mV", "1.65 V +/- 50 mV at 10 kHz"],
        ["AND truth table / delays", f"{am['truth_table_passed']}/16; rise {number(am.get('rise_delay_ns'),3)} ns; fall {number(am.get('fall_delay_ns'),3)} ns", "50% crossings; fall switches all four inputs"],
        ["Op-amp positive control", f"Dormant max deviation {dormant_opamp}; triggered drop {cp['trigger_recovery_drop_v']:.3f} V", "Pass: dormant <=20 mV; triggered >=0.3 V"],
        ["AND positive control", f"{ap['truth_table_passed']}/16; dormant deviation {ap['normal_settled_max_deviation_v']*1e3:.3f} mV; triggered drop {ap['trigger_output_drop_v']:.3f} V", "Pass: settled deviation <=0.2 V; triggered >=0.8 V"],
    ]
    table(["Check", "Measured result", "Meaning / criterion"], verification_rows, [133, 200, 183])
    figure(waveform, width=480)
    p("Figure 1. Clean and positive-control outputs under identical activation stimuli: op-amp recovery after the burst and AND late burst cycles. Both controls pass normal-stimulus checks and exceed the disturbance threshold.", "caption")
    p("Trigger abstraction and stimulus limits", "h2")
    p("A diode-capacitor network accumulates charge against resistive leakage. A thresholded switch or smooth behavioral current loads the output. The attacker varies representation, names and bounded component parameters while the core circuit stays fixed. These choices explore one mechanism, rather than unrestricted Trojan topologies.")
    p("The op-amp normal stimulus is a 10 kHz sinusoid at 1.65 V +/-50 mV; activation uses a 1 MHz burst between 0.6 and 2.7 V. <b>Both amplitude and frequency change.</b> The burst ends at t=45 us and recovery is evaluated at t=50-60 us. AND4 normal inputs enumerate 16 combinations at 20 us intervals; activation toggles one input at 1 MHz with the others high.")
    diagnostic_path = ROOT / "results/reaudit/simulation_audit.json"
    if diagnostic_path.exists():
        audit = read_json(diagnostic_path)
        diagnostic = audit["posthoc_diagnostics"]
        grid = {(r["frequency_hz"], r["swing_vpp"]): r for r in diagnostic["stimulus_grid"] if r["circuit"] == "opamp"}
        low_large = grid[(25000.0, 2.1)]
        high_large = grid[(1000000.0, 2.1)]
        p(f"A post-hoc amplitude-by-frequency check over 40 us found no output disturbance at 0.1 V peak-to-peak for either 25 kHz or 1 MHz. At 2.1 V peak-to-peak, 25 kHz produced a {low_large['peak_reservoir_v']:.3f} V reservoir peak and negligible disturbance; 1 MHz produced {high_large['peak_reservoir_v']:.3f} V and a {high_large['recovery_output_drop_v']:.3f} V drop. Both sufficient swing and rapid accumulation matter for this positive control. Separately, the AND single-input fall delay was {diagnostic['and4_single_sensitized_input_fall_delay_ns']:.3f} ns; it is a different transition from the tabulated all-input fall.", "small")

    # PAGE 3: report all six groups and small-n trajectory uncertainty.
    new_page()
    p("Baseline results: a detection ceiling", "h1")
    result_rows = []
    for c in ("opamp", "and4"):
        for level in config["feedback_levels"]:
            g = groups[c, level]
            interval = g["trajectory_wilson95"]
            result_rows.append(["Op-amp" if c == "opamp" else "AND4", level,
                                f"{g['valid']}/{g['attempts']}", f"{g['valid_undetected']}/{g['attempts']} ({pct(g['primary_rate'])})",
                                pct(g["conditional_evasion_rate"]),
                                f"{g['trajectory_any_success']}/5 [{pct(interval[0],1)}, {pct(interval[1],1)}]"])
    table(["Circuit", "Feedback", "Valid", "Primary success", "Given valid", "Any success; 95% CI"], result_rows, [61, 61, 46, 117, 70, 161])
    p("Primary = valid and undetected / all attempts. Given valid = valid and undetected / valid attempts. The last column counts trajectories with any success and gives a Wilson interval under independence of starts. The shared first round and adaptive later rounds are not independent attempts.", "caption")
    figure(baseline_figures / "attempt_outcomes.png", width=505, height=192)
    p("Figure 2. Electrical validity and detection outcomes for the six conditions. An invalid circuit is unsuccessful even if its modification appears less suspicious. The first-round candidate is shared across conditions; percentages describe condition-specific attempts.", "caption")
    unique_valid = sum(r["simulation"]["valid"] is True for r in unique_attempts.values())
    distinct_valid = len({r["netlist_sha256"] for r in unique_attempts.values() if r["simulation"]["valid"] and r.get("netlist_sha256")})
    distinct_by_circuit = {c: len({r["netlist_sha256"] for r in attempts if r["circuit"] == c and r.get("netlist_sha256")})
                          for c in config["circuits"]}
    p(f"All {flagged_events}/{len(unique_attempts)} generation events received a positive detection verdict, including all {unique_valid} electrically valid events. These events produced {summary['unique_netlists']} distinct netlist texts ({distinct_by_circuit['opamp']} op-amp, {distinct_by_circuit['and4']} AND), of which only {distinct_valid} were valid. The 120 rows include shared first rounds. Thus every condition has zero valid evasion, but the classification endpoint has no variation with which to estimate a feedback advantage.")
    initial = {(r["circuit"], r["trajectory"]): r for r in attempts if r["round"] == 0}
    examples = []
    for row in attempts:
        sim = row.get("simulation") or {}
        metrics = sim.get("metrics") or {}
        base = initial[row["circuit"], row["trajectory"]]
        if (row["circuit"] == "opamp" and row["feedback"] == "full" and row["round"] > 0
                and base["simulation"]["valid"] and sim.get("normal_ok") is True
                and sim.get("trigger_ok") is False and isinstance(metrics.get("trigger_recovery_drop_v"), (float, int))
                and (row.get("detector") or {}).get("is_trojan") is True):
            examples.append((row, base))
    if examples:
        row, base = min(examples, key=lambda pair: (pair[0]["simulation"]["metrics"]["trigger_recovery_drop_v"], pair[0]["candidate_id"]))
        drop = row["simulation"]["metrics"]["trigger_recovery_drop_v"]
        base_drop = base["simulation"]["metrics"]["trigger_recovery_drop_v"]
        p("Feedback revisions and payload effectiveness", "h2")
        p(f"In one op-amp trajectory, a full-feedback revision changed the output-load resistance from {base['parameters']['payload_ohms']:g} to {row['parameters']['payload_ohms']:g} ohms along with other parameters. The recovery disturbance fell from <b>{base_drop:.3f} V to {drop:.3f} V</b>, below the 0.3 V criterion, while normal behavior remained acceptable. Both candidates were detected. This example illustrates a loss of payload effectiveness, not concealment; simultaneous parameter changes prevent attributing the loss to resistance alone.")
    else:
        p("Separating generation quality from detection", "h2")
        p("A negative verdict is insufficient when the candidate no longer produces a functioning payload. The table therefore keeps physical-validity counts beside both unconditional and conditional success rates. This prevents an ineffective modification, a malformed response or a simulation failure from inflating apparent evasion. Which stage fails matters as much as the final success percentage.")
    sensitivity_path = ROOT / "results" / run_id / "threshold_sensitivity.json"
    if sensitivity_path.exists():
        sensitivity = read_json(sensitivity_path)
        loose = {r["feedback"]: r for r in sensitivity["groups"]
                 if r["circuit"] == "opamp" and r["threshold_v"] == .2}
        if set(loose) == set(config["feedback_levels"]):
            invariant = all(r["valid_undetected"] == 0 for r in sensitivity["groups"])
            p(f"<b>Post-hoc sensitivity check.</b> With a looser 0.2 V op-amp drop threshold, valid counts become {loose['none']['valid']}/20, {loose['binary']['valid']}/20 and {loose['full']['valid']}/20. Validity fractions therefore depend on the cutoff. "
              + ("Successful evasion remains zero under every tested threshold. " if invariant else "The saved sensitivity table records how success also changes. ")
              + "The primary threshold was not changed. The 0-43.4% interval for zero successes in five trajectories is conditional on this narrow setup, not a bound on all possible analog Trojans.", "small")

    # Supplementary page: role-specific model changes, not an adaptive two-model duel.
    new_page()
    p("Supplementary model comparison", "h1")
    strong = supplement["strong_summary"]
    strong_config = supplement["strong_config"]
    strong_groups = {(g["circuit"], g["feedback"]): g for g in strong["groups"]}
    strong_unique = {r["candidate_id"]: r for r in supplement["strong_attempts"]}
    strong_flagged = sum((r.get("detector") or {}).get("is_trojan") is True for r in strong_unique.values())
    strong_valid = sum(r["simulation"]["valid"] is True for r in strong_unique.values())
    strong_forms = {r["parameters"]["topology"] for r in strong_unique.values() if r.get("parameters")}
    strong_names = {r["parameters"]["name_style"] for r in strong_unique.values() if r.get("parameters")}
    p("These supplementary analyses were designed after observing the baseline detection ceiling. Their inclusion and deduplication rules were fixed before the additional generations, but they are exploratory follow-ups rather than independent confirmation. They address two different questions: whether a model change expands the attacker's search, and whether another reviewer reaches the same verdicts on frozen candidate circuits.")
    p("Changing the attacker", "h2")
    p(f"The first follow-up replaces only the attacker with <b>{strong_config['attacker_model']}</b>, retaining the GPT-4o mini reviewer, prompts, templates, test stimuli and thresholds. It repeats the six conditions with five starts and four attempts, sharing the first candidate within each model's feedback arms. Temperature remains 0.3 and reasoning effort is set to none. The alternative model receives no seed parameter; comparisons across models therefore do not pair identical random draws.")
    comparison_rows = []
    for circuit in ("opamp", "and4"):
        for level in config["feedback_levels"]:
            baseline_group = groups[circuit, level]
            extended_group = strong_groups[circuit, level]
            comparison_rows.append(["Op-amp" if circuit == "opamp" else "AND4", level,
                                    f"{baseline_group['valid']}/{baseline_group['attempts']}",
                                    f"{extended_group['valid']}/{extended_group['attempts']}",
                                    f"{extended_group['valid_undetected']}/{extended_group['attempts']}",
                                    f"{extended_group['trajectory_any_success']}/5"])
    table(["Circuit", "Feedback", "Baseline valid", "New model valid", "New model success", "Successful starts"],
          comparison_rows, [57, 59, 92, 104, 107, 97])
    p("Validity and success use the same electrical criteria in both experiments. Baseline valid evasion is zero in every group. New model success counts valid, reviewer-negative candidates, not all negative verdicts.", "caption")
    strong_controls = {(r["circuit"], r["label"]): r for r in strong["controls"]}
    p(f"Fresh checks of the unchanged reviewer flagged clean controls {strong_controls['opamp', 'clean']['flagged']}/5 and {strong_controls['and4', 'clean']['flagged']}/5, and positive controls {strong_controls['opamp', 'positive']['flagged']}/5 and {strong_controls['and4', 'positive']['flagged']}/5 (op-amp, AND4). These repeat the same control circuits.", "small")
    p(f"The alternative attacker produced {strong['unique_netlists']} distinct netlist texts from {len(strong_unique)} generation events; {strong_valid} events met the electrical criteria and {strong_flagged} were flagged by the unchanged reviewer. It used {len(strong_forms)} of three representations and {len(strong_names)} of three naming styles. This measures broader exploration of the permitted template, not independent physical attack mechanisms or an intrinsic model ranking.")
    p("Reviewing frozen candidates with another model", "h2")
    cross = supplement["cross_summary"]
    reviews = supplement["reviews"]
    p(f"A separate retrospective check uses <b>{cross['reviewer_model']}</b> with the fixed review prompt. Every distinct netlist text in the union of the two generation experiments is included once, irrespective of its validity or previous verdict. This compares reviewers on fixed inputs; the new reviewer's feedback is never returned to either attacker. It is therefore not an adaptive stronger-attacker/stronger-reviewer experiment.")
    cross_rows = []
    for circuit in ("opamp", "and4"):
        selected = [r for r in reviews if r["circuit"] == circuit]
        cross_rows.append(["Op-amp" if circuit == "opamp" else "AND4", len(selected),
                           sum(r["valid"] for r in selected),
                           sum(r["stronger_detector"]["is_trojan"] for r in selected),
                           sum(r["valid"] and not r["stronger_detector"]["is_trojan"] for r in selected)])
    table(["Circuit", "Distinct inputs", "Valid inputs", "New reviewer flags", "Valid inputs missed"],
          cross_rows, [72, 95, 95, 126, 128])
    cross_controls = {(r["circuit"], r["label"]): r for r in cross["controls"]}
    p(f"The new reviewer disagreed with the stored representative verdict on {cross['verdict_disagreements']}/{cross['unique_netlists']} distinct inputs. Its clean-control flags were {cross_controls['opamp', 'clean']['flagged']}/5 and {cross_controls['and4', 'clean']['flagged']}/5; positive-control flags were {cross_controls['opamp', 'positive']['flagged']}/5 and {cross_controls['and4', 'positive']['flagged']}/5. Each candidate has one new judgment, and the controls still repeat the same four designs. These denominators differ from the adaptive attempt counts.", "small")
    audit_paths = [ROOT / "results/reaudit/simulation_audit.json", ROOT / "results/reaudit/strong_all/simulation_audit.json"]
    if all(path.exists() for path in audit_paths):
        audits = [read_json(path) for path in audit_paths]
        if all(a["all_saved_simulation_metrics_match"] and a["all_independent_verdicts_agree"] and a["all_netlist_hashes_match"] for a in audits):
            p(f"Re-simulation reproduced the stored measurements for all {cross['unique_netlists']} distinct candidate netlists; an independent uniform-time calculation agreed with every validity classification. Code, prompts, netlists and measurements are available in the <link href=\"https://github.com/MikeJiahaoXu/a2-llm-trojan-study\" color=\"#187F79\">project repository</link>.", "small")

    # Final page: scientific interpretation, calibration, and limitations.
    new_page()
    p("Interpretation and limitations", "h1")
    if prior_clean_count:
        p("Detector calibration", "h2")
        p(f"During exploratory testing, the initial prompt mislabeled both clean circuits in every repeat ({prior_clean_flags}/{prior_clean_count} false flags). Before the final comparison, it was refined to recognize ordinary bias and compensation motifs and require trigger-to-payload evidence. Final clean-control flags were {controls['opamp', 'clean']['flagged']}/5 and {controls['and4', 'clean']['flagged']}/5; positive-control flags were {controls['opamp', 'positive']['flagged']}/5 and {controls['and4', 'positive']['flagged']}/5, for op-amp and AND4 respectively. These same circuits informed prompt development, so controls are not held out. Repeated judgments of four fixed netlists cannot estimate population false-positive rates or sensitivity.")
    if no_valid_candidates:
        p("No candidate passed both electrical criteria, so conditional evasion is undefined. This result concerns generation quality rather than reviewer robustness. A comparison of diagnostic-feedback leakage would first require a sufficiently diverse set of functioning modifications.")
    elif all_zero:
        p("Identifiability at the observed ceiling", "h2")
        p("The baseline is a bounded exploratory negative result: every allowed variant retains a recognizable charge-storage-to-output path, and every generated candidate is flagged. This ceiling prevents identifying a benefit from more detailed feedback. Validity differences show changed electrical behavior, not a general evasion effect. Neither the ceiling nor confidence scores establish broad reviewer robustness.")
    else:
        p(f"Full versus none differs by {100*full_delta:+.1f} percentage points in valid evasion. This is a descriptive result from five paired trajectories per circuit, not evidence of a general effect across hardware designs. Differences in physical validity and the limited modification family must be considered alongside the classification endpoint.")
    supplementary_successes = sum(r["simulation"]["valid"] and (r.get("detector") or {}).get("is_trojan") is False
                                  for r in strong_unique.values())
    if supplementary_successes:
        p(f"The model-swap follow-up yielded {supplementary_successes} valid evasion event. This is an exception within the permitted template, not a monotonic feedback effect or a reliable model ranking. The comparison is exploratory, and a single negative judgment does not show stable evasion across repeated reviews.")
        escape = sorted(supplement_escapes, key=lambda r: r["candidate_id"])[0]
        review = next(r for r in reviews if r["sha256"] == escape["netlist_sha256"])
        if escape["circuit"] == "and4":
            em = escape["simulation"]["metrics"]
            verdict = "flagged" if review["stronger_detector"]["is_trojan"] else "also accepted"
            p(f"In the observed AND binary-feedback case, all {em['truth_table_passed']} normal logic cases passed, settled deviation was {em['normal_settled_max_deviation_v']*1e3:.3f} mV, and the activated high-output drop was {em['trigger_output_drop_v']:.3f} V. The original reviewer treated the extra network as potentially ordinary biasing and requested simulation. The alternative reviewer {verdict} this same netlist. This case separates real simulated payload behavior from a model's interpretation; it does not isolate the causal role of naming, feedback or reviewer randomness.")
        if supplement["stability"] is not None:
            checks = {r["model"]: r for r in supplement["stability"]["results"] if r["sha256"] == escape["netlist_sha256"]}
            first = checks["gpt-4o-mini-2024-07-18"]
            second = checks[strong_config["attacker_model"]]
            p(f"A post-hoc check kept that netlist and prompt fixed for five fresh judgments per reviewer: GPT-4o mini flagged it {first['flagged']}/{first['judgments']} times and GPT-5.4 mini {second['flagged']}/{second['judgments']}. The observed miss is therefore intermittent rather than stable concealment. This success-selected case is not pooled into the original rates and cannot estimate general reviewer error.", "small")
    elif cross["valid_undetected"]:
        p(f"The alternative attacker also produced no valid evasion against the fixed reviewer. However, the retrospective reviewer missed {cross['valid_undetected']} valid distinct inputs, showing that the ceiling depends on the reviewer. Because those verdicts were never fed back to an attacker, this is classification disagreement rather than evidence of feedback-assisted concealment.")
    else:
        p("The model-swap follow-up and retrospective review also produced no valid evasion. The ceiling therefore persists across the tested model roles, but the common template remains a plausible explanation. These additional observations do not turn a narrow, low-diversity experiment into evidence that diagnostic feedback has no security effect.")
    p("Relation to earlier work", "h2")
    p("LATENT reports mean component-level evasion of 23.7% with one-shot prompting and 94.4% with iterative refinement across 15 circuits [3]. That localization-oriented endpoint differs from our requirement that an entire valid candidate receive a negative verdict; these percentages are not directly comparable.")
    p("SPICED uses specifications, simulation-derived voltage/current information and few-shot rules [2]. Our netlist-only review omits this evidence, and our fixed template is much narrower than LATENT's insertion strategy. In the baseline, all generations retained plain names and none selected the offered subcircuit form; the verified starting example and low sampling temperature may anchor exploration. Generic devices and an abstract behavioral payload also preclude claims about the area, power, stealth or manufacturability of original A2 hardware [1].")
    p("Next experiment", "h2")
    p("A more discriminating evaluation would use independently designed attack families, benign look-alike modifications and held-out circuits, seeking a reviewer with neither universal acceptance nor universal rejection. Matched-amplitude frequency sweeps would separate trigger mechanisms. Comparing netlist-only review with simulation-informed review would then test whether detailed diagnostics improve defense, assist valid evasion, or both.")
    p("References", "h2")
    p('[1] K. Yang, M. Hicks, Q. Dong, T. Austin and D. Sylvester. <b>A2: Analog Malicious Hardware.</b> IEEE Symposium on Security and Privacy, 2016, pp. 18-37. DOI: 10.1109/SP.2016.10. <link href="https://www.ieee-security.org/TC/SP2016/papers/0824a018.pdf" color="#187F79">Original paper</link>.', "small")
    p('[2] J. Chaudhuri, D. Thapar, A. Chaudhuri, F. Firouzi and K. Chakrabarty. <b>SPICED: Syntactical Bug and Trojan Pattern Identification in A/MS Circuits using LLM-Enhanced Detection.</b> PAINE 2024; <link href="https://arxiv.org/abs/2408.16018" color="#187F79">arXiv:2408.16018</link>.', "small")
    p('[3] J. Chaudhuri, A. Chaudhuri and K. Chakrabarty. <b>LATENT: LLM-Augmented Trojan Insertion and Evaluation Framework for Analog Netlist Topologies.</b> ICLAD 2025; <link href="https://arxiv.org/abs/2505.06364" color="#187F79">arXiv:2505.06364</link>.', "small")
    p('Acknowledgement: an AI coding assistant supported implementation and drafting. All numerical results were computed from recorded model outputs and circuit simulations.', "small")

    pdf_path = out / "A2_Trojan_LLM_Informal_Report.pdf"
    text_path = out / "A2_Trojan_LLM_Informal_Report.txt"
    text_path.write_text("\n\n".join(text_blocks) + "\n", encoding="utf-8")
    doc = SimpleDocTemplate(str(pdf_path), pagesize=(612, 792), rightMargin=48, leftMargin=48,
                            topMargin=41, bottomMargin=43,
                            title="A2 Trojans in the LLM Era: Does Detection Feedback Help an Attacker?",
                            author="Amber Tsao; Jiahao Xu", subject="Information Security informal project report")

    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#D7E0E7")); canvas.setLineWidth(.5)
        canvas.line(48, 32, 564, 32)
        canvas.setFont(font, 7.4); canvas.setFillColor(muted)
        canvas.drawString(48, 20, "A2-inspired LLM experiment | Informal course report | 30 October 2026")
        canvas.drawRightString(564, 20, str(document.page))
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    from pypdf import PdfReader
    page_count = len(PdfReader(str(pdf_path)).pages)
    if not 3 <= page_count <= 5:
        raise RuntimeError(f"Report has {page_count} pages; revise layout before delivery")
    word_count = len(re.findall(r"\S+", text_path.read_text()))
    print(json.dumps({"pdf": str(pdf_path), "editable_text": str(text_path), "pages": page_count,
                      "approximate_words_including_tables": word_count}, indent=2))
    return pdf_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="main_v2")
    arguments = parser.parse_args()
    build(arguments.run_id)
