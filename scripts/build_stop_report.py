#!/usr/bin/env python3
"""Build the final single-experiment report from completed, audited evidence.

This generator makes no API requests or new circuit simulations.  The previous
report builder remains available for the archived experiments.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_proposal_report import ReportLayout
from scripts.stopstudy_v6.analyze import (CIRCUITS, FEEDBACK, NAMES, RUN_ID, make_figure,
                                        summarize, summarize_controls)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def circuit_name(circuit):
    return "two-stage op-amp" if circuit == "opamp" else "four-input AND"


def source_blocks():
    """Keep approved wording; minimally correct the timing of attacker requests."""
    source = (ROOT / "docs/inputs/Collaborator_Report_Comments_2026-11-02.txt").read_text()
    result = {"title": source.splitlines()[0], "authors": source.splitlines()[1]}
    prefixes = {"intro1": "Inspired by the brief survey", "intro2": "SPICED feedback was",
                "attacker": "First, the attacker", "validation": "Next, ngspice",
                "feedback": "The experiment is conducted"}
    for key, prefix in prefixes.items():
        content = source[source.index(prefix):]
        content = content[:content.index("Each request produces")] if key == "feedback" else re.split(r"\n[ \t]*\n", content, maxsplit=1)[0]
        result[key] = " ".join(content.split())
    result["intro1"] = result["intro1"].replace("A2 trojans", "analog hardware trojans")
    result["attacker"] = result["attacker"].replace("First, the attacker receives", "After the first attempt, the attacker receives", 1)
    return result


def load_evidence(run_id):
    require(run_id == RUN_ID, "The report is scoped to the declared final experiment")
    folder = ROOT / "results" / run_id
    completion = read(folder / "completion.json")
    require(completion.get("complete") is True, "Experiment is incomplete")
    for field, name in (("manifest_sha256", "manifest.json"), ("schedule_sha256", "schedule.json"),
                        ("attempts_sha256", "attempts.json"), ("dispositions_sha256", "dispositions.json"),
                        ("controls_sha256", "controls.json"), ("controls_gate_sha256", "controls_gate.json")):
        require(completion.get(field) == sha(folder / name), "Completion evidence changed: " + name)
    manifest = read(folder / "manifest.json")
    config = manifest["config"]
    require(config["sessions_per_condition"] == 10 and config["max_attempts"] == 10
            and config["attacker_temperature"] == .3 and config["detector_temperature"] == 0
            and config["shared_first_attempt"] is True and config["new_control_api_calls"] == 4,
            "Report settings differ from the frozen experiment")
    for name, expected in manifest["source_hashes"].items():
        require(sha(ROOT / name) == expected, "Frozen experiment source changed: " + name)
    rows = read(folder / "attempts.json")
    summary = read(folder / "summary.json")
    recount = summarize(rows)
    require({key: value for key, value in summary.items() if key not in ("source_sha256", "controls")} == recount,
            "Summary differs from the raw attempts")
    controls = read(folder / "controls.json")
    require(summary.get("controls") == summarize_controls(controls),
            "Control summary differs from the separate sanity checks")
    require(summary["totals"]["unusable_detector_cache_entries"] == 0,
            "A completed final experiment cannot contain an unusable cached review")
    for name, expected in summary["source_sha256"].items():
        require(sha(ROOT / name) == expected, "Summary has stale source evidence: " + name)
    audit_path = folder / "audit.json"
    audit = read(audit_path)
    require(audit.get("passed") is True, "Independent experiment audit has not passed")
    for name, expected in audit.get("source_sha256", {}).items():
        require(sha(ROOT / name) == expected, "Audit has stale source evidence: " + name)
    qualification_path = ROOT / "results/proposal_validation/qualification_summary.json"
    qualification = read(qualification_path)
    require(qualification.get("status") == "qualified"
            and all(group["passed"] == group["combinations"] for group in qualification["groups"].values()),
            "Circuit menu qualification did not pass")
    paths = [folder / name for name in ("manifest.json", "schedule.json", "attempts.json", "dispositions.json",
                                        "completion.json", "summary.json", "audit.json", "controls.json",
                                        "controls_gate.json", "design.json")]
    paths.extend([qualification_path, ROOT / "configs/stopstudy_v6.json", ROOT / "scripts/stopstudy_v6/analyze.py",
                  ROOT / "scripts/build_stop_report.py", ROOT / "scripts/build_proposal_report.py",
                  ROOT / config["protocol_document"],
                  ROOT / "docs/inputs/Collaborator_Report_Comments_2026-11-02.txt"])
    return {"folder": folder, "config": config, "rows": rows, "summary": summary, "audit": audit, "controls": controls,
            "qualification": qualification, "sources": {str(path.relative_to(ROOT)): sha(path) for path in paths}}


def outcome_text(groups, circuit):
    counts = {level: groups[circuit, level]["escaped_sessions"] for level in FEEDBACK}
    text = (f"For the {circuit_name(circuit)}, None, Binary and Full succeed in "
            f"{counts['none']}/10, {counts['binary']}/10 and {counts['full']}/10 sessions, respectively. ")
    if all(groups[circuit, level]["first_attempt_escapes"] == 10 for level in FEEDBACK):
        return (text + "Each of the ten paired starting circuits already escapes before any feedback is delivered. "
                "The three curves therefore coincide at ten from attempt one. These sessions do not test "
                "whether feedback would help a revision.")
    if all(count == 0 for count in counts.values()):
        return text + "No session escapes within ten attempts, so all three curves remain at zero."
    if len(set(counts.values())) == 1:
        return text + "Their final session success counts are equal in this run. The curves show whether the successful sessions reached escape at different attempts."
    if counts["full"] > counts["binary"]:
        text += "Full produces more successful sessions than Binary in this run. "
    elif counts["full"] < counts["binary"]:
        text += "Binary produces more successful sessions than Full in this run. "
    else:
        text += "Full and Binary reach the same final session count. "
    if min(counts["binary"], counts["full"]) > counts["none"]:
        text += "Both feedback conditions exceed the no-feedback count."
    elif max(counts["binary"], counts["full"]) <= counts["none"]:
        text += "Neither feedback condition exceeds the no-feedback count."
    else:
        text += "The two feedback conditions differ in their comparison with None."
    return text


def trajectory_example(evidence):
    sessions = evidence["summary"]["sessions"]
    candidates = [session for session in sessions if session["escaped"] and session["first_escape_attempt"] > 1]
    if not candidates:
        return None
    chosen = next((session for session in candidates if session["circuit"] == "and4"
                   and session["feedback"] == "full"), candidates[0])
    rows = sorted((row for row in evidence["rows"] if row["circuit"] == chosen["circuit"]
                   and row["feedback"] == chosen["feedback"] and row["session"] == chosen["session"]),
                  key=lambda row: row["attempt"])
    first, last = rows[0], rows[-1]
    if not isinstance(first.get("parameters"), dict) or not isinstance(last.get("parameters"), dict):
        return None
    left, right = first["parameters"], last["parameters"]
    fields = [field for field in ("insertion_site", "representation", "trigger_profile", "strength")
              if left.get(field) != right.get(field)]
    changes = "; ".join(f"{field.replace('_', ' ')}: {left[field]} to {right[field]}" for field in fields)
    if not changes:
        return None
    return (f"In {NAMES[chosen['circuit']]} / {chosen['feedback'].capitalize()}, session {chosen['session']}, "
            f"the first escape occurs at attempt {chosen['first_escape_attempt']}. Relative to the start, "
            f"the escaping configuration changes {changes}. It passes the electrical checks and "
            "receives a negative Trojan verdict.")


def build(run_id, output):
    output = Path(output).resolve()
    evidence = load_evidence(run_id)
    summary, config = evidence["summary"], evidence["config"]
    groups = {(group["circuit"], group["feedback"]): group for group in summary["groups"]}
    totals = summary["totals"]
    original = source_blocks()
    figure = output.parent / "stop_report_figures/cumulative_escape.png"
    make_figure(summary, figure)
    report = ReportLayout()
    report.styles["title"].fontSize = 16
    report.styles["title"].leading = 20
    p, table = report.p, report.table

    # Page 1: retain the collaborator's introduction and method wording.
    p(html.escape(original["title"]), "title")
    p(html.escape(original["authors"]), "small")
    p("Introduction", "h1")
    p(html.escape(original["intro1"]))
    p(html.escape(original["intro2"]))
    p("LATENT's percentages measure inserted components escaping localization, rather than whole "
      "circuits escaping detection. Our experiment holds the model fixed and compares feedback conditions.")
    p("Methodology", "h1")
    p("Our experiment consists of two small circuits as benchmarks, an LLM attacker inspired by "
      "LATENT's feedback loop, and a netlist-only LLM detector inspired by SPICED. Both use "
      f"<b>{html.escape(config['model'])}</b>. The attacker uses temperature <b>0.3</b>; the detector "
      "uses <b>0.0</b>, with its first result cached for each identical input. These are simplified "
      "implementations, not full reproductions. We omit syntax-repair evaluation.")
    p("Each session begins from a prespecified circuit modification. Python renders this first "
      "candidate from the permitted menu; subsequent attempts are proposed by the attacker LLM.")
    p(html.escape(original["attacker"]))
    p(html.escape(original["validation"]))
    p(html.escape(original["feedback"]))
    p("Each attacker request produces a complete next configuration. The session stops immediately when "
      "a candidate passes both electrical checks and the detector returns is_trojan=false. "
      "Otherwise, it continues for at most ten attempts. The successful configuration is retained.")

    # Page 2: define a session, the fixed reviewer, and the electrical experiment.
    report.new_page()
    p("Methodology (continued)", "h1")
    p("A <b>session</b> is one attack process with a separate history. Before this run's detector calls, "
      "we select <b>ten different starting configurations per circuit</b> with fixed sampling seeds. "
      "Sampling covers every insertion-site/device-representation combination, then fills the "
      "remaining slots without replacement. Within each session, None, Binary and Full share "
      "the start and review. Each circuit/condition has <b>10 sessions and at most 10 attempts</b>, "
      "including the preset first attempt. Later requests use predeclared attacker seeds. "
      "All 60 condition-specific sessions are summarized together.")
    p("After the preset first attempt, None makes a fresh request at each attempt. Binary and Full also receive the preceding "
      "candidate's choices; Binary receives only its Boolean review, while Full receives the complete "
      "review, including confidence and explanation. Neither condition receives simulator feedback. "
      "Only the preceding candidate and review are provided, not the full session history.")
    p("The detector does not learn online. Temperature 0.0 and a fixed seed reduce sampling "
      "variation but do not guarantee identical API outputs. To keep its behavior fixed in this "
      "experiment, each distinct detector request is reviewed once and its result is reused across "
      "all sessions and feedback conditions. The cache key covers the exact netlist, nominal "
      "function, prompt, model and generation settings. Repeating the same circuit therefore cannot "
      "obtain a different verdict by chance. An unusable detector response halts execution "
      "for inspection; it cannot be counted as an escape.")
    p("Before the sessions, the same detector must correctly label two clean circuits and two "
      "separately specified, electrically verified Trojan circuits. Both clean controls are accepted "
      "and both positive controls detected. The positive control configurations lie outside the "
      "attacker menu. These four checks establish basic operation, not general detection accuracy; "
      "they are excluded from session results.")
    p("Circuits and electrical checks", "h2")
    p("The two small circuits make normal function and triggered interference easy to check. "
      "Their clean versions use a 3.3 V supply:")
    clean = evidence["qualification"]["clean_results"]
    op, gate = clean["opamp"]["metrics"], clean["and4"]["metrics"]
    table(["Clean circuit", "Verification"], [
        ["Two-stage op-amp", f"Open-loop gain {op['dc_gain_db']:.2f} dB; -3 dB bandwidth {op['bandwidth_3db_hz']:.2f} Hz; unity-gain frequency {op['unity_gain_hz']/1e6:.3f} MHz; phase margin {op['phase_margin_deg']:.2f} degrees."],
        ["Four-input AND", f"{gate['truth_table_passed']}/16 logic cases pass. Rise delay {gate['rise_delay_ns']:.4f} ns; simultaneous four-input fall delay {gate['fall_delay_ns']:.4f} ns (100 fF load, 100 ps input edges)."],
    ], [112, 404])
    p("The trigger works like a leaky bucket: input transitions add charge through a coupling "
      "capacitor and two diodes to a 10 pF reservoir; a resistor drains it. Rapid activity can cross "
      "a threshold, enabling a branch that pulls an output or internal node toward a supply rail. "
      "These are A2-inspired simulation models, not fabricated hardware.")
    p("The op-amp permits output, gain-node or mirror-reference insertions; AND permits output or "
      "internal NAND-node insertions. Each site has three representations (switch, smooth conductance "
      "or MOSFET), three RC/threshold profiles and three strengths: <b>81 op-amp and 54 AND choices</b>. "
      "The MOSFET uses an ideal reservoir comparator. The menu was electrically qualified before "
      "this run, and every candidate is simulated again. Validity therefore measures "
      "selection within a qualified menu, not unrestricted circuit synthesis.")
    p("For the op-amp, normal follower output must stay within 20 mV of the clean reference. "
      "Normal input is 1.65 V +/- 50 mV at 10 kHz; activation uses a 0.6-2.7 V, 1 MHz burst at "
      "5-45 us. Output must fall at least 0.3 V below the reference during recovery at 50-60 us. "
      "Both frequency and amplitude change. AND must preserve all 16 logic cases and settled "
      "output within 0.2 V; a 1 MHz burst on input a, with b, c and d high, must reduce its high "
      "output by at least 0.8 V. A harmless or permanently broken modification cannot qualify.")

    # Page 3: one session-level table and the requested cumulative escape lines.
    report.new_page()
    p("Results", "h1")
    p("An <b>escape</b> requires both electrical validity and a usable negative Trojan verdict. "
      "The primary outcome is the number of sessions that achieve an escape within ten attempts, "
      "divided by ten sessions. Each successful session contributes once, at its first escape.")
    table(["Circuit", "Feedback", "Escape at attempt 1", "Escape by attempt 10", "Median first-escape attempt*"], [
        [NAMES[circuit], feedback.capitalize(), f"{groups[circuit, feedback]['first_attempt_escapes']}/10",
         f"{groups[circuit, feedback]['escaped_sessions']}/10",
         f"{groups[circuit, feedback]['median_first_escape_among_successes']:g}"
         if groups[circuit, feedback]["median_first_escape_among_successes"] is not None else "--"]
        for circuit in CIRCUITS for feedback in FEEDBACK], [116, 62, 98, 106, 134])
    p("Table 1. All conditions have ten sessions. *The median includes only successful sessions; "
      "-- means no session escaped. Failed sessions exhaust ten attempts and remain in the "
      "success-rate denominator. Attempt 1 evaluates the shared preset, before feedback is used.", "small")
    report.figure(figure, width=516)
    p("Figure 1. Cumulative number of sessions that have escaped by each attempt, out of ten. "
      "Each panel shows one circuit and three feedback conditions. A session remains counted "
      "after its first escape, although no later attempts are executed for that session. "
      "Overlapping lines indicate equal counts, not missing observations.", "small")
    p(outcome_text(groups, "opamp"))
    p(outcome_text(groups, "and4"))
    p(f"The completed run contains {totals['analysis_rows']} condition-level attempt records from "
      f"{totals['actual_candidate_events']} candidate events: {totals['preset_candidate_events']} "
      f"preset starts and {totals['llm_generated_candidate_events']} LLM proposals. The extra table "
      "records are shared first attempts. These events contain "
      f"{totals['distinct_netlists']} distinct netlists. Electrical checks pass for "
      f"{totals['electrically_valid_candidate_events']}/{totals['actual_candidate_events']} candidate events. "
      f"Main candidates use {totals['distinct_detector_cache_entries']} distinct cached detector outcomes, "
      f"including {totals['unusable_detector_cache_entries']} unusable outcomes; the four control reviews are separate. "
      "Unusable outputs and invalid candidates cannot count as escapes.", "small")

    # Page 4: interpret only this experiment and relate its metric to the papers.
    report.new_page()
    p("Discussion", "h1")
    p("What the feedback comparison measures", "h2")
    initial_counts = {circuit: groups[circuit, "none"]["first_attempt_escapes"] for circuit in CIRCUITS}
    opportunity_text = (f"Before feedback, {initial_counts['opamp']}/10 op-amp starts and "
                        f"{initial_counts['and4']}/10 AND starts already escape. This leaves "
                        f"{10-initial_counts['opamp']} op-amp sessions and {10-initial_counts['and4']} AND "
                        "sessions per condition in which later proposals can affect the outcome.")
    if any(group["median_first_escape_among_successes"] == 1 for group in groups.values()):
        opportunity_text += " A median of one reflects shared starting escapes, not faster feedback-guided revision."
    p(opportunity_text)
    for circuit in CIRCUITS:
        if all(groups[circuit, level]["first_attempt_escapes"] == 10 for level in FEEDBACK):
            initial_netlists = len({row["netlist_sha256"] for row in evidence["rows"]
                                    if row["circuit"] == circuit and row["attempt"] == 1 and row.get("netlist_sha256")})
            p(f"For the {circuit_name(circuit)}, all sessions stop at the shared first attempt. "
              f"The ten starting circuits contain {initial_netlists} distinct "
              f"{'netlist' if initial_netlists == 1 else 'netlists'}. "
              "This exposes a blind spot in the fixed review of those starting candidates; "
              "there is no remaining opportunity for Binary or Full feedback to change the outcome. "
              "The equal curves therefore cannot establish that feedback is useless on this circuit.")
    example = trajectory_example(evidence)
    if example:
        p(html.escape(example))
    else:
        p("The stopping rule preserves the first successful candidate. A flat part of a curve means "
          "that no additional session first escaped at those attempts; it does not mean an already "
          "successful candidate was lost. Sessions with no escape still use their full ten attempts.")
    revision_circuits = [c for c in CIRCUITS if groups[c, "none"]["first_attempt_escapes"] < 10]
    revision_names = " and ".join("the " + circuit_name(c) for c in revision_circuits)
    full_advantage = [groups[c, "full"]["escaped_sessions"] > groups[c, "binary"]["escaped_sessions"] for c in revision_circuits]
    if not revision_circuits:
        p("Every session ends before feedback is used. This run establishes escapes against the "
          "fixed reviewer but provides no comparison of feedback-guided revision.")
    elif all(full_advantage):
        p(f"On {revision_names}, where revisions occur, Full has a higher final success count "
          "than Binary. This supports an advantage from the complete review under these particular "
          "menus and cached judgments; ten sessions per condition do not establish a general advantage.")
    elif all(groups[c, "full"]["escaped_sessions"] == groups[c, "binary"]["escaped_sessions"] for c in revision_circuits):
        p(f"On {revision_names}, where revisions occur, Full and Binary reach the same final "
          "success count. " + " ".join(
              f"For the {circuit_name(c)}, Full reaches its final total by attempt "
              f"{max(groups[c, 'full']['first_escape_attempts'])}, compared with attempt "
              f"{max(groups[c, 'binary']['first_escape_attempts'])} for Binary."
              for c in revision_circuits if groups[c, "full"]["first_escape_attempts"]
              and groups[c, "binary"]["first_escape_attempts"]) +
          " This is a difference in this run's search speed, not evidence of a general advantage.")
    else:
        p("Full does not consistently produce a higher final success count than Binary where revisions occur. "
          "The results therefore do not establish that more detailed feedback consistently helps "
          "the attacker. The cumulative curves also show whether a condition reaches its escapes "
          "earlier, even when final success counts tie.")
    none_revisions = {circuit: [row for row in evidence["rows"] if row["circuit"] == circuit
                               and row["feedback"] == "none" and row["attempt"] > 1] for circuit in CIRCUITS}
    if all(records and len({row.get("netlist_sha256") for row in records}) == 1
           and all(row.get("detector", {}).get("is_trojan") is True for row in records)
           for records in none_revisions.values()):
        p(f"None's {len(none_revisions['opamp'])} op-amp revisions all repeat one flagged netlist, "
          f"and its {len(none_revisions['and4'])} AND revisions do the same within that circuit. "
          "Thus its successes come entirely from the preset starts; fresh prompts did not "
          "produce useful diversity. Feedback gives the attacker a way to depart from these defaults.")
    p("Repeated netlists keep the same cached review. Binary and Full receive both a preceding "
      "candidate and its review; None receives neither. None versus either feedback condition "
      "therefore also changes candidate history. Binary versus Full more directly compares the "
      "amount of review information.")
    p("Relation to A2, SPICED and LATENT", "h2")
    p("A2 demonstrates a small charge-accumulating malicious circuit in fabricated hardware [1]. "
      "Our diode-capacitor triggers retain the idea of accumulated activity causing conditional "
      "interference, but use educational simulation models and idealized elements. They do not "
      "reproduce A2's transistor layout or silicon measurements.")
    p("SPICED combines netlists, voltage/current logs, specifications and few-shot anomaly rules "
      "[2, Sec. IV and Table III]. Our detector uses the proposal's minimal netlist-only input. "
      "It receives no simulation traces or activation measurements. Its review can therefore "
      "disagree with the electrical tests, which separately establish whether a modification works.")
    p("LATENT uses broader component/node edits, simulation-informed diagnosis and reversion "
      "[3, Secs. IV-V]. Its 23.7% and 94.4% figures concern inserted components escaping localization "
      "[3, Table I]; ours count sessions finding a valid whole netlist with a negative verdict. "
      "These metrics are not directly comparable. Its DC activation also differs from our transient "
      "trigger. LATENT uses GPT-4o-mini at temperature 0.3; we do not test model-generation progress.")
    p("Scope of the conclusion", "h2")
    p("We measure search from varied prescribed starts against one fixed reviewer, not online "
      "detector learning or LLMs' overall benefit. Conditions share starts and revisions may repeat "
      "circuits. The cache fixes judgments within this run; another run may obtain different verdicts "
      "despite the same temperature and seed. Finite menus and simulation at one supply and nominal "
      "model settings limit generalization.")
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
    text = output.with_suffix(".txt").read_text()
    from pypdf import PdfReader
    pdf_text = " ".join(page.extract_text() for page in PdfReader(output).pages)
    for key, value in original.items():
        require(" ".join(text.split()).count(" ".join(value.split())) == 1, "Approved text changed or duplicated: " + key)
        require(" ".join(pdf_text.split()).count(" ".join(value.split())) == 1, "Approved PDF text changed or duplicated: " + key)
    require(not re.search(r"Batch [12]|Supplementary paired|normal-operation evidence|13/40|39/60", text),
            "An archived experiment leaked into the current report")
    provenance = {"protocol": RUN_ID, "run_id": run_id, "pages": pages,
                  "generator_sha256": sha(ROOT / "scripts/build_stop_report.py"),
                  "primary_unit": "session", "sessions_per_condition": 10,
                  "source_sha256": evidence["sources"],
                  "figure_sha256": {str(path.relative_to(ROOT)): sha(path) for path in (figure, figure.with_suffix(".pdf"))},
                  "unchanged_collaborator_blocks": [key for key in original if key != "attacker"],
                  "minimally_corrected_collaborator_blocks": ["attacker"],
                  "necessary_method_changes": ["attacker and detector temperatures", "stop immediately after first valid escape",
                                               "first attempt is a prespecified circuit; attacker requests begin at attempt two",
                                               "ten diverse starting configurations per circuit selected before reviews",
                                               "separate four-design detector sanity gate"],
                  "pdf_sha256": sha(output), "text_sha256": sha(output.with_suffix(".txt"))}
    output.with_suffix(".provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return {"output": str(output), "text": str(output.with_suffix(".txt")), "pages": pages,
            "word_count": len(" ".join(report.text).split()), "protected_blocks": len(original)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default=RUN_ID)
    parser.add_argument("--output", type=Path, default=ROOT / "output/pdf/A2_Trojan_LLM_Informal_Report.pdf")
    args = parser.parse_args()
    print(json.dumps(build(args.run_id, args.output), indent=2))
