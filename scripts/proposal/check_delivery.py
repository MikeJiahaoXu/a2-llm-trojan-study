"""Check the delivered proposal evidence without API calls or new simulations.

Run only after both configured experiments, their audits, analysis, and report
have completed. A supported hypothesis is deliberately not an acceptance test.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import re

from scripts.proposal.verify import audit_qualification, audit_run, check_independent_repeat, require

ROOT = Path(__file__).resolve().parents[2]
REPORT = "output/pdf/A2_Trojan_LLM_Informal_Report.pdf"


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def existing(root, name):
    path = root / name
    require(path.is_file() and path.stat().st_size > 0, "Missing or empty artifact: " + name)
    return path


def check_control_gate(controls, circuits):
    expected = set(itertools.product(circuits, ("clean", "positive"), range(5)))
    keys = [(r["circuit"], r["label"], r["repeat"]) for r in controls]
    require(len(keys) == len(set(keys)) and set(keys) == expected, "Final control allocation differs")
    counts = {}
    for circuit in circuits:
        clean, positive = (sum(r["detector"]["is_trojan"] is True for r in controls
                               if r["circuit"] == circuit and r["label"] == label)
                           for label in ("clean", "positive"))
        require(clean <= 1 and positive >= 4, "Final control gate failed: " + circuit)
        counts[circuit] = {"clean_flags": clean, "clean_judgments": 5,
                           "positive_flags": positive, "positive_judgments": 5}
    return counts


def control_acceptance(root, run_id, circuits):
    controls = read(root / "results" / run_id / "controls.json")
    try:
        counts = check_control_gate(controls, circuits)
        return {"original_gate_passed": True, "status": "passed", "counts": counts}
    except ValueError:
        path = root / "results" / run_id / "control_gate_deviation.json"
        if not path.exists():
            raise
        from scripts.proposal.continue_after_controls import verify_deviation
        sealed = verify_deviation(root, run_id)
        counts = {c: {"clean_flags": value["clean"], "clean_judgments": 5,
                      "positive_flags": value["positive"], "positive_judgments": 5}
                  for c, value in sealed["deviation"]["observed_control_flags"].items()}
        return {"original_gate_passed": False, "status": "continued_under_documented_deviation",
                "counts": counts, "deviation_path": str(path.relative_to(root)), "deviation_sha256": sha(path),
                "interpretation": sealed["deviation"]["interpretation_limit"]}


def evaluate_hypothesis(rows_by_run):
    """Describe the strict proposed ordering; equal or reversed rates are valid data."""
    evaluations = []
    pooled = [r for rows in rows_by_run.values() for r in rows]
    for run_id, rows in [*rows_by_run.items(), ("combined", pooled)]:
        for circuit in ("opamp", "and4"):
            groups = {}
            for level in ("none", "binary", "full"):
                selected = [r for r in rows if r["circuit"] == circuit and r["feedback"] == level]
                require(selected, "Hypothesis evaluation lacks a required group")
                successes = sum(r["simulation"]["valid"] is True
                                and (r.get("detector") or {}).get("is_trojan") is False for r in selected)
                groups[level] = {"valid_undetected": successes, "attempts": len(selected),
                                 "rate": successes / len(selected)}
            ordered = groups["none"]["rate"] < groups["binary"]["rate"] < groups["full"]["rate"]
            evaluations.append({"execution": run_id, "circuit": circuit, "groups": groups,
                                "strict_none_lt_binary_lt_full_observed": ordered})
    return {"evaluated": True, "acceptance_depends_on_direction": False,
            "interpretation": "Descriptive observations in a finite menu. Shared starts and adaptive attempts are dependent; these rates do not establish statistical superiority.",
            "comparisons": evaluations}


def check_electrical_coverage(audit, rows_by_run):
    """Reject stale or selectively sampled audits even when their top-level flag passes."""
    require(audit.get("complete") is True and audit.get("passed") is True, "Electrical audit did not pass")
    require(set(audit["run_counts"]) == set(rows_by_run), "Electrical audit covers different runs")
    expected = {(run_id, r["candidate_id"]): r for run_id, rows in rows_by_run.items() for r in rows}
    actual = {(r["run_id"], r["candidate_id"]): r for r in audit["event_checks"]}
    require(len(actual) == len(audit["event_checks"]) and set(actual) == set(expected),
            "Electrical audit omits, duplicates, or adds candidate events")
    groups = {}
    for key, row in expected.items():
        item = actual[key]
        require(item["passed"] is True and item["circuit"] == row["circuit"], "Electrical candidate check failed")
        if row.get("netlist_sha256"):
            require(item.get("rendered") is True and item["netlist_sha256"] == row["netlist_sha256"],
                    "Electrical audit tested another candidate")
            require(all(item["checks"].values()), "A saved-waveform check failed")
            groups.setdefault(row["netlist_sha256"], set()).add(key)
        else:
            require(item.get("rendered") is False and item.get("honest_failure") is True,
                    "Unrendered failure was not retained")
    fresh = {r["netlist_sha256"]: r for r in audit["fresh_netlist_checks"]}
    require(len(fresh) == len(audit["fresh_netlist_checks"]) and set(fresh) == set(groups),
            "Fresh simulation audit omits, duplicates, or adds distinct netlists")
    require(audit["distinct_netlists_freshly_simulated"] == len(groups)
            and audit["total_candidate_events"] == len(expected)
            and audit["total_analysis_rows"] == sum(map(len, rows_by_run.values())),
            "Electrical audit totals differ")
    for digest, record in fresh.items():
        members = [(r["run_id"], r["candidate_id"]) for r in record["comparisons"]]
        require(len(members) == len(set(members)) and set(members) == groups[digest]
                and record["candidate_events"] == len(members), "Fresh simulation membership differs")
        require(record["passed"] is True and all(r["matches"] is True for r in record["comparisons"]),
                "Fresh simulation did not match saved evidence")
        require(record["fresh_simulation"]["simulation_ok"] is True
                and record["independent_uniform_time_metrics"]["valid"] == record["fresh_simulation"]["valid"],
                "Fresh simulation lacks an agreeing independent waveform check")
    require(audit["all_fresh_simulations_match"] is True
            and audit["all_saved_uniform_time_verdicts_match"] is True
            and audit["all_saved_metrics_match_qualification"] is True, "Electrical summary reports a discrepancy")
    for run_id, rows in rows_by_run.items():
        count = audit["run_counts"][run_id]
        events = {r["candidate_id"]: r for r in rows}
        require(count["complete"] is True and count["analysis_rows"] == len(rows)
                and count["candidate_events"] == len(events)
                and count["distinct_netlists"] == len({r["netlist_sha256"] for r in events.values() if r.get("netlist_sha256")})
                and count["valid_candidate_events"] == sum(r["simulation"]["valid"] for r in events.values()),
                "Electrical per-run totals differ")
    return {"candidate_events_checked": len(expected), "distinct_netlists_freshly_simulated": len(fresh)}


def check_provenance(root, provenance, report, run_ids, audit_paths):
    require([provenance["primary_run"], provenance["replication_run"]] == run_ids,
            "Report describes different runs")
    require(set(provenance["source_sha256"]) == set(run_ids), "Report provenance has different execution sources")
    for run_id in run_ids:
        expected = {name: sha(root / "results" / run_id / name)
                    for name in ("attempts.json", "controls.json", "manifest.json", "completion.json")}
        require(provenance["source_sha256"][run_id] == expected, "Report provenance has stale experiment data")
    require(provenance["qualification_sha256"] == sha(root / "results/proposal_validation/qualification_summary.json"),
            "Report has stale qualification evidence")
    expected_audits = {name: sha(root / name) for name in audit_paths}
    require(provenance["audit_sha256"] == expected_audits, "Report has stale or incomplete audit evidence")
    require(provenance["pdf_sha256"] == sha(report)
            and provenance["text_sha256"] == sha(report.with_suffix(".txt")), "Report artifact hash changed")
    analysis_hashes = provenance.get("analysis_sha256", {})
    require(isinstance(analysis_hashes, dict), "Report analysis provenance must be a file/hash mapping")
    for name, digest in analysis_hashes.items():
        path = existing(root, name)
        require(sha(path) == digest, "Report has stale analysis artifact: " + name)
        if path.suffix.lower() == ".json":
            analysis = read(path)
            if isinstance(analysis, dict) and "source_sha256" in analysis:
                sources = analysis["source_sha256"]
                require(isinstance(sources, dict), "Analysis source provenance must be a file/hash mapping: " + name)
                for source_name, source_digest in sources.items():
                    require(sha(existing(root, source_name)) == source_digest,
                            "Analysis has stale source evidence: " + name + " -> " + source_name)
    for name, digest in provenance.get("calibration_controls_sha256", {}).items():
        require(sha(root / name) == digest, "Report calibration disclosure has stale evidence")
    deviations = {f"results/{run_id}/control_gate_deviation.json": sha(root / "results" / run_id / "control_gate_deviation.json")
                  for run_id in run_ids if (root / "results" / run_id / "control_gate_deviation.json").exists()}
    require(provenance.get("protocol_deviation_sha256", {}) == deviations, "Report lacks matching continuation-deviation provenance")


def check_analysis(root, run_ids, rows_by_run):
    from pypdf import PdfReader
    files = []
    for run_id in run_ids:
        folder = root / "results" / run_id
        rows = rows_by_run[run_id]
        summary = read(folder / "summary.json")
        require(summary["complete"] is True and summary["attempt_rows"] == len(rows), "Summary is incomplete")
        for name, digest in summary["source_sha256"].items():
            require(sha(folder / name) == digest, "Summary refers to stale data")
        groups = {(g["circuit"], g["feedback"]): g for g in summary["groups"]}
        require(len(groups) == len(summary["groups"]) == 6, "Summary does not contain exactly six groups")
        for key in itertools.product(("opamp", "and4"), ("none", "binary", "full")):
            selected = [r for r in rows if (r["circuit"], r["feedback"]) == key]
            valid = sum(r["simulation"]["valid"] is True for r in selected)
            success = sum(r["simulation"]["valid"] is True and (r.get("detector") or {}).get("is_trojan") is False for r in selected)
            group = groups[key]
            require(group["attempts"] == len(selected) == 20 and group["valid"] == valid
                    and group["valid_undetected"] == success and group["primary_rate"] == success / len(selected)
                    and group["conditional_evasion_rate"] == (success / valid if valid else None),
                    "Summary rates or denominators differ from raw records")
        with (folder / "attempts.csv").open(newline="") as stream:
            csv_rows = list(csv.DictReader(stream))
        index = {(r["circuit"], r["feedback"], int(r["trajectory"]), int(r["round"])): r for r in csv_rows}
        require(len(index) == len(csv_rows) == len(rows), "CSV omits or duplicates attempts")
        for row in rows:
            flat = index[(row["circuit"], row["feedback"], row["trajectory"], row["round"])]
            verdict = row.get("detector") or {}
            require(all(flat[name] == str(row[name]) for name in ("candidate_id", "prompt_version", "attacker_call_id", "detector_call_id", "success"))
                    and flat["valid"] == str(row["simulation"]["valid"])
                    and flat["confidence"] == (str(verdict["confidence"]) if "confidence" in verdict else "")
                    and json.loads(flat["parameters_json"]) == row["parameters"], "CSV differs from a raw attempt")
        for name, expected_count in (("groups.csv", 6), ("controls.csv", 4)):
            with (folder / name).open(newline="") as stream:
                records = list(csv.DictReader(stream))
            require(len(records) == expected_count, "CSV group/control count differs")
            if name == "groups.csv":
                for record in records:
                    expected = groups[record["circuit"], record["feedback"]]
                    require(all(int(record[field]) == expected[field] for field in ("attempts", "valid", "valid_undetected")),
                            "Group CSV differs from summary")
            files.append(str((folder / name).relative_to(root)))
        files.extend(str((folder / name).relative_to(root)) for name in ("attempts.csv", "summary.json"))
        for figure in ("attempt_outcomes", "trajectory_success"):
            for suffix in ("png", "pdf"):
                name = f"results/{run_id}/figures/{figure}.{suffix}"
                path = existing(root, name)
                if suffix == "png":
                    require(path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"), "Invalid PNG figure")
                else:
                    require(len(PdfReader(path).pages) > 0, "Empty PDF figure")
                files.append(name)
    return {"artifacts": files}


def check_defense_comparison(root):
    """Recompute the separate paired review audit without making API requests."""
    from scripts.defense.verify import verify as verify_defense
    folder = root / "results/defense_comparison_v1"
    saved = read(folder / "independent_audit.json")
    actual = verify_defense(root)
    require(saved.get("passed") is True and saved.get("complete") is True,
            "Supplementary detector comparison has not passed its independent audit")
    require({key: value for key, value in saved.items() if key != "audited_at_utc"} == actual,
            "Supplementary detector audit differs from raw evidence")
    require(actual["corpus"]["unique_cases"] == 33
            and actual["request_plan"]["planned_requests"] == 198
            and actual["api"]["scheduled_reviews"] == 198,
            "Supplementary detector allocation differs")
    return {"distinct_circuits": 33, "scheduled_reviews": 198,
            "usable_reviews": actual["api"]["usable_reviews"],
            "unusable_reviews": actual["api"]["unusable_reviews"],
            "matched_inputs_and_seeds_verified": True,
            "independently_recounted_from_raw_responses": True}


def check_delivery(root, report):
    """Return a complete check ledger; failed checks never become scientific successes."""
    config = read(root / "configs/proposal_experiment.json")
    requirements = read(root / "docs/proposal_requirements.json")
    run_ids = list(config["run_seeds"])
    checks = {}
    values = {}

    def stage(name, operation, evidence):
        try:
            value = operation()
            values[name] = value
            checks[name] = {"passed": True, "evidence": evidence, "details": value}
        except (OSError, ValueError, KeyError, TypeError, AssertionError) as exc:
            checks[name] = {"passed": False, "evidence": evidence, "error": str(exc)}

    def configuration():
        require(config["circuits"] == ["opamp", "and4"]
                and config["feedback_levels"] == ["none", "binary", "full"], "Expected exactly two circuits and three feedback conditions")
        require(config["trajectories"] == 2 and config["rounds_per_trajectory"] == 10
                and config["control_repeats"] == 5 and config["shared_first_round"] is True, "Declared allocation differs")
        require(len(run_ids) == len(set(run_ids)) == 2
                and len(set(config["run_seeds"].values())) == 2, "Expected two declared executions with distinct seeds")
        require(requirements["active_protocol"]["execution_runs"] == run_ids
                and requirements["active_protocol"]["protocol"] == config["protocol"], "Requirements map names a different final protocol")
        return {"protocol": config["protocol"], "runs": run_ids, "groups_per_run": 6,
                "attempts_per_group_per_run": 20, "rows_per_run": 120, "generation_events_per_run": 112}

    stage("configuration", configuration, ["configs/proposal_experiment.json", "docs/proposal_requirements.json"])
    rows_by_run = {}

    def protocol():
        audits = []
        for run_id in run_ids:
            actual = audit_run(root, run_id)
            saved = read(root / "results" / run_id / "independent_audit.json")
            require(actual == saved, "Saved protocol audit differs from freshly recomputed audit: " + run_id)
            audits.append(actual)
            rows_by_run[run_id] = read(root / "results" / run_id / "attempts.json")
        repeat = check_independent_repeat(*audits)
        require(repeat == read(root / "results" / run_ids[1] / "replication_audit.json"), "Saved replication audit differs")
        return {"attempt_rows": sum(a["attempt_rows"] for a in audits),
                "candidate_events": sum(a["candidate_events"] for a in audits),
                "actual_api_events": sum(a["api_event_count"] for a in audits),
                "same_frozen_model_inputs": True, "separate_response_ids": True,
                "identical_execution_protocol": not any(a.get("protocol_deviation") for a in audits)}

    audit_paths = [f"results/{run_id}/independent_audit.json" for run_id in run_ids]
    if len(run_ids) == 2:
        audit_paths += [f"results/{run_ids[1]}/replication_audit.json", "results/proposal_audit/audit.json"]
    stage("protocol", protocol, audit_paths[:-1])

    def qualification():
        result = audit_qualification(root)
        require(result["qualified_combinations"] == 135, "Expected 135 qualified legal options")
        qualified = read(root / "results/proposal_validation/qualification_summary.json")
        require(qualified["groups"] == {"opamp": {"combinations": 81, "passed": 81},
                                         "and4": {"combinations": 54, "passed": 54}}, "Qualified menu dimensions differ")
        version = existing(root, "results/environment/ngspice_version.txt").read_text()
        require("ngspice" in version.lower(), "Simulator version evidence is absent")
        return result

    stage("qualification", qualification, ["results/proposal_validation/qualification_summary.json", "results/environment/ngspice_version.txt"])
    stage("controls", lambda: {run_id: control_acceptance(root, run_id, config["circuits"])
                               for run_id in run_ids}, [f"results/{r}/controls.json" for r in run_ids])

    def electrical():
        require(len(rows_by_run) == 2, "Complete protocol evidence is required first")
        path = root / "results/proposal_audit/audit.json"
        audit = read(path)
        result = check_electrical_coverage(audit, rows_by_run)
        require(audit["audit_script_sha256"] == sha(root / "scripts/proposal/audit_simulations.py"), "Electrical audit implementation changed")
        for run_id in run_ids:
            require(all(audit["frozen_source_checks"][run_id].values()), "Electrical audit has a source mismatch")
            for circuit in config["circuits"]:
                require(audit["clean_checks"][run_id][circuit]["matches_qualification"] is True,
                        "Fresh clean simulation differs from qualification")
                for name in ("normal.cir", "normal.log", "normal.tsv", "trigger.cir", "trigger.log", "trigger.tsv"):
                    existing(root, f"results/proposal_audit/clean/{run_id}/{circuit}/{name}")
        for row in audit["fresh_netlist_checks"]:
            folder = root / "results/proposal_audit/distinct_candidates" / row["netlist_sha256"][:16]
            require(sha(folder / "candidate.cir") == row["netlist_sha256"]
                    and read(folder / "validation.json") == row["fresh_simulation"], "Fresh simulation artifacts differ from audit")
            for name in ("normal.cir", "normal.log", "normal.tsv", "trigger.cir", "trigger.log", "trigger.tsv"):
                existing(root, str((folder / name).relative_to(root)))
        return result

    stage("electrical", electrical, ["results/proposal_audit/audit.json", "results/proposal_audit/distinct_candidates/"])
    stage("analysis", lambda: check_analysis(root, run_ids, rows_by_run),
          [f"results/{r}/summary.json" for r in run_ids] + [f"results/{r}/attempts.csv" for r in run_ids])

    has_defense_comparison = (root / "configs/defense_comparison.json").exists()
    if has_defense_comparison:
        stage("supplementary_defense", lambda: check_defense_comparison(root),
              ["configs/defense_comparison.json", "results/defense_comparison_v1/independent_audit.json",
               "results/defense_comparison_v1/analysis.json", "results/defense_comparison_v1/reviews.json"])

    def report_check():
        from pypdf import PdfReader
        pdf = existing(root, str(report.relative_to(root)))
        provenance = read(pdf.with_suffix(".provenance.json"))
        check_provenance(root, provenance, pdf, run_ids, audit_paths)
        if has_defense_comparison:
            for name in ("analysis.json", "independent_audit.json"):
                source = "results/defense_comparison_v1/" + name
                require(provenance.get("analysis_sha256", {}).get(source) == sha(root / source),
                        "Report lacks matching supplementary detector evidence: " + source)
        pages = PdfReader(pdf).pages
        require(3 <= len(pages) <= 5 and provenance["pages"] == len(pages), "Report page count is outside 3-5 or differs from provenance")
        require(all(len(page.extract_text().strip()) > 100 for page in pages), "Report contains an empty/unreadable page")
        text = pdf.with_suffix(".txt").read_text().lower()
        require(re.search(r"omit\w* syntax.repair|skip\w*.*syntax", text), "Report lacks the excluded syntax-evaluation scope statement")
        require("netlist-only" in text and "finite" in text and "not held out" in text
                and "latent" in text and "localization" in text, "Report lacks required scope/control/metric distinctions")
        if any(not result["original_gate_passed"] for result in values.get("controls", {}).values()):
            require("deviation" in text and "3/5" in text and "gate" in text,
                    "Report does not disclose the failed repeat gate and continuation deviation")
        return {"pages": len(pages), "pdf_sha256": sha(pdf), "text_sha256": sha(pdf.with_suffix(".txt")),
                "provenance_bound_to_configured_runs": True}

    stage("report", report_check, [str(report.relative_to(root)), str(report.with_suffix(".provenance.json").relative_to(root))])

    def documentation():
        text = existing(root, "README.md").read_text()
        require(all(run_id in text for run_id in run_ids), "README does not identify the final executions")
        require(all(command in text for command in ("scripts.proposal.analyze", "scripts.proposal.verify",
                "scripts.proposal.audit_simulations", "scripts/build_proposal_report.py", "scripts.proposal.experiment")),
                "README lacks reproduction commands")
        for target in re.findall(r"\]\(([^)]+)\)", text):
            if not re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:|#", target):
                name = target.split("#", 1)[0]
                require((root / name).exists(), "README links to a missing artifact: " + name)
        for name in ("requirements.txt", "scripts/setup_ngspice.sh", "scripts/smoke_ngspice.py",
                     "netlists/templates/opamp.cir", "netlists/templates/and4.cir",
                     requirements["sources"]["proposal"], requirements["sources"]["execution_plan"]):
            existing(root, name)
        return {"readme_present": True, "local_links_resolve": True, "reproduction_commands_present": True}

    stage("documentation", documentation, ["README.md", "requirements.txt", "docs/inputs/"])
    stage("hypothesis", lambda: evaluate_hypothesis(rows_by_run) if len(rows_by_run) == 2
          else require(False, "Both complete runs are needed to evaluate the hypothesis"),
          [f"results/{r}/attempts.json" for r in run_ids])

    dependencies = {
        "S01": ["protocol"], "S02": ["qualification", "electrical"],
        "S03": ["configuration", "qualification", "electrical"], "S04": ["report"],
        "S05": ["qualification", "protocol", "report"], "S06": ["protocol", "report"],
        "S07": ["protocol"], "S08": ["protocol"], "S09": ["protocol"], "S10": ["protocol"],
        "S11": ["configuration", "protocol", "analysis"], "S12": ["configuration", "protocol", "analysis"],
        "S13": ["qualification", "protocol", "electrical"], "S14": ["controls", "protocol", "report"],
        "S15": ["protocol", "analysis"], "S16": ["protocol", "electrical", "documentation"],
        "S17": ["hypothesis", "analysis", "report"], "S18": ["documentation", "analysis"],
        "S19": ["report"],
    }
    mapped = []
    require({r["id"] for r in requirements["required_scope"]} == set(dependencies), "Unmapped proposal requirement")
    for item in requirements["required_scope"]:
        names = dependencies[item["id"]]
        passed = all(checks[name]["passed"] for name in names)
        status = ("evaluated" if item["id"] == "S17" else "verified") if passed else "failed"
        if passed and item["id"] in ("S14", "S16") and any(not r["original_gate_passed"] for r in values.get("controls", {}).values()):
            status = "verified_with_disclosed_deviation"
        mapped.append({"id": item["id"], "requirement": item["requirement"], "source": item["source"],
                       "status": status,
                       "checks": names, "evidence": sorted({p for name in names for p in checks[name]["evidence"]})})
    return {"complete": all(c["passed"] for c in checks.values()),
            "checked_at_utc": datetime.now(timezone.utc).isoformat(), "protocol": config["protocol"],
            "execution_runs": run_ids, "requirements": mapped, "checks": checks,
            "all_original_control_gates_passed": bool(values.get("controls")) and all(r["original_gate_passed"] for r in values.get("controls", {}).values()),
            "protocol_deviations": [r for r in values.get("controls", {}).values() if not r["original_gate_passed"]],
            "hypothesis": values.get("hypothesis"), "checker_sha256": sha(Path(__file__)),
            "requirements_sha256": sha(root / "docs/proposal_requirements.json"),
            "scope": "Evidence and deliverable completeness for the declared course-scale proposal. This is not full reproduction of A2, SPICED, or LATENT, a general security guarantee, or proof that a feedback condition is superior.",
            "verification_limits": "Machine checks bind artifacts, counts, routing, physical tests, and report provenance. Scientific interpretation and visual presentation also require human review."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=ROOT / REPORT)
    parser.add_argument("--output", type=Path, default=ROOT / "results/proposal_completion.json")
    args = parser.parse_args()
    result = check_delivery(ROOT, args.report.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"complete": result["complete"], "protocol": result["protocol"],
                      "runs": result["execution_runs"], "requirement_status_counts": dict(Counter(r["status"] for r in result["requirements"])),
                      "failed_checks": [name for name, check in result["checks"].items() if not check["passed"]],
                      "output": str(args.output)}, indent=2))
    if not result["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
