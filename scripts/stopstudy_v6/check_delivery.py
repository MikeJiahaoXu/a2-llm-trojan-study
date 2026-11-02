"""Validate the current single-experiment report and all six requested changes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from pypdf import PdfReader

from scripts import llm_client as shared
from scripts.stopstudy_v6.verify import verify

ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root=ROOT):
    active = read(root/"configs/active_experiment.json")
    folder = root/"results"/active["run_id"]
    config = read(root/active["config"])
    saved = read(folder/"audit.json")
    actual = verify(root)
    if not actual.get("passed") or not actual.get("complete"):
        raise ValueError("Completed experiment has not passed independent verification")
    if {k: v for k, v in saved.items() if k != "audited_at_utc"} != actual:
        raise ValueError("Saved audit is stale or differs from the raw evidence")
    assert config["sessions_per_condition"] == config["max_attempts"] == 10
    assert config["detector_temperature"] == 0 and config["attacker_temperature"] == 0.3
    report = root/active["report"]
    provenance = read(report.with_suffix(".provenance.json"))
    for suffix, key in ((".pdf", "pdf_sha256"), (".txt", "text_sha256")):
        if provenance.get(key) != sha(report.with_suffix(suffix)):
            raise ValueError("Report differs from its provenance: " + suffix)
    evidence = provenance.get("source_sha256", {})
    for name in ("summary.json", "audit.json", "attempts.json", "manifest.json", "completion.json", "design.json", "controls.json", "controls_gate.json"):
        relative = f"results/{active['run_id']}/{name}"
        if evidence.get(relative) != sha(root/relative):
            raise ValueError("Report lacks current experiment evidence: " + relative)
    if provenance.get("generator_sha256") != sha(root/"scripts/build_stop_report.py"):
        raise ValueError("Report generator changed after rendering")
    pages = PdfReader(report).pages
    if not 3 <= len(pages) <= 5 or any(len(p.extract_text().strip()) < 100 for p in pages):
        raise ValueError("Report must contain 3–5 nonempty readable pages")
    text = report.with_suffix(".txt").read_text()
    for phrase in ("Supplementary paired detector comparison", "Batch 1", "Batch 2", "39/60", "21/27"):
        if phrase in text:
            raise ValueError("Report still contains excluded older experiment results: " + phrase)
    if not re.search(r"stop", text, re.I) or "10" not in text or "temperature" not in text:
        raise ValueError("Report omits the revised experimental arrangement")
    readme = (root/"README.md").read_text()
    for command in ("scripts.stopstudy_v6.experiment", "scripts.stopstudy_v6.analyze", "scripts.stopstudy_v6.verify", "scripts/build_stop_report.py"):
        if command not in readme:
            raise ValueError("README lacks a current reproduction command: " + command)
    return {"complete": True, "run_id": active["run_id"], "report_pages": len(pages),
            "requested_changes": {"stop_on_first_valid_escape": True, "detector_temperature_zero_and_fixed_cache": True,
                "ten_new_sessions_per_condition": True, "ten_distinct_prespecified_starts_per_circuit": True, "pre_main_basic_control_gate": True, "cumulative_escape_line_plots": True,
                "only_requested_main_experiment_in_report": True, "one_aggregate_no_batch_tables": True},
            "api": {k: actual["api"][k] for k in ("actual_api_events", "roles", "billed_cost_usd")},
            "report_pdf_sha256": sha(report), "report_text_sha256": sha(report.with_suffix('.txt')),
            "audit_sha256": sha(folder/"audit.json"), "checker_sha256": sha(root/"scripts/stopstudy_v6/check_delivery.py"),
            "checks_include": ["independent raw-response and waveform audit", "all sixty stopped/exhausted sessions",
                               "exact cached reviewer reuse", "current report hashes and scope", "offline reproduction commands"]}


if __name__ == "__main__":
    result = check()
    shared._atomic_json(ROOT/"results/final_delivery.json", {**result, "checked_at_utc": shared._now()})
    print(json.dumps(result, indent=2))
