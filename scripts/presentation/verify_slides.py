"""Check the exported presentation against the current report and saved results."""
from pathlib import Path
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "output/slides/a2_feedback"
SCRATCH = ROOT / "tmp/slides/a2_feedback_final_report_2026-11-03"
NS = {"a": "http://schemas.openxmlformats.org/drawingml/2006/main"}


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize(text):
    return " ".join(text.split())


def check():
    active = read(ROOT / "configs/active_experiment.json")
    meta = read(OUT / "provenance.json")
    summary = read(ROOT / "results" / active["run_id"] / "summary.json")
    assert meta["run_id"] == active["run_id"] == "proposal_stop_v6"
    assert meta["pptx_sha256"] == sha(OUT / "output.pptx")
    assert meta["planned_seconds"] == 300 and 550 <= meta["spoken_words"] <= 700
    assert meta["attacker_temperature"] == .3 and meta["detector_temperature"] == 0
    for name, expected in meta["source_sha256"].items():
        assert sha(ROOT / name) == expected, name
    assert meta["report_modified"] is False
    assert sha(ROOT / meta["presentation_report"]) == meta["presentation_report_sha256"] == '89c091c8477b1b6beaa8ab2fa4d085492cb0033d3c7d989fc56d7629167ae970'
    groups = {(g["circuit"], g["feedback"]): g for g in summary["groups"]}
    for circuit in ("opamp", "and4"):
        assert meta["counts"][circuit] == [groups[circuit, f]["escaped_sessions"] for f in ("none", "binary", "full")]
        assert meta["initial_escapes"][circuit] == groups[circuit, "none"]["first_attempt_escapes"]
        for feedback in ("binary", "full"):
            points = groups[circuit, feedback]["cumulative_curve"]
            assert meta["attempt_reaching_ten"][circuit][feedback] == next(p["attempt"] for p in points if p["escaped_sessions"] == 10)
    with ZipFile(OUT / "output.pptx") as archive:
        slides = sorted((n for n in archive.namelist() if re.fullmatch(r"ppt/slides/slide\d+\.xml", n)),
                        key=lambda n: int(re.search(r"(\d+)\.xml", n).group(1)))
        notes = sorted(n for n in archive.namelist() if re.fullmatch(r"ppt/notesSlides/notesSlide\d+\.xml", n))
        assert len(slides) == len(notes) == meta["slides"] == 6
        texts = {i: normalize(" ".join(ET.fromstring(archive.read(name)).itertext())) for i, name in enumerate(slides, 1)}
        # Text in every authored textbox must occur in editable DrawingML runs.
        editable = {i: normalize(" ".join(t.text or "" for t in ET.fromstring(archive.read(name)).findall(".//a:t", NS)))
                    for i, name in enumerate(slides, 1)}
        native_textboxes = [shape for name in slides
                            for shape in ET.fromstring(archive.read(name)).iter()
                            if shape.tag.endswith('}sp')
                            and any((t.text or "").strip() for t in shape.findall(".//a:t", NS))]
        assert len(native_textboxes) == meta["editable_textboxes"]
        if (SCRATCH / "inspect.ndjson").exists():
            records = [json.loads(line) for line in (SCRATCH / "inspect.ndjson").read_text().splitlines()]
            textboxes = [r for r in records if r["kind"] == "textbox"]
            assert len(textboxes) == len(native_textboxes)
            for row in textboxes:
                assert normalize(row["text"]) in editable[row["slide"]], (row["slide"], row["role"])
        note_text = normalize(" ".join(" ".join(ET.fromstring(archive.read(n)).itertext()) for n in notes))
        assert note_text.count("ENGLISH TALK SCRIPT") == 6 and note_text.count("中文答辩提醒") == 6
        visible = " ".join(texts.values())
        assert "attacker 0.3" in visible and "detector 0.0" in visible
        assert "no attacker API call" in visible and "Stop at any attempt" in visible
        assert normalize(meta["feedback_example"]["summary"]) in visible
        assert "Detector learning" in visible and "Designer use" in visible and "Newer models" in visible
        request = read(ROOT / meta["feedback_example"]["attacker_record"])
        supplied = json.loads(request["request"]["messages"][1]["content"].split("REVIEWER FEEDBACK:\n")[1])
        attempts = read(ROOT / "results" / active["run_id"] / "attempts.json")
        prior = next(r for r in attempts if r["circuit"] == "and4" and r["feedback"] == "full" and r["session"] == 2 and r["attempt"] == 2)
        assert supplied == prior["detector"] and supplied["is_trojan"] is True
        assert "voltage at node n31" in supplied["feedback_text"]
        assert "potential Trojan mechanism" in supplied["feedback_text"]
        assert not re.search(r"42\s*/\s*60|40\s*/\s*40|Batch [12]|continuation exception|out of 20 attempts|both roles.{0,25}temperature 0\.3", visible + note_text, re.I)
        media = [n for n in archive.namelist() if n.startswith("ppt/media/")]
        figure = meta["reused_report_figures"][0]
        assert len(media) == 1 and hashlib.sha256(archive.read(media[0])).hexdigest() == figure["sha256"]
        import fitz
        with fitz.open(ROOT / figure["source_pdf"]) as report:
            extracted = report.extract_image(figure["source_xref"])["image"]
            assert hashlib.sha256(extracted).hexdigest() == figure["sha256"]
        assert not any(re.search(r"/charts/chart\d+\.xml$", n) for n in archive.namelist())
    first_preview_hashes = read(SCRATCH / "preview_loop1_hashes.json") if (SCRATCH / "preview_loop1_hashes.json").exists() else {}
    unchanged_previews = [n for n, h in first_preview_hashes.items()
                          if (SCRATCH / "preview" / n).exists() and sha(SCRATCH / "preview" / n) == h]
    result = {"passed": True, "run_id": active["run_id"], "slides": 6,
              "planned_seconds": meta["planned_seconds"], "spoken_words": meta["spoken_words"],
              "editable_textboxes_verified": len(native_textboxes), "speaker_notes_verified": 6,
              "supplied_report_unchanged": True, "actual_feedback_verified": True,
              "exact_report_figure_embedded": True, "old_experiment_content_excluded": True,
              "pptx_sha256": meta["pptx_sha256"], "sources_verified": len(meta["source_sha256"]),
              "unchanged_previews_from_first_pass": unchanged_previews}
    SCRATCH.mkdir(parents=True, exist_ok=True)
    (SCRATCH / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
