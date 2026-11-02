"""Offline V6 control-gate recovery and preset-event behavior checks.

All API transport is blocked; fake reviewer outputs are saved as durable test
records. No study data, ledger, frozen sources, or live API state is modified.
"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import llm_client as shared
from scripts.proposal import circuits
from scripts.stopstudy_v6 import client, design, experiment as exp


class V6RuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="stop-v6-runtime-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.folder = self.root / "results/proposal_stop_v6"
        self.config = exp.read(exp.ROOT / exp.CONFIG)
        self.labels = {}
        self.interrupt_next_content = None
        self.successful_call_ids = []

        controls = design.render_controls()
        for control in controls:
            dut = control.pop("dut")
            path = self.folder / "controls" / (control["control_id"] + ".cir")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(dut)
            control["netlist_path"] = str(path.relative_to(self.root))
            self.labels[control["circuit"] + "\n" + dut] = control["expected_is_trojan"]
        starts = design.select_starts()
        for start in starts:
            dut = circuits.render(start["circuit"], start["parameters"])
            path = self.folder / "starts" / start["circuit"] / f'{start["session"]:02d}.cir'
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(dut)
            start["netlist_path"] = str(path.relative_to(self.root))
            self.labels[start["circuit"] + "\n" + dut] = False
        shared._atomic_json(self.folder / "design.json", {
            "specification": {"controls": controls, "starts": starts},
            "physical_control_checks": [
                {"control_id": control["control_id"], "control_physical_check_passed": True}
                for control in controls],
        })
        self.controls = controls
        self.starts = starts
        for mock in [
            patch.object(exp, "ROOT", self.root),
            patch.object(client, "record_path", side_effect=lambda call_id:
                self.root / "results/api" / (call_id + ".json")),
            patch.object(exp, "detector_messages", side_effect=lambda circuit, dut:
                [{"role": "user", "content": circuit + "\n" + dut}]),
            patch.object(client.urllib.request, "urlopen", side_effect=AssertionError("Network is forbidden")),
            patch("builtins.print"),
        ]:
            mock.start()
            self.addCleanup(mock.stop)
        mocked = patch.object(client, "json_call", side_effect=self.fake_call)
        self.api = mocked.start()
        self.addCleanup(mocked.stop)

    def fake_call(self, messages, schema, call_id, role, seed, max_tokens=None):
        self.assertEqual(role, "stop_detector", "Preset events must not invoke the attacker")
        content = messages[-1]["content"]
        if content == self.interrupt_next_content:
            self.interrupt_next_content = None
            raise RuntimeError("Offline process interruption")
        output = {"is_trojan": self.labels[content], "confidence": .8,
                  "suspect_nodes": [], "feedback_text": "Offline fixed review."}
        payload = client.payload_for(messages, schema, role, seed, max_tokens)
        shared._atomic_json(client.record_path(call_id), {
            "call_id": call_id, "role": role, "request": payload,
            "result": {"output": output},
        })
        self.successful_call_ids.append(call_id)
        return {"output": output}

    def test_correct_gate_uses_four_reviews_and_resumes_without_calls(self):
        first = exp.control_gate(self.config, self.folder)
        self.assertTrue(first["passed"])
        self.assertEqual(self.api.call_count, 4)
        self.assertTrue(all(row["passed"] for row in exp.read(self.folder / "controls.json")))
        self.assertEqual(exp.control_gate(self.config, self.folder), first)
        self.assertEqual(self.api.call_count, 4)

    def test_failed_gate_persists_and_blocks_main_even_if_future_output_would_pass(self):
        first = self.controls[0]
        content = first["circuit"] + "\n" + (self.root / first["netlist_path"]).read_text()
        self.labels[content] = not first["expected_is_trojan"]
        with self.assertRaisesRegex(RuntimeError, "failed the predeclared control gate"):
            exp.control_gate(self.config, self.folder)
        self.assertFalse(exp.read(self.folder / "controls_gate.json")["passed"])
        self.assertEqual(self.api.call_count, 4)
        self.labels[content] = first["expected_is_trojan"]
        with patch.object(exp, "freeze", return_value=(self.folder, exp.make_schedule(self.config))), \
             patch.object(exp, "event") as candidate, patch.object(exp, "clean_references") as references:
            with self.assertRaisesRegex(RuntimeError, "failed the predeclared control gate"):
                exp.run(self.config)
        candidate.assert_not_called()
        references.assert_not_called()
        self.assertEqual(self.api.call_count, 4)
        self.assertFalse((self.folder / "attempts.json").exists())
        self.assertFalse((self.folder / "completion.json").exists())

    def test_interrupted_gate_reuses_completed_control_without_resampling(self):
        second = self.controls[1]
        self.interrupt_next_content = second["circuit"] + "\n" + (self.root / second["netlist_path"]).read_text()
        with self.assertRaisesRegex(RuntimeError, "Offline process interruption"):
            exp.control_gate(self.config, self.folder)
        first_rows = exp.read(self.folder / "controls.json")
        self.assertEqual(len(first_rows), 1)
        self.assertFalse((self.folder / "controls_gate.json").exists())
        self.assertTrue(exp.control_gate(self.config, self.folder)["passed"])
        self.assertEqual(len(self.successful_call_ids), 4)
        self.assertEqual(len(set(self.successful_call_ids)), 4)
        self.assertEqual(exp.read(self.folder / "controls.json")[0], first_rows[0])

    def test_changed_gate_evidence_is_rejected_without_new_reviews(self):
        exp.control_gate(self.config, self.folder)
        path = self.folder / "controls.json"
        rows = exp.read(path)
        rows[0]["passed"] = False
        shared._atomic_json(path, rows)
        with self.assertRaisesRegex(ValueError, "Control results changed"):
            exp.control_gate(self.config, self.folder)
        self.assertEqual(self.api.call_count, 4)

    def fake_validation(self, circuit, parameters, directory):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "candidate.cir").write_text(circuits.render(circuit, parameters))
        for name in ("normal.cir", "trigger.cir", "normal.tsv", "trigger.tsv", "normal.log", "trigger.log"):
            (directory / name).write_text("offline fixture\n")
        result = {"valid": True, "normal_ok": True, "trigger_ok": True, "simulation_ok": True}
        shared._atomic_json(directory / "validation.json", result)
        return result

    def test_preset_is_physically_checked_reviewed_once_and_never_generates_via_api(self):
        task = next(t for t in exp.make_schedule(self.config)
                    if t["circuit"] == "and4" and t["session"] == 1 and t["attempt"] == 1)
        self.assertIsNone(task["seed"])
        with patch.object(circuits, "validate", side_effect=self.fake_validation) as simulate:
            event = exp.event(task, None, self.config, self.folder)
            self.assertEqual(event["parameters"], next(s["parameters"] for s in self.starts
                             if s["circuit"] == "and4" and s["session"] == 1))
            self.assertTrue(event["success"])
            self.assertEqual(event["attacker_records"], [])
            self.assertIsNone(event["attacker_record"])
            self.assertEqual(self.api.call_count, 1)
            self.assertEqual(self.api.call_args.args[3], "stop_detector")
            self.assertEqual(exp.event(task, None, self.config, self.folder), event)
            self.assertEqual(simulate.call_count, 1)
            self.assertEqual(self.api.call_count, 1)

        state, rows = {}, []
        exp.apply_event(task, event, state, rows, self.config)
        self.assertEqual(len(state), 3)
        self.assertEqual({r["feedback"] for r in rows}, {"none", "binary", "full"})
        self.assertTrue(all(r["shared_initial"] and r["success"] for r in rows))
        self.assertEqual(len({r["candidate_id"] for r in rows}), 1)
        following = next(t for t in exp.make_schedule(self.config)
                         if t["circuit"] == "and4" and t["session"] == 1
                         and t["feedback"] == "binary" and t["attempt"] == 2)
        with self.assertRaisesRegex(ValueError, "Attempt after first escape"):
            exp.apply_event(following, {**event, **following}, state, rows, self.config)


if __name__ == "__main__":
    unittest.main()
