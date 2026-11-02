"""Offline checks for diverse fixed starts and physically separate controls."""
import hashlib
import random
import unittest

from scripts.proposal import circuits
from scripts.stopstudy_v6 import design


class PrespecifiedDesignTests(unittest.TestCase):
    def test_starts_are_distinct_menu_members_and_cover_every_cell(self):
        starts = design.select_starts()
        self.assertEqual(len(starts), 20)
        for circuit in circuits.CIRCUITS:
            records = [r for r in starts if r["circuit"] == circuit]
            self.assertEqual([r["session"] for r in records], list(range(1, 11)))
            self.assertEqual(len({r["netlist_sha256"] for r in records}), 10)
            self.assertEqual({r["stratum"] for r in records}, {
                f"{site}/{rep}" for site in circuits.SITES[circuit]
                for rep in circuits.REPRESENTATIONS})
            menu = circuits.all_parameters(circuit)
            for record in records:
                self.assertIn(record["parameters"], menu)
                self.assertEqual(record["netlist_sha256"],
                    hashlib.sha256(circuits.render(circuit, record["parameters"]).encode()).hexdigest())

    def test_selection_is_reproducible_and_does_not_modify_global_rng(self):
        state = random.getstate()
        first = design.select_starts()
        self.assertEqual(random.getstate(), state)
        random.seed(923)
        second = design.select_starts()
        self.assertEqual(first, second)
        random.setstate(state)

    def test_fixed_positive_controls_are_outside_menu_and_preserve_clean_core(self):
        controls = design.render_controls()
        self.assertEqual(len(controls), 4)
        self.assertEqual(sum(r["expected_is_trojan"] for r in controls), 2)
        for control in controls:
            circuit = control["circuit"]
            clean = circuits.render_clean(circuit)
            self.assertEqual(design.digest(control["dut"]), control["netlist_sha256"])
            if control["kind"] == "clean":
                self.assertEqual(control["dut"], clean)
            else:
                self.assertNotIn(control["netlist_sha256"], {
                    design.digest(circuits.render(circuit, params))
                    for params in circuits.all_parameters(circuit)})
                clean_prefix, clean_suffix = clean.split(".ends dut")
                self.assertTrue(control["dut"].startswith(clean_prefix))
                self.assertIn(".ends dut"+clean_suffix, control["dut"])
                base = circuits.render(circuit, control["base_parameters"])
                resistance = circuits.resolved_parameters(circuit, control["base_parameters"])["payload_resistance_ohms"]
                expected = base.replace(f"RON={resistance:.8g} ",
                    f'RON={design.CONTROL_RESISTANCES[circuit]:.8g} ', 1)
                self.assertEqual(control["dut"], expected)


if __name__ == "__main__":
    unittest.main()
