#!/usr/bin/env python3
"""Validate the local ngspice CLI using an analytic first-order RC response."""
import json
import math
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "environment"
RESULTS.mkdir(parents=True, exist_ok=True)
executable = ROOT / ".tools" / "ngspice" / "bin" / "ngspice"
run = subprocess.run(
    [str(executable), "-b", str(ROOT / "netlists" / "smoke" / "hello_rc.cir")],
    capture_output=True, text=True, timeout=30, check=False,
)
log = run.stdout + run.stderr
(RESULTS / "hello_rc.log").write_text(log)
measured = {}
for name in ("v_tau", "v_final"):
    match = re.search(rf"^{name}\s*=\s*([0-9.eE+-]+)", log, re.MULTILINE)
    measured[name] = float(match.group(1)) if match else None
expected = {"v_tau": 1 - math.exp(-1), "v_final": 1 - math.exp(-5)}
passed = run.returncode == 0 and all(
    measured[name] is not None and abs(measured[name] - value) < 0.001
    for name, value in expected.items()
)
result = {
    "passed": passed,
    "returncode": run.returncode,
    "circuit": "R=1000 ohm, C=1 microfarad, 1 V step",
    "expected_volts": expected,
    "measured_volts": measured,
    "absolute_tolerance_volts": 0.001,
    "command": [str(executable.relative_to(ROOT)), "-b", "netlists/smoke/hello_rc.cir"],
}
(RESULTS / "hello_rc.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
raise SystemExit(0 if passed else 1)
