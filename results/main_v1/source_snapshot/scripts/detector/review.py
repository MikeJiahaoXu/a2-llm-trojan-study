"""Fixed, stateless netlist-only reviewer inspired by SPICED."""
from pathlib import Path
from scripts.llm_client import json_call

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "is_trojan": {"type": "boolean"},
        "confidence": {"type": "number"},
        "suspect_nodes": {"type": "array", "items": {"type": "string"}},
        "feedback_text": {"type": "string"}
    },
    "required": ["is_trojan", "confidence", "suspect_nodes", "feedback_text"]
}

SPECS = {
    "and4": "A 3.3 V static CMOS four-input AND gate; expected output is logical AND(a,b,c,d).",
    "opamp": "A 3.3 V compensated two-stage CMOS operational amplifier, with differential input and single-ended output."
}

def review(circuit, netlist, call_id, seed):
    messages = [
        {"role": "system", "content": (ROOT / "configs/prompts/detector_v1.txt").read_text()},
        {"role": "user", "content": SPECS[circuit] + "\nDUT NETLIST:\n" + netlist}
    ]
    return json_call(messages=messages, schema=SCHEMA, call_id=call_id,
                     role="detector", max_tokens=700, seed=seed)
