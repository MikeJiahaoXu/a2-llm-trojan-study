"""Independent, offline verification of the proposal experiment's evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path

from scripts.eval.verify_cross_review import check_raw, check_verdict, require
from scripts.proposal import circuits, prompts

ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def check_feedback(messages, feedback, previous):
    """Check the masks independently of the request builder's implementation."""
    text = messages[-1]["content"]
    pmark, rmark = "\nPREVIOUS PARAMETERS:\n", "\nREVIEWER FEEDBACK:\n"
    if feedback == "none" or previous is None:
        require(pmark not in text and rmark not in text, "Fresh condition contains prior information")
        return
    require(pmark in text, "Revision lacks preceding parameters")
    tail = text.split(pmark, 1)[1]
    actual_parameters = json.loads(tail.split(rmark, 1)[0])
    require(actual_parameters == previous["parameters"], "Preceding parameters belong to another candidate")
    verdict = previous.get("detector")
    if verdict is None:
        require(rmark not in tail, "Missing verdict was replaced by invented feedback")
    else:
        require(rmark in tail, "Revision lacks its available verdict")
        actual = json.loads(tail.split(rmark, 1)[1])
        expected = {"is_trojan": verdict["is_trojan"]} if feedback == "binary" else verdict
        require(actual == expected, "Feedback mask differs from the declared condition")


def check_qualification_coverage(schemas, records):
    expected = set()
    for circuit, schema in schemas.items():
        names = schema["required"]
        for values in itertools.product(*(schema["properties"][name]["enum"] for name in names)):
            expected.add((circuit, canonical(dict(zip(names, values)))))
    actual = [(r["circuit"], canonical(r["parameters"])) for r in records]
    require(len(actual) == len(set(actual)) and set(actual) == expected,
            "Qualification omits, duplicates, or adds Cartesian combinations")
    return len(expected)


def audit_qualification(root):
    path = root/"results/proposal_validation/qualification_summary.json"
    qualification = read(path)
    require(qualification["status"] == "qualified", "Template space is not qualified")
    for name, expected in qualification["source_hashes"].items():
        require(sha(root/name) == expected, "Qualification source changed: " + name)
    schemas = {c: circuits.schema(c) for c in ("opamp", "and4")}
    count = check_qualification_coverage(schemas, qualification["records"])
    for row in qualification["records"]:
        require(row["passed"] is True and row["validation"]["valid"] is True
                and row["independent_uniform_time_checks"]["valid"] is True, "Unqualified legal candidate")
        netlist = circuits.render(row["circuit"], row["parameters"])
        require(hashlib.sha256(netlist.encode()).hexdigest() == row["netlist_sha256"], "Qualified DUT changed")
        case = "_".join(row["parameters"][name] for name in schemas[row["circuit"]]["required"])
        folder = path.parent/"cases"/row["circuit"]/case
        require(read(folder/"validation.json") == row["validation"], "Qualification metrics differ from saved simulation")
        require(sha(folder/"candidate.cir") == row["netlist_sha256"], "Qualification deck hash differs")
    require(all(qualification["clean_results"][c]["passed"] for c in schemas), "Clean validation failed")
    return {"passed": True, "qualified_combinations": count, "qualification_sha256": sha(path)}


def _find_record(root, row, field, logical_id, ledger):
    if row.get(field):
        return read(root/row[field])
    # A billed refusal/truncation may not return a record path to the runner.
    retry = logical_id + "_transport_retry1"
    entry = ledger["calls"].get(retry) or ledger["calls"].get(logical_id)
    return read(root/entry["record"]) if entry else None


def _check_api(raw, config, messages, schema, output, seed, max_tokens, output_failure=False):
    require(raw is not None, "Attempt lacks an actual API record")
    if not output_failure:
        check_raw(raw, config["model"], messages, schema, output, seed=seed, max_tokens=max_tokens)
    else:
        request, result, response = raw["request"], raw["result"], raw["response"]
        require(request["model"] == response["model"] == result["model"] == config["model"], "Failure record model differs")
        require(request["messages"] == messages and request["temperature"] == config["temperature"], "Failure record prompt/settings differ")
        require(request["response_format"]["json_schema"]["schema"] == schema, "Failure record schema differs")
        require(result.get("output_error") and result["output"] is None and output is None,
                "Unusable output was not retained honestly")
    return raw["call_id"], raw["response"]["id"]


def check_deviation_timing(recorded_at_utc, events):
    recorded = datetime.fromisoformat(recorded_at_utc)
    require(recorded.tzinfo is not None and events, "Deviation timing lacks dated event evidence")
    starts = []
    for event in events:
        started = datetime.fromisoformat(event["created_at_utc"])
        require(started.tzinfo is not None and started > recorded, "Repeat API event predates the recorded deviation")
        starts.append(started)
        raw = event.get("raw")
        if raw:
            require(datetime.fromisoformat(raw["created_at_utc"]) == started, "Raw request timestamp differs from ledger")
            if raw.get("response", {}).get("created") is not None:
                require(raw["response"]["created"] >= int(recorded.timestamp()), "Server response predates the deviation")
    first = min(starts)
    return {"passed": True, "events_including_transport_retries": len(events),
            "earliest_request_created_at_utc": first.astimezone(timezone.utc).isoformat(),
            "minimum_seconds_after_recorded_deviation": (first-recorded).total_seconds()}


def audit_deviation_timing(root, run_id, sealed):
    ledger = read(root / "results/cost_ledger.json")
    events = []
    for call_id, entry in ledger["calls"].items():
        if call_id.startswith(run_id + "_") and not call_id.startswith(run_id + "_control_") \
                and entry.get("role") in {"proposal_attacker", "proposal_detector"}:
            item = {"created_at_utc": entry["created_at_utc"]}
            path = root / entry["record"]
            if path.exists():
                raw = read(path)
                require(raw["call_id"] == call_id, "Deviation timing record belongs to another API event")
                item["raw"] = raw
            events.append(item)
    return check_deviation_timing(sealed["deviation"]["recorded_at_utc"], events)


def audit_run(root, run_id):
    folder = root/"results"/run_id
    manifest, rows, controls, completion = (read(folder/name) for name in
        ("manifest.json", "attempts.json", "controls.json", "completion.json"))
    config = manifest["config"]
    require(completion.get("complete") is True, "Run incomplete")
    require(read(root/"configs/proposal_experiment.json") == config, "Manifest configuration differs from the frozen configuration file")
    require(config["circuits"] == ["opamp", "and4"] and config["feedback_levels"] == ["none", "binary", "full"],
            "The proposal requires exactly the declared two circuits and three feedback conditions")
    require(config["trajectories"]*config["rounds_per_trajectory"] == 20, "Attempt budget differs")
    require(run_id in config["run_seeds"] and manifest["base_seed"] == config["run_seeds"][run_id], "Undeclared execution seed")
    for name, expected in manifest["source_hashes"].items():
        require(sha(root/name) == expected, "Frozen source changed: " + name)
        require(sha(folder/"source_snapshot"/name) == expected, "Snapshot differs: " + name)
    qualification = audit_qualification(root)
    expected = set(itertools.product(config["circuits"], config["feedback_levels"],
                                    range(config["trajectories"]), range(config["rounds_per_trajectory"])))
    keys = [(r["circuit"],r["feedback"],r["trajectory"],r["round"]) for r in rows]
    require(len(keys) == len(set(keys)) and set(keys) == expected, "Missing, duplicate, or unexpected attempts")
    require(completion["attempt_rows"] == len(rows), "Completion row count differs")
    index = dict(zip(keys, rows)); unique = {}; events = {}
    ledger = read(root/"results/cost_ledger.json")
    for row in rows:
        expected_seed = config["run_seeds"][run_id] + config["circuits"].index(row["circuit"])*1000 + row["trajectory"]*100 + row["round"]
        require(row["seed"] == expected_seed, "Attempt seed differs from the declared schedule")
        prior = None if row["round"] == 0 else index[row["circuit"],row["feedback"],row["trajectory"],row["round"]-1]
        previous_id = prior["candidate_id"] if prior and row["feedback"] != "none" else None
        require(row["previous_candidate_id"] == previous_id, "Preceding-candidate link differs")
        messages = prompts.attacker_messages(row["circuit"], prior, row["feedback"])
        generation = _find_record(root,row,"attacker_record",row["attacker_call_id"],ledger)
        check_feedback(generation["request"]["messages"],row["feedback"],prior)
        call_id,response_id = _check_api(generation,config,messages,circuits.schema(row["circuit"]),
                                        row["parameters"],row["seed"],500,bool(row.get("generation_error")))
        events[call_id] = response_id
        candidate = read(root/"results/candidates"/(row["candidate_id"]+".json"))
        require(all(candidate[k] == row[k] for k in candidate), "Analysis row differs from canonical candidate")
        if row.get("netlist_path"):
            netlist = circuits.render(row["circuit"],row["parameters"])
            require((root/row["netlist_path"]).read_text() == netlist, "Actual generated DUT differs from declared edit")
            require(hashlib.sha256(netlist.encode()).hexdigest() == row["netlist_sha256"], "Generated DUT hash differs")
            simpath = root/"results/simulations"/row["candidate_id"]
            require(read(simpath/"validation.json") == row["simulation"], "Per-attempt simulation evidence differs")
            require((simpath/"candidate.cir").read_text() == netlist, "Simulator tested another candidate")
            if row["simulation"]["simulation_ok"]:
                require(row["simulation"]["resolved_parameters"] == circuits.resolved_parameters(row["circuit"],row["parameters"]),
                        "Physical parameter resolution differs")
            review = _find_record(root,row,"detector_record",row["detector_call_id"],ledger)
            if row.get("detector") is not None:
                check_verdict(row["detector"])
            call_id,response_id = _check_api(review,config,prompts.detector_messages(row["circuit"],netlist),
                prompts.DETECTOR_SCHEMA,row.get("detector"),row["seed"]+1000000,800,bool(row.get("detector_error")))
            events[call_id] = response_id
        else:
            require(row.get("detector") is None and row["simulation"]["valid"] is False, "Non-rendered attempt cannot succeed")
        success = row["simulation"]["valid"] and (row.get("detector") or {}).get("is_trojan") is False
        require(row["success"] is bool(success), "Invalid or flagged candidate counted as success")
        unique[row["candidate_id"]] = row
    expected_events = len(config["circuits"])*config["trajectories"]*(1+len(config["feedback_levels"])*(config["rounds_per_trajectory"]-1))
    require(len(unique) == expected_events == completion["unique_candidates"], "Generation-event count differs")
    for circuit,trajectory in itertools.product(config["circuits"],range(config["trajectories"])):
        initial = [index[circuit,level,trajectory,0] for level in config["feedback_levels"]]
        require(len({r["candidate_id"] for r in initial}) == 1, "Initial candidate was not paired")
        require(len({canonical({k:r[k] for k in ("parameters","detector","simulation")}) for r in initial}) == 1,
                "Shared first-round results diverge")
    ckeys = [(r["circuit"],r["label"],r["repeat"]) for r in controls]
    required_controls = set(itertools.product(config["circuits"],["clean","positive"],range(config["control_repeats"])))
    require(len(ckeys) == len(set(ckeys)) and set(ckeys) == required_controls, "Control allocation differs")
    for row in controls:
        expected_seed = config["run_seeds"][run_id] + 50000 + config["circuits"].index(row["circuit"])*100 + row["repeat"]
        require(row["seed"] == expected_seed, "Control seed differs from the declared schedule")
        netlist = (root/row["netlist_path"]).read_text()
        expected_netlist = circuits.render_clean(row["circuit"]) if row["label"] == "clean" else circuits.render(
            row["circuit"],circuits.known_positive_examples(row["circuit"])[0])
        require(netlist == expected_netlist and sha(root/row["netlist_path"]) == row["netlist_sha256"], "Control input differs")
        if row["label"] == "positive":
            require(row["validation"] == read(folder/"control_simulations"/row["circuit"]/"validation.json")
                    and row["validation"]["valid"] is True, "Positive control lacks matching physical evidence")
        else:
            require(row["validation"] is None, "Clean control contains positive-control metadata")
        check_verdict(row["detector"])
        call_id,response_id = _check_api(read(root/row["detector_record"]),config,prompts.detector_messages(row["circuit"],netlist),
            prompts.DETECTOR_SCHEMA,row["detector"],row["seed"],800)
        events[call_id] = response_id
    require(len(events) == len(set(events.values())), "Different API events reused a raw response ID")
    result = {"passed":True,"run_id":run_id,"attempt_rows":len(rows),"candidate_events":len(unique),
            "distinct_netlists":len({r["netlist_sha256"] for r in unique.values() if r.get("netlist_sha256")}),
            "valid_candidate_events":sum(r["simulation"]["valid"] for r in unique.values()),
            "successful_candidate_events":sum(r["success"] for r in unique.values()),
            "control_judgments":len(controls),"api_event_count":len(events),"qualification":qualification,
            "source_hashes":manifest["source_hashes"],"api_call_ids":sorted(events),"api_response_ids":sorted(events.values()),
            "checks":["exact original feedback masks","actual prompt/schema/model/settings/output",
                      "complete six-group allocation","source snapshots","full Cartesian electrical qualification",
                      "declared rendering and per-candidate simulation","honest failure denominators",
                      "shared initial candidates","actual independent API events","required clean/positive controls"]}
    deviation = folder / "control_gate_deviation.json"
    if deviation.exists():
        from scripts.proposal.continue_after_controls import verify_deviation
        sealed = verify_deviation(root, run_id)
        launcher = folder / "source_snapshot/scripts/proposal/continue_after_controls.py"
        require(sha(launcher) == sealed["deviation"]["launcher_sha256"], "Continuation source snapshot differs")
        result["protocol_deviation"] = {"path": str(deviation.relative_to(root)), "sha256": sha(deviation),
            "type": sealed["deviation"]["type"], "original_gate_passed": False,
            "interpretation": sealed["deviation"]["interpretation_limit"],
            "recorded_before_repeat_requests": audit_deviation_timing(root, run_id, sealed)}
    return result


def check_independent_repeat(a, b):
    require(a["run_id"] != b["run_id"], "Replication reused the run identifier")
    require(a["source_hashes"] == b["source_hashes"], "Replication changed the frozen protocol")
    require(not set(a["api_call_ids"]) & set(b["api_call_ids"]), "Replication reused cached call IDs")
    require(not set(a["api_response_ids"]) & set(b["api_response_ids"]), "Replication reused actual response IDs")
    result = {"passed":True,"runs":[a["run_id"],b["run_id"]],
            "attempt_rows":a["attempt_rows"]+b["attempt_rows"],
            "candidate_events":a["candidate_events"]+b["candidate_events"],
            "interpretation":"Same frozen protocol, separate API events; repeated outputs remain legitimate repeated observations, not new circuit families."}
    deviations = [audit["protocol_deviation"] for audit in (a,b) if audit.get("protocol_deviation")]
    if deviations:
        result.update(same_frozen_model_inputs=True, identical_execution_protocol=False, protocol_deviations=deviations,
            interpretation="Same frozen model, prompts, circuit menu, seeds and allocation with separate API events. The repeat continued after a failed control gate under an explicit post-control deviation; the stopping protocol was not identical.")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", action="append", default=[])
    parser.add_argument("--qualification-only", action="store_true")
    args = parser.parse_args()
    if args.qualification_only:
        print(json.dumps(audit_qualification(ROOT),indent=2))
        return
    require(args.run_id, "Specify at least one completed run")
    audits = [audit_run(ROOT,run_id) for run_id in args.run_id]
    for audit in audits:
        (ROOT/"results"/audit["run_id"]/"independent_audit.json").write_text(json.dumps(audit,indent=2)+"\n")
        print(json.dumps({k:v for k,v in audit.items() if k not in {"api_call_ids","api_response_ids","source_hashes"}},indent=2))
    if len(audits) == 2:
        result = check_independent_repeat(*audits)
        (ROOT/"results"/audits[-1]["run_id"]/"replication_audit.json").write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(result,indent=2))


if __name__ == "__main__":
    main()
