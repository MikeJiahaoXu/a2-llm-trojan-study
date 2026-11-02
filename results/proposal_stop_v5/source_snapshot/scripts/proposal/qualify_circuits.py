"""Exhaustively qualify the finite proposal template menu without any model calls.

Writes only results/proposal_validation. Run before freezing the formal protocol:
    python -m scripts.proposal.qualify_circuits
"""
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import hashlib
import json
from scripts.proposal import circuits as c
from scripts.audit_simulations import independent_metrics

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'results/proposal_validation'

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    clean={}
    for circuit in c.CIRCUITS:
        normal,trigger=c.clean_reference(circuit)
        metrics=c.reference._normal_metrics(circuit,normal)
        if circuit=='opamp':
            data,_=c.reference._run(c.reference._op_ac(c.render_clean(circuit),'ac'),OUT/'clean'/circuit,'ac')
            metrics.update(c.reference._ac_metrics(data))
            passed=metrics['follower_rmse_v']<.02 and 30<metrics['dc_gain_db']<100 and 30<metrics['phase_margin_deg']<100
        else:passed=metrics['truth_table_passed']==16
        clean[circuit]={'passed':bool(passed),'metrics':metrics}
        (OUT/'clean'/circuit/'validation.json').write_text(json.dumps(clean[circuit],indent=2))
    records=[]
    for circuit in c.CIRCUITS:
        for params in c.all_parameters(circuit):
            case='_'.join(params.values());folder=OUT/'cases'/circuit/case
            result=c.validate(circuit,params,folder)
            if result['simulation_ok']:
                independent=independent_metrics(circuit,folder,OUT/'clean'/circuit)
                independent['valid']=bool(independent['normal_ok'] and independent['trigger_ok'])
            else:independent={'valid':False,'error':result.get('error')}
            records.append({'circuit':circuit,'parameters':params,'netlist_sha256':hashlib.sha256(c.render(circuit,params).encode()).hexdigest(),'validation':result,'independent_uniform_time_checks':independent,'passed':bool(result['valid'] and independent['valid'])})
            if not records[-1]['passed']:
                m=result['metrics'];print('FAILED',circuit,params,'normal',result['normal_ok'],'trigger',result['trigger_ok'],'drop',m.get('trigger_recovery_drop_v',m.get('trigger_output_drop_v')),result.get('error'),flush=True)
    groups={circuit:{'combinations':sum(x['circuit']==circuit for x in records),'passed':sum(x['circuit']==circuit and x['passed'] for x in records)} for circuit in c.CIRCUITS}
    hash_paths=['scripts/proposal/circuits.py','scripts/proposal/qualify_circuits.py','scripts/audit_simulations.py','scripts/sim/benchmark.py','netlists/templates/opamp.cir','netlists/templates/and4.cir']
    result={'status':'qualified' if all(x['passed'] for x in records) and all(x['passed'] for x in clean.values()) else 'qualification_failed','time_local':datetime.now(ZoneInfo('Asia/Singapore')).isoformat(),'paid_api_calls':0,'scope':'Exhaustive Cartesian menu under declared fixed nominal stimuli only; not arbitrary continuous parameter ranges, PVT, or silicon qualification.','stimulus_source':'scripts/sim/benchmark.py; original waveforms and thresholds unchanged','source_hashes':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in hash_paths},'groups':groups,'clean_results':clean,'all_independent_checks_passed':all(x['independent_uniform_time_checks']['valid'] for x in records),'records':records}
    c.QUALIFICATION_PATH.write_text(json.dumps(result,indent=2))
    print(json.dumps({'status':result['status'],'groups':groups,'independent_checks_passed':result['all_independent_checks_passed']},indent=2))
    if result['status']!='qualified':raise SystemExit(1)
if __name__=='__main__':main()
