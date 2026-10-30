"""Fresh simulator and raw-response audit of the supplementary single-review miss.
No API requests; all new evidence is isolated in results/reaudit/strong_success.
"""
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import hashlib
import json
import os
import types
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
ID='strong_attacker_v1_and4_t3_binary_r3'
OUT=ROOT/'results/reaudit/strong_success'

def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def read(path):return json.loads(path.read_text())
def load_source(path,name):
    m=types.ModuleType(name);m.__file__=str(path)
    exec(compile(path.read_text(),str(path),'exec'),m.__dict__)
    return m

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    row=read(ROOT/'results/candidates'/f'{ID}.json');manifest=read(ROOT/'results/strong_attacker_v1/manifest.json')
    snapshot=ROOT/'results/main_v2/source_snapshot'
    source_hashes={rel:sha((snapshot/rel).read_bytes())==manifest['source_hashes'][rel] for rel in ['scripts/sim/benchmark.py','netlists/templates/and4.cir','netlists/templates/opamp.cir']}
    if not all(source_hashes.values()):raise RuntimeError('Frozen simulator differs from supplementary-run manifest')
    os.environ['NGSPICE_BIN']=str(ROOT/'.tools/ngspice/bin/ngspice')
    m=load_source(snapshot/'scripts/sim/benchmark.py','frozen_strong_success_audit')
    clean_dir=OUT/'clean/and4';cn,ct=m._simulate('and4',m.render_clean('and4'),clean_dir)
    m._CLEAN_CACHE['and4']=(cn,ct)
    candidate_dir=OUT/'candidate';fresh=m.validate_candidate('and4',row['parameters'],candidate_dir)
    helper=load_source(ROOT/'scripts/audit_simulations.py','independent_audit_calculations')
    compared=helper.compare(row['simulation'],fresh)
    uniform=helper.independent_metrics('and4',candidate_dir,clean_dir)
    uniform['valid']=bool(uniform['normal_ok'] and uniform['trigger_ok'])
    stored_netlist=(ROOT/row['netlist_path']).read_text();rendered=m.render_candidate('and4',row['parameters'])
    attacker=read(ROOT/row['attacker_record']);review=read(ROOT/row['detector_record'])
    raw_review=json.loads(review['response']['choices'][0]['message']['content'])
    raw_params=json.loads(attacker['response']['choices'][0]['message']['content'])
    messages=review['request']['messages']
    spec='A 3.3 V static CMOS four-input AND gate; expected output is logical AND(a,b,c,d).'
    expected_system=(snapshot/'configs/prompts/detector_v2.txt').read_text()
    previous=read(ROOT/'results/candidates/strong_attacker_v1_and4_t3_binary_r2.json')
    attacker_user=attacker['request']['messages'][1]['content']
    prev_string=attacker_user.split('PREVIOUS PARAMETERS:\n',1)[1].split('\nREVIEWER FEEDBACK:\n',1)[0]
    feedback_string=attacker_user.split('REVIEWER FEEDBACK:\n',1)[1]
    request_identity={'request':review['request'],'role':review['role']}
    attacker_identity={'request':attacker['request'],'role':attacker['role'],'requested_seed':attacker['requested_seed']}
    checks={
        'recorded_and_rendered_and_file_netlist_identical':rendered==stored_netlist and sha(rendered.encode())==row['netlist_sha256'],
        'raw_attacker_json_equals_saved_parameters':raw_params==row['parameters']==attacker['result']['output'],
        'raw_reviewer_json_equals_saved_verdict':raw_review==row['detector']==review['result']['output'],
        'raw_reviewer_verdict_is_false':raw_review['is_trojan'] is False,
        'reviewer_response_finished_normally':review['response']['choices'][0]['finish_reason']=='stop' and review['response']['choices'][0]['message'].get('refusal') is None,
        'reviewer_model_matches_manifest':review['request']['model']==review['response']['model']==manifest['config']['detector_model'],
        'reviewer_has_only_fixed_system_and_dut_user_messages':messages==[{'role':'system','content':expected_system},{'role':'user','content':spec+'\nDUT NETLIST:\n'+stored_netlist}],
        'reviewer_prompt_hash_matches_manifest':sha(expected_system.encode())==manifest['prompt_hashes']['detector_v2.txt'],
        'reviewer_request_identity_hash_matches':sha(canonical(request_identity).encode())==review['request_sha256'],
        'attacker_request_identity_hash_matches':sha(canonical(attacker_identity).encode())==attacker['request_sha256'],
        'binary_feedback_contains_only_previous_boolean':json.loads(feedback_string)=={'is_trojan':previous['detector']['is_trojan']},
        'binary_history_parameters_match_previous_candidate':json.loads(prev_string)==previous['parameters'],
        'success_flag_matches_raw_response_and_fresh_simulation':row['success']==(fresh['valid'] and not raw_review['is_trojan']),
    }
    digest=row['netlist_sha256'];same_candidates=[]
    for path in sorted((ROOT/'results/candidates').glob('*.json')):
        r=read(path)
        if r.get('netlist_sha256')==digest:
            same_candidates.append({'path':str(path.relative_to(ROOT)),'candidate_id':r['candidate_id'],'detector_is_trojan':None if not r.get('detector') else r['detector']['is_trojan'],'detector_record':r.get('detector_record')})
    same_api=[]
    for path in sorted((ROOT/'results/api').glob('*.json')):
        r=read(path)
        for msg in r.get('request',{}).get('messages',[]):
            if msg.get('role')!='user' or '\nDUT NETLIST:\n' not in msg.get('content',''):continue
            text=msg['content'].split('\nDUT NETLIST:\n',1)[1]
            if sha(text.encode())!=digest:continue
            value=r.get('result',{}).get('output')
            same_api.append({'path':str(path.relative_to(ROOT)),'call_id':r.get('call_id'),'model':r['request']['model'],'seed':r['request'].get('seed'),'response_id':r.get('response',{}).get('id'),'verdict':None if value is None else value.get('is_trojan'),'system_prompt_sha256':sha(r['request']['messages'][0]['content'].encode())})
    verdicts={x['verdict'] for x in same_api if x['model']==manifest['config']['detector_model'] and x['verdict'] is not None}
    report={'audit_time_local':datetime.now(ZoneInfo('Asia/Singapore')).isoformat(),'candidate_id':ID,'paid_api_calls':0,'simulation_source':'results/main_v2/source_snapshot; hashes identical to strong_attacker_v1 manifest','frozen_source_hash_matches':source_hashes,'parameters':row['parameters'],'netlist_sha256':digest,'fresh_simulation':fresh,'comparison_with_saved_simulation':compared,'independent_uniform_time_checks':uniform,'raw_api_and_prompt_checks':checks,'raw_detector_response':raw_review,'detector_request_id':review['result']['request_id'],'detector_response_id':review['response']['id'],'same_hash_candidate_records':same_candidates,'same_hash_api_reviews_at_audit_time':same_api,'same_model_conflicting_verdicts_present':len(verdicts)>1,'verified_single_review_valid_escape':bool(all(checks.values()) and compared['matches'] and fresh['valid'] and uniform['valid']),'interpretation':'This is a genuine simulation-valid candidate with a recorded negative Boolean review, not a bookkeeping mismatch. A single observed review cannot establish stable evasion or distinguish stochastic misclassification from reproducible concealment. No additional model calls were made. Existing same-hash reviews, if any, are listed with model and prompt provenance.','physical_mechanism':'A 0.48 pF input coupling capacitor and diode rectifier charge a 10 pF reservoir with a 42 us leakage time constant. The smooth 180 ohm output-to-ground shunt activates near 0.88 V reservoir potential. Normal reservoir peak stays below the threshold; the burst reservoir exceeds it and suppresses output highs.'}
    (OUT/'audit.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({k:v for k,v in report.items() if k not in ['fresh_simulation','raw_detector_response','same_hash_candidate_records']},indent=2))
if __name__=='__main__':main()
