"""Offline electrical audit of the completed proposal experiment and its repeat.

Loads frozen sources; writes new simulations only under results/proposal_audit.
No model/API calls. Refuses incomplete runs before creating an audit result.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import types
from zoneinfo import ZoneInfo

ROOT=Path(__file__).resolve().parents[2]
DEFAULT_RUNS=('proposal_main_v3','proposal_repeat_v3')


def read(path):return json.loads(path.read_text())
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def text_sha(text):return hashlib.sha256(text.encode()).hexdigest()

def load_source(path,name):
    module=types.ModuleType(name);module.__file__=str(path)
    exec(compile(path.read_text(),str(path),'exec'),module.__dict__)
    return module


def expected_counts(config):
    circuits=len(config['circuits']);levels=len(config['feedback_levels'])
    starts=config['trajectories'];rounds=config['rounds_per_trajectory']
    rows=circuits*levels*starts*rounds
    events=circuits*starts*(1+levels*(rounds-1)) if config.get('shared_first_round') else rows
    return rows,events


def prepare_run(run_id):
    folder=ROOT/'results'/run_id
    required=('completion.json','manifest.json','attempts.json')
    if not all((folder/name).exists() for name in required):raise ValueError(f'{run_id}: required completion/evidence files are absent; finish the run first')
    completion,manifest,rows=(read(folder/name) for name in required)
    if completion.get('complete') is not True:raise ValueError(f'{run_id}: execution is incomplete')
    expected_rows,expected_events=expected_counts(manifest['config'])
    events={}
    for row in rows:
        key=row['candidate_id']
        if key in events:
            fields=('circuit','parameters','netlist_sha256','simulation')
            if any(events[key].get(field)!=row.get(field) for field in fields):raise ValueError(f'{run_id}: shared event has inconsistent physical evidence: {key}')
        events[key]=row
    if len(rows)!=expected_rows or completion.get('attempt_rows')!=expected_rows or len(events)!=expected_events or completion.get('unique_candidates')!=expected_events:
        raise ValueError(f'{run_id}: expected {expected_rows} rows/{expected_events} events, got {len(rows)}/{len(events)}')
    snapshot=folder/'source_snapshot'
    source_checks={name:(snapshot/name).exists() and sha(snapshot/name)==digest for name,digest in manifest['source_hashes'].items()}
    if not all(source_checks.values()):raise ValueError(f'{run_id}: frozen source hash mismatch: {[k for k,v in source_checks.items() if not v]}')
    qualification_path=snapshot/'results/proposal_validation/qualification_summary.json'
    qualification=read(qualification_path)
    if qualification.get('status')!='qualified':raise ValueError(f'{run_id}: template menu was not fully qualified')
    for name,digest in qualification['source_hashes'].items():
        # Some qualification-only helpers are not runtime snapshot dependencies.
        path=snapshot/name if (snapshot/name).exists() else ROOT/name
        if sha(path)!=digest:raise ValueError(f'{run_id}: qualification source changed: {name}')
    reference=load_source(snapshot/'scripts/sim/benchmark.py',run_id+'_frozen_reference')
    circuits=load_source(snapshot/'scripts/proposal/circuits.py',run_id+'_frozen_circuits')
    circuits.reference=reference  # Isolated module object, not the shared import.
    circuits._CLEAN_REFERENCES={}
    return {'run_id':run_id,'folder':folder,'snapshot':snapshot,'completion':completion,'manifest':manifest,'rows':rows,'events':events,'source_checks':source_checks,'qualification':qualification,'circuits':circuits,'reference':reference}


def expected_deck(reference,circuit,netlist,kind):
    make=(reference._op_normal if kind=='normal' else reference._op_trigger) if circuit=='opamp' else (reference._and_normal if kind=='normal' else reference._and_trigger)
    return make(netlist,kind).replace('v(out)\nquit','v(out) v(x1.n31)\nquit')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-ids',nargs='+',default=list(DEFAULT_RUNS))
    parser.add_argument('--output',default='results/proposal_audit')
    args=parser.parse_args()
    if len(args.run_ids)!=len(set(args.run_ids)):raise SystemExit('Run identifiers must be distinct')
    # Check both runs completely before writing any audit files or starting ngspice.
    try:runs=[prepare_run(run_id) for run_id in args.run_ids]
    except (ValueError,KeyError,FileNotFoundError) as exc:raise SystemExit(str(exc)) from exc
    output=(ROOT/args.output).resolve()
    if any(output==run['folder'].resolve() or run['folder'].resolve() in output.parents for run in runs):raise SystemExit('Audit output must be separate from original run evidence')
    output.mkdir(parents=True,exist_ok=True)
    os.environ.setdefault('NGSPICE_BIN',str(ROOT/'.tools/ngspice/bin/ngspice'))
    helper=load_source(ROOT/'scripts/audit_simulations.py','proposal_uniform_waveform_audit_helper')
    independent_metrics=helper.independent_metrics;compare=helper.compare
    failures=[];event_checks=[];groups=defaultdict(list);clean_checks={}
    source_identity={canonical({k:v for k,v in r['manifest']['source_hashes'].items() if k in ('scripts/proposal/circuits.py','scripts/sim/benchmark.py','netlists/templates/opamp.cir','netlists/templates/and4.cir')}) for r in runs}
    if len(source_identity)!=1:raise SystemExit('Runs do not share the same frozen circuit implementation; audit them separately')
    # Each isolated module gets freshly simulated clean references in its own cache.
    for run in runs:
        c=run['circuits'];ref=run['reference'];clean_dir=output/'clean'/run['run_id']
        clean_checks[run['run_id']]={}
        for circuit in run['manifest']['config']['circuits']:
            n,t,_=c._simulate(circuit,c.render_clean(circuit),clean_dir/circuit)
            c._CLEAN_REFERENCES[circuit]=(n,t)
            metrics=ref._normal_metrics(circuit,n)
            if circuit=='opamp':
                a,_=ref._run(ref._op_ac(c.render_clean(circuit),'ac'),clean_dir/circuit,'ac')
                metrics.update(ref._ac_metrics(a))
            previous=run['qualification']['clean_results'][circuit]['metrics']
            result=compare(previous,metrics)
            clean_checks[run['run_id']][circuit]={'matches_qualification':result['matches'],'comparison':result,'fresh_metrics':metrics}
            if not result['matches']:failures.append(f'{run["run_id"]}/{circuit}: clean metrics mismatch')
        qualified={(r['circuit'],canonical(r['parameters'])):r for r in run['qualification']['records']}
        for candidate_id,row in sorted(run['events'].items()):
            base={'run_id':run['run_id'],'candidate_id':candidate_id,'circuit':row['circuit']}
            if not row.get('netlist_path'):
                ok=row['simulation']['valid'] is False and not row.get('success')
                event_checks.append({**base,'rendered':False,'honest_failure':ok,'passed':ok})
                if not ok:failures.append(candidate_id+': missing netlist marked successful')
                continue
            circuit=row['circuit'];netlist=c.render(circuit,row['parameters']);digest=text_sha(netlist)
            q=qualified.get((circuit,canonical(row['parameters'])))
            simdir=ROOT/'results/simulations'/candidate_id
            checks={'rendered_hash_matches_record':digest==row['netlist_sha256'],
                    'saved_netlist_matches_render':(ROOT/row['netlist_path']).read_text()==netlist,
                    'saved_simulation_netlist_matches_render':(simdir/'candidate.cir').read_text()==netlist,
                    'saved_validation_matches_record':read(simdir/'validation.json')==row['simulation'],
                    'normal_deck_matches_frozen_stimulus':(simdir/'normal.cir').read_text()==expected_deck(ref,circuit,netlist,'normal'),
                    'trigger_deck_matches_frozen_stimulus':(simdir/'trigger.cir').read_text()==expected_deck(ref,circuit,netlist,'trigger'),
                    'parameters_in_qualified_menu':q is not None,
                    'qualified_netlist_hash_matches':q is not None and q['netlist_sha256']==digest}
            comparison=compare(q['validation'],row['simulation']) if q is not None else {'matches':False,'mismatches':['unqualified parameters']}
            checks['saved_metrics_match_qualification']=comparison['matches']
            if row['simulation'].get('simulation_ok'):
                uniform=independent_metrics(circuit,simdir,clean_dir/circuit)
                uniform['valid']=bool(uniform['normal_ok'] and uniform['trigger_ok'])
                checks['uniform_normal_verdict_matches']=uniform['normal_ok']==row['simulation']['normal_ok']
                checks['uniform_trigger_verdict_matches']=uniform['trigger_ok']==row['simulation']['trigger_ok']
                checks['uniform_validity_matches']=uniform['valid']==row['simulation']['valid']
            else:
                uniform={'valid':False,'reason':'saved simulation failed'}
                checks['uniform_validity_matches']=False
            passed=all(checks.values())
            event_checks.append({**base,'rendered':True,'netlist_sha256':digest,'checks':checks,'qualification_comparison':comparison,'independent_uniform_time_metrics':uniform,'passed':passed})
            if not passed:failures.append(candidate_id+': '+', '.join(k for k,v in checks.items() if not v))
            groups[digest].append((run,row))
    fresh_records=[]
    for digest,instances in sorted(groups.items()):
        run,row=instances[0];circuit=row['circuit'];c=run['circuits']
        folder=output/'distinct_candidates'/digest[:16]
        result=c.validate(circuit,row['parameters'],folder)
        comparisons=[{'candidate_id':r['candidate_id'],'run_id':owner['run_id'],**compare(r['simulation'],result)} for owner,r in instances]
        uniform=independent_metrics(circuit,folder,output/'clean'/run['run_id']/circuit) if result['simulation_ok'] else {'valid':False}
        if result['simulation_ok']:uniform['valid']=bool(uniform['normal_ok'] and uniform['trigger_ok'])
        passed=bool(result['simulation_ok'] and all(x['matches'] for x in comparisons) and uniform['valid']==result['valid'])
        fresh_records.append({'netlist_sha256':digest,'circuit':circuit,'parameters':row['parameters'],'candidate_events':len(instances),'fresh_simulation':result,'comparisons':comparisons,'independent_uniform_time_metrics':uniform,'passed':passed})
        if not passed:failures.append(digest+': fresh simulation discrepancy')
    counts={r['run_id']:{'complete':True,'analysis_rows':len(r['rows']),'candidate_events':len(r['events']),'distinct_netlists':len({x['netlist_sha256'] for x in r['events'].values() if x.get('netlist_sha256')}),'valid_candidate_events':sum(x['simulation']['valid'] for x in r['events'].values())} for r in runs}
    audit={'complete':True,'passed':not failures,'time_local':datetime.now(ZoneInfo('Asia/Singapore')).isoformat(),'paid_api_calls':0,
           'run_counts':counts,'total_analysis_rows':sum(len(r['rows']) for r in runs),'total_candidate_events':sum(len(r['events']) for r in runs),
           'rendered_candidate_events_checked':sum(x['rendered'] for x in event_checks),'distinct_netlists_freshly_simulated':len(fresh_records),
           'all_saved_metrics_match_qualification':all(x['checks']['saved_metrics_match_qualification'] for x in event_checks if x['rendered']),
           'all_saved_uniform_time_verdicts_match':all(x['checks']['uniform_validity_matches'] for x in event_checks if x['rendered']),
           'all_fresh_simulations_match':all(x['passed'] for x in fresh_records),'frozen_source_checks':{r['run_id']:r['source_checks'] for r in runs},
           'clean_checks':clean_checks,'event_checks':event_checks,'fresh_netlist_checks':fresh_records,'failures':failures,
           'audit_script_sha256':sha(Path(__file__)),'scope':'Electrical reproduction under the declared nominal stimuli; not PVT, exhaustive functional equivalence, silicon validation, or additional statistical evidence from new API requests.'}
    (output/'audit.json').write_text(json.dumps(audit,indent=2))
    print(json.dumps({k:v for k,v in audit.items() if k not in ('frozen_source_checks','clean_checks','event_checks','fresh_netlist_checks')},indent=2))
    if failures:raise SystemExit(1)
if __name__=='__main__':main()
