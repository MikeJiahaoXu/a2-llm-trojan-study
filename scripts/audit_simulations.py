"""Read-only-of-originals audit: rerun frozen circuits and all distinct candidates.

No API access. All newly generated decks, logs and traces live in results/reaudit.
The original frozen simulator is imported without editing it. Its new in-memory
clean cache is populated from newly executed clean simulations. Independent
uniform-time waveform calculations cross-check the adaptive-step statistics.
"""
from __future__ import annotations
import argparse
import hashlib
import types
import json
import os
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import Counter
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'results/main_v2'
OUT=ROOT/'results/reaudit'
SNAPSHOT=RUN/'source_snapshot'

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2))
def floats(obj,path=''):
    if isinstance(obj,dict):
        return {k:v for key,value in obj.items() for k,v in floats(value,path+'/'+str(key)).items()}
    if isinstance(obj,list):
        return {k:v for i,value in enumerate(obj) for k,v in floats(value,path+'/'+str(i)).items()}
    return {path:obj}
def compare(a,b):
    aa,bb=floats(a),floats(b); mismatches=[];max_error=0.
    for key in sorted(set(aa)|set(bb)):
        x,y=aa.get(key),bb.get(key)
        if isinstance(x,(float,int)) and not isinstance(x,bool) and isinstance(y,(float,int)) and not isinstance(y,bool):
            error=abs(x-y);max_error=max(max_error,error)
            same=bool(np.isclose(x,y,rtol=1e-7,atol=1e-10))
        else: same=x==y
        if not same:mismatches.append({'field':key,'saved':x,'fresh':y})
    return {'matches':not mismatches,'max_absolute_numeric_difference':max_error,'mismatches':mismatches}
def interp(d,col,t):return np.interp(t,d[:,0],d[:,col])

def independent_metrics(circuit,folder,clean):
    n=np.loadtxt(folder/'normal.tsv',skiprows=1);a=np.loadtxt(folder/'trigger.tsv',skiprows=1)
    gn=np.loadtxt(clean/'normal.tsv',skiprows=1);ga=np.loadtxt(clean/'trigger.tsv',skiprows=1)
    if circuit=='and4':
        sample_t=(np.arange(16)+1)*20e-6+10e-6
        measured=interp(n,5,sample_t);inputs=np.array([interp(n,k,sample_t)>1.65 for k in range(1,5)]).T
        expected=inputs.all(axis=1)
        truth=bool(np.all(np.where(expected,measured>2.8,measured<.3)))
        input_vectors_correct=bool(np.array_equal(inputs,np.array([[(i>>b)&1 for b in range(4)] for i in range(16)],dtype=bool)))
        t=np.arange(1e-6,359.99e-6,10e-9);phase=np.mod(t,20e-6);t=t[(phase>.1e-6)&(phase<19.9e-6)]
        normal_dev=float(np.max(abs(interp(n,5,t)-interp(gn,5,t))))
        t=np.arange(35.002e-6,55e-6,2e-9);ref=interp(ga,2,t);mask=(interp(a,1,t)>3)&(ref>2.8)
        drop=float(np.median((ref-interp(a,2,t))[mask]))
        return {'input_vectors_correct':input_vectors_correct,'truth_table_pass':truth,'normal_max_deviation_v_uniform':normal_dev,'trigger_drop_v_uniform':drop,'normal_ok':truth and input_vectors_correct and normal_dev<=.2,'trigger_ok':drop>=.8}
    t=np.arange(20.01e-6,200e-6,100e-9)
    normal_dev=float(np.max(abs(interp(n,2,t)-interp(gn,2,t))))
    rmse=float(np.sqrt(np.mean((interp(n,2,t)-interp(n,1,t))**2)))
    t=np.arange(50e-6,60.00001e-6,10e-9);drop=float(np.median(interp(ga,2,t)-interp(a,2,t)))
    return {'normal_max_deviation_v_uniform':normal_dev,'follower_rmse_v_uniform':rmse,'trigger_drop_v_uniform':drop,'normal_ok':normal_dev<=.02 and rmse<.02,'trigger_ok':drop>=.3}

def clean_independent(folder):
    d=np.loadtxt(folder/'opamp/ac.tsv',skiprows=1)
    f=d[:,0];h=d[:,1]+1j*d[:,2];db=20*np.log10(abs(h));phase=np.unwrap(np.angle(h))*180/np.pi
    # Independently invert the magnitude trace at each first downward crossing.
    def at_level(level):
        idx=int(np.flatnonzero((db[:-1]>=level)&(db[1:]<level))[0]);fraction=(db[idx]-level)/(db[idx]-db[idx+1]);logf=(1-fraction)*np.log10(f[idx])+fraction*np.log10(f[idx+1]);p=(1-fraction)*phase[idx]+fraction*phase[idx+1]
        return float(10**logf),float(p)
    bw,_=at_level(db[0]-3);ugf,up=at_level(0)
    a=np.loadtxt(folder/'and4/normal.tsv',skiprows=1)
    def edge(column,start,direction):
        sel=(a[:,0]>start-1e-9)&(a[:,0]<start+5e-9);t=a[sel,0];v=a[sel,column]-1.65
        idx=np.flatnonzero((v[:-1]<0)&(v[1:]>=0) if direction==1 else (v[:-1]>0)&(v[1:]<=0))[0]
        return float(t[idx]-v[idx]*(t[idx+1]-t[idx])/(v[idx+1]-v[idx]))
    return {'opamp_dc_gain_approx_at_1hz_db':float(db[0]),'opamp_bandwidth_3db_hz':bw,'opamp_unity_gain_hz':ugf,'opamp_phase_margin_deg':180+up,'and4_0111_to_1111_rise_delay_ns':1e9*(edge(5,320e-6,1)-edge(1,320e-6,1)),'and4_all_inputs_fall_delay_ns':1e9*(edge(5,340e-6,-1)-edge(1,340e-6,-1))}

def diagnostic_ablations(m):
    """Post-hoc diagnostics only, kept separate from preregistered primary rows."""
    data=[]
    for circuit in ['and4','opamp']:
        params=m.default_parameters(circuit);dut=m.render_candidate(circuit,params);clean=m.render_clean(circuit)
        for freq in [25000.,1000000.]:
            for swing in ([3.3] if circuit=='and4' else [.1,2.1]):
                lo=0 if circuit=='and4' else 1.65-swing/2;hi=lo+swing
                period=1/freq;start=5e-6;stop=45e-6;end=75e-6
                # Fixed40us exposure window; frequencies thus alter edge count.
                pts=[(0,lo if circuit=='and4' else 1.65),(start,lo if circuit=='and4' else 1.65)]
                for k in range(int(round((stop-start)/period))):
                    t=start+k*period;pts.extend([(t+2e-9,lo),(t+period/2,lo),(t+period/2+2e-9,hi),(t+period-2e-9,hi)])
                pts.extend([(stop,hi if circuit=='and4' else 1.65),(end,hi if circuit=='and4' else 1.65)])
                name=f'{circuit}_{int(freq)}hz_{swing:g}vpp';folder=OUT/'ablations'/name
                runs=[]
                for label,body in [('clean',clean),('modified',dut)]:
                    deck='Post-hoc amplitude-frequency diagnostic\n'+body+'\nVDD vdd 0 3.3\n'
                    if circuit=='and4':deck+='X1 a b c d out vdd 0 dut\nVb b 0 3.3\nVc c 0 3.3\nVd d 0 3.3\nVa a 0 '+m._pwl(pts)+'\n'
                    else:deck+='X1 inp out out vdd 0 dut\nVin inp 0 '+m._pwl(pts)+'\n'
                    vec='v(out)'+(' v(x1.store)' if label=='modified' else '')
                    deck+=m._control(label,'tran 5n 75u 0 10n',vec)
                    arr,_=m._run(deck,folder,label);runs.append(arr)
                t=np.arange(50e-6,60e-6,10e-9);drop=float(np.median(interp(runs[0],1,t)-interp(runs[1],1,t)))
                data.append({'circuit':circuit,'frequency_hz':freq,'swing_vpp':swing,'exposure_us':40,'nominal_cycles':int(round(40e-6*freq)),'peak_reservoir_v':float(runs[1][:,-1].max()),'recovery_output_drop_v':drop,'parameters':params,'interpretation':'post-hoc diagnostic; not added to formal denominators'})
    # The original ANDfall toggles all four inputs; directly measure a-only fall withb,c,d high.
    body=m.render_clean('and4');deck='Single sensitized falling-edge diagnostic\n'+body+'\nVDD vdd 0 3.3\nX1 a b c d out vdd 0 dut\nVb b 0 3.3\nVc c 0 3.3\nVd d 0 3.3\nVa a 0 PWL(0 3.3 1u 3.3 1.0001u 0 2u 0)\n'+m._control('fall','tran 1p 2u 0 2n','v(a) v(out)')
    arr,_=m._run(deck,OUT/'ablations/and4_single_input_fall','fall')
    def falling(col):
        i=np.flatnonzero((arr[:-1,col]>1.65)&(arr[1:,col]<=1.65))[0]
        return float(arr[i,0]+(1.65-arr[i,col])*(arr[i+1,0]-arr[i,0])/(arr[i+1,col]-arr[i,col]))
    return {'stimulus_grid':data,'and4_single_sensitized_input_fall_delay_ns':(falling(2)-falling(1))*1e9}

def main():
    global RUN, OUT, SNAPSHOT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id',default='main_v2')
    parser.add_argument('--output',help='Separate output directory relative to repository root')
    parser.add_argument('--source-snapshot',help='Frozen source directory; simulation files must match the run manifest')
    parser.add_argument('--skip-ablations',action='store_true')
    args=parser.parse_args()
    RUN=ROOT/'results'/args.run_id
    OUT=ROOT/args.output if args.output else ROOT/'results/reaudit' if args.run_id=='main_v2' else ROOT/'results/reaudit'/args.run_id
    SNAPSHOT=ROOT/args.source_snapshot if args.source_snapshot else RUN/'source_snapshot'
    OUT.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((RUN/'manifest.json').read_text());rows=json.loads((RUN/'attempts.json').read_text())
    source_checks={rel:sha(SNAPSHOT/rel)==digest for rel,digest in manifest['source_hashes'].items() if (SNAPSHOT/rel).exists()}
    missing_sources=[rel for rel in manifest['source_hashes'] if not (SNAPSHOT/rel).exists()]
    required=['scripts/sim/benchmark.py','netlists/templates/opamp.cir','netlists/templates/and4.cir']
    if not all(source_checks.values()) or not all(source_checks.get(rel) for rel in required):raise RuntimeError('Frozen source integrity mismatch or missing simulator/template source')
    os.environ['NGSPICE_BIN']=str(ROOT/'.tools/ngspice/bin/ngspice')
    source_path=SNAPSHOT/'scripts/sim/benchmark.py'
    m=types.ModuleType('frozen_audit_benchmark');m.__file__=str(source_path)
    exec(compile(source_path.read_text(),str(source_path),'exec'),m.__dict__)
    # ROOT points to frozen snapshot for reading templates. Explicit destinations
    # and clean-cache population ensure original simulation outputs remain untouched.
    fresh_clean=m.validate_clean_all(OUT/'simulations/clean')
    previous_clean=json.loads((ROOT/'results/validation/clean/summary.json').read_text())
    clean_comparison=compare(previous_clean,fresh_clean)
    grouped={}
    for row in rows:grouped.setdefault(row['netlist_sha256'],[]).append(row)
    candidates=[]
    for digest,instances in sorted(grouped.items()):
        row=instances[0];c=row['circuit'];folder=OUT/'simulations/candidates'/digest[:16]
        rendered=m.render_candidate(c,row['parameters']);render_matches=hashlib.sha256(rendered.encode()).hexdigest()==digest
        stored_files_match=all(sha(ROOT/x['netlist_path'])==digest for x in instances)
        result=m.validate_candidate(c,row['parameters'],folder)
        comparisons=[compare(x['simulation'],result) for x in instances]
        independent=independent_metrics(c,folder,OUT/'simulations/clean'/c)
        independent['valid']=independent['normal_ok'] and independent['trigger_ok']
        candidates.append({'netlist_sha256':digest,'circuit':c,'parameters':row['parameters'],'formal_row_count':len(instances),'candidate_ids':sorted(set(x['candidate_id'] for x in instances)),'render_matches_saved_hash':render_matches,'all_stored_netlists_match_hash':stored_files_match,'fresh_simulation':result,'all_saved_metrics_match':all(x['matches'] for x in comparisons),'saved_metric_comparisons':comparisons,'independent_uniform_time_metrics':independent,'independent_verdict_agrees':independent['valid']==result['valid']})
    ablations=None if args.skip_ablations else diagnostic_ablations(m)
    findings=[
      {'severity':'scope_limitation','finding':f'The {len(candidates)} distinct candidates vary one fixed charge-pump/output-shunt family. Used representations: {sorted({x["parameters"]["topology"] for x in rows})}. Detection may therefore be recognition of a fixed family, not general A2 defense.'},
      {'severity':'causal_limitation','finding':'Original opamp normal/activation stimuli jointly change swing0.1Vpp→2.1Vpp, frequency10kHz→1MHz and waveform sine→square. Original results alone cannot attribute activation to frequency. New post-hoc amplitude-frequency ablations are separate diagnostics, not new formalfeedback trials.'},
      {'severity':'measurement_label','finding':'Original ANDfall delay measures simultaneous1111→0000. It is a valid stated transition delay, but not single-input sensitized propagation delay. The latter is measured separately in the audit.'},
      {'severity':'scope_limitation','finding':'Normal preservation covers the enumerated16input sequence or a small10kHz opamp sine. It is not exhaustive history/transition checking, startup/PVT, timing/power equivalence or a rarity estimate.'},
      {'severity':'model_limitation','finding':'Generic LEVEL1 MOS, ideal sources, ideal switches/behavioral shunts and no layout/silicon validation make this an A2-inspired functional abstraction, not transistor-realistic A2 insertion.'},
      {'severity':'statistical_limitation','finding':'Default statistics take medians/RMSE over adaptive simulator points, not uniformly in time. Independent uniform resampling checks whether this changes verdicts; primary frozen metrics remain unmodified.'},
      {'severity':'measurement_label','finding':'Reported DC gain is the open-loop magnitude at1Hz with a DC-closing AC-breaking testbench servo, a close low-frequency approximation rather than a literal DC transfer derivative.'},
    ]
    result={'audit_time_local':datetime.now(ZoneInfo('Asia/Singapore')).isoformat(),'run_id':args.run_id,'source':str(SNAPSHOT.relative_to(ROOT)),'source_files_not_present_in_selected_snapshot':missing_sources,'source_scope':'Simulation module and templates must match the requested run manifest; absent API orchestration sources are not used by this audit.','paid_api_calls':0,'original_files_modified':False,'frozen_source_hash_checks':source_checks,'formal_rows':len(rows),'distinct_netlists_rerun':len(candidates),'fresh_clean_results':fresh_clean,'clean_saved_comparison':clean_comparison,'independent_clean_metrics':clean_independent(OUT/'simulations/clean'),'all_netlist_hashes_match':all(x['render_matches_saved_hash'] and x['all_stored_netlists_match_hash'] for x in candidates),'all_saved_simulation_metrics_match':all(x['all_saved_metrics_match'] for x in candidates),'all_independent_verdicts_agree':all(x['independent_verdict_agrees'] for x in candidates),'valid_distinct_by_circuit':dict(Counter(x['circuit'] for x in candidates if x['fresh_simulation']['valid'])),'valid_analysis_rows_by_group':{f'{c}/{feedback}':sum(r['circuit']==c and r['feedback']==feedback and r['simulation']['valid'] for r in rows) for c in manifest['config']['circuits'] for feedback in manifest['config']['feedback_levels']},'candidates':candidates,'posthoc_diagnostics':ablations,'findings':findings}
    save(OUT/'simulation_audit.json',result)
    print(json.dumps({k:v for k,v in result.items() if k not in ['candidates','fresh_clean_results','findings']},indent=2))
if __name__=='__main__':main()
