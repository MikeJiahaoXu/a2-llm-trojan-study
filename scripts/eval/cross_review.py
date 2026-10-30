"""Retrospective stronger-reviewer comparison on every distinct frozen DUT."""
import hashlib
import json
from pathlib import Path
from scripts.detector.review import SPECS, SCHEMA
from scripts.model_client import json_call
from scripts.sim.benchmark import render_clean,render_candidate,default_parameters
from scripts.eval.run_loop import save

ROOT=Path(__file__).resolve().parents[2]

def review(circuit,netlist,call_id,model):
    messages=[{'role':'system','content':(ROOT/'configs/prompts/detector_v2.txt').read_text()},
              {'role':'user','content':SPECS[circuit]+'\nDUT NETLIST:\n'+netlist}]
    result=json_call(messages=messages,schema=SCHEMA,call_id=call_id,role='cross_reviewer',
                     max_tokens=700,model=model)
    assert result['model']==model
    assert isinstance(result['output']['is_trojan'],bool) and 0<=result['output']['confidence']<=1
    return result

def main():
    config=json.loads((ROOT/'configs/cross_review.json').read_text())
    run_id=config['run_id'];dest=ROOT/'results'/run_id;model=config['reviewer_model']
    representatives={};members={};source_hashes={}
    for run in config['source_runs']:
        folder=ROOT/'results'/run
        assert json.loads((folder/'completion.json').read_text())['complete']
        source_hashes[run]=hashlib.sha256((folder/'attempts.json').read_bytes()).hexdigest()
        for row in json.loads((folder/'attempts.json').read_text()):
            digest=row.get('netlist_sha256')
            if not digest:
                continue
            members.setdefault(digest,{})[row['candidate_id']]={'run':run,'id':row['candidate_id'],
               'valid':row['simulation']['valid'],'baseline_flag':(row.get('detector') or {}).get('is_trojan')}
            if digest not in representatives or row['candidate_id']<representatives[digest]['candidate_id']:
                representatives[digest]=row
    manifest={'config':config,'source_attempt_hashes':source_hashes,'unique_netlists':len(representatives),
              'code_hash':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'dependency_hashes':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in [
                  'scripts/model_client.py','scripts/llm_client.py','scripts/detector/review.py',
                  'scripts/sim/benchmark.py','netlists/templates/opamp.cir','netlists/templates/and4.cir']},
              'prompt_hash':hashlib.sha256((ROOT/'configs/prompts/detector_v2.txt').read_bytes()).hexdigest()}
    if (dest/'manifest.json').exists() and json.loads((dest/'manifest.json').read_text())!=manifest:
        raise RuntimeError('Cross-review input or protocol changed.')
    save(dest/'manifest.json',manifest)
    controls=[]
    for circuit in ['opamp','and4']:
        for label,netlist in [('clean',render_clean(circuit)),('positive',render_candidate(circuit,default_parameters(circuit)))]:
            for repeat in range(5):
                response=review(circuit,netlist,f'{run_id}_{circuit}_{label}_{repeat}',model)
                controls.append({'circuit':circuit,'label':label,'repeat':repeat,'detector':response['output'],'api_record':response['record_path']})
                save(dest/'controls.json',controls)
                print('cross control',circuit,label,repeat+1,flush=True)
    results=[]
    for digest,row in sorted(representatives.items()):
        assert all(m['valid']==row['simulation']['valid'] for m in members[digest].values())
        netlist=(ROOT/row['netlist_path']).read_text()
        assert hashlib.sha256(netlist.encode()).hexdigest()==digest
        response=review(row['circuit'],netlist,f'{run_id}_{digest[:24]}',model)
        result={'sha256':digest,'circuit':row['circuit'],'representative_id':row['candidate_id'],
                'valid':row['simulation']['valid'],'baseline_detector':row['detector'],
                'stronger_detector':response['output'],'api_record':response['record_path'],
                'members':list(members[digest].values())}
        results.append(result);save(dest/'reviews.json',results)
        print(f'cross candidate {len(results)}/{len(representatives)} flagged={response["output"]["is_trojan"]}',flush=True)
    summary={'complete':True,'reviewer_model':model,'unique_netlists':len(results),
             'valid_unique_netlists':sum(r['valid'] for r in results),
             'flagged':sum(r['stronger_detector']['is_trojan'] for r in results),
             'valid_undetected':sum(r['valid'] and not r['stronger_detector']['is_trojan'] for r in results),
             'verdict_disagreements':sum(r['baseline_detector']['is_trojan']!=r['stronger_detector']['is_trojan'] for r in results),
             'disagreement_denominator':'One lexicographically selected representative baseline judgment per distinct netlist, not all repeated judgments.',
             'controls':[{'circuit':c,'label':label,'flagged':sum(r['detector']['is_trojan'] for r in controls if r['circuit']==c and r['label']==label),'n':5} for c in ['opamp','and4'] for label in ['clean','positive']],
             'interpretation':config['interpretation']}
    save(dest/'summary.json',summary)
    save(dest/'completion.json',{'complete':True,'unique_netlists':len(results),'control_judgments':len(controls)})
    print(json.dumps(summary,indent=2))

if __name__=='__main__':
    main()
