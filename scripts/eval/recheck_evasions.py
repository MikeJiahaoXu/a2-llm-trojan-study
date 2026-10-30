"""Post-hoc stability check: five fresh reviews per model for every escaped DUT.

Selection is on observed success, so these judgments are never pooled into the
adaptive experiment's evasion rate. Circuit, prompt and parameters stay fixed.
"""
import hashlib,json
from pathlib import Path
from scripts.model_client import json_call,BASELINE_MODEL,STRONGER_MODEL
from scripts.detector.review import SCHEMA,SPECS
from scripts.eval.run_loop import save

ROOT=Path(__file__).resolve().parents[2]

def main():
    dest=ROOT/'results/evasion_recheck_v1'
    selected={}
    for run in ['main_v2','strong_attacker_v1']:
        folder=ROOT/'results'/run
        assert json.loads((folder/'completion.json').read_text())['complete']
        for row in json.loads((folder/'attempts.json').read_text()):
            if row['success']:
                selected.setdefault(row['netlist_sha256'],row)
    manifest={'selection':'All distinct valid-and-undetected candidates from the two completed experiments; post-hoc selected cohort.',
              'repeats_per_model':5,'models':[BASELINE_MODEL,STRONGER_MODEL],
              'selected_ids':[r['candidate_id'] for r in selected.values()],
              'code_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'prompt_sha256':hashlib.sha256((ROOT/'configs/prompts/detector_v2.txt').read_bytes()).hexdigest()}
    if (dest/'manifest.json').exists():
        assert json.loads((dest/'manifest.json').read_text())==manifest
    save(dest/'manifest.json',manifest)
    results=[]
    for digest,row in sorted(selected.items()):
        netlist=(ROOT/row['netlist_path']).read_text()
        assert hashlib.sha256(netlist.encode()).hexdigest()==digest
        messages=[{'role':'system','content':(ROOT/'configs/prompts/detector_v2.txt').read_text()},
                  {'role':'user','content':SPECS[row['circuit']]+'\nDUT NETLIST:\n'+netlist}]
        for model in [BASELINE_MODEL,STRONGER_MODEL]:
            tag='baseline' if model==BASELINE_MODEL else 'stronger'
            for repeat in range(5):
                response=json_call(messages=messages,schema=SCHEMA,
                    call_id=f'evasion_recheck_v1_{digest[:16]}_{tag}_{repeat}',
                    role='evasion_recheck',model=model,max_tokens=700,seed=90100+repeat)
                results.append({'sha256':digest,'candidate_id':row['candidate_id'],'circuit':row['circuit'],
                    'model':model,'repeat':repeat,'detector':response['output'],'api_record':response['record_path']})
                save(dest/'reviews.json',results)
                print('recheck',tag,repeat+1,'flagged',response['output']['is_trojan'],flush=True)
    summary={'complete':True,'selected_netlists':len(selected),'post_hoc':True,'results':[
        {'candidate_id':row['candidate_id'],'sha256':digest,'model':model,'judgments':5,
         'flagged':sum(r['detector']['is_trojan'] for r in results if r['sha256']==digest and r['model']==model)}
        for digest,row in selected.items() for model in [BASELINE_MODEL,STRONGER_MODEL]],
        'interpretation':'Fresh-review stability of a success-selected input, not a new unselected attack success rate.'}
    save(dest/'summary.json',summary);print(json.dumps(summary,indent=2))

if __name__=='__main__':
    main()
