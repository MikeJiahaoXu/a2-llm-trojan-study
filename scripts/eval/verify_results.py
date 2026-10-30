"""Audit completed primary rows against raw API and simulator artifacts."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

def read(path):
    return json.loads(path.read_text())

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--run-id',default='main_v2');args=parser.parse_args()
    folder=ROOT/'results'/args.run_id
    manifest=read(folder/'manifest.json');rows=read(folder/'attempts.json');complete=read(folder/'completion.json')
    config=manifest['config']
    expected=len(config['circuits'])*len(config['feedback_levels'])*config['trajectories']*config['rounds_per_trajectory']
    assert complete['complete'] and len(rows)==expected
    assert len({(r['circuit'],r['feedback'],r['trajectory'],r['round']) for r in rows})==expected
    for name,digest in manifest['source_hashes'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,name
    for name,digest in manifest['prompt_hashes'].items():
        assert hashlib.sha256((ROOT/'configs/prompts'/name).read_bytes()).hexdigest()==digest,name
    for row in rows:
        candidate=read(ROOT/'results/candidates'/(row['candidate_id']+'.json'))
        assert row['simulation']==candidate['simulation']
        assert row['success']==bool(row['simulation']['valid'] and (row.get('detector') or {}).get('is_trojan') is False)
        if row.get('netlist_path'):
            assert hashlib.sha256((ROOT/row['netlist_path']).read_bytes()).hexdigest()==row['netlist_sha256']
            assert read(ROOT/'results/simulations'/row['candidate_id']/'validation.json')==row['simulation']
        if row.get('attacker_record'):
            raw=read(ROOT/row['attacker_record'])
            assert raw['result']['output']==row['parameters']
            assert raw['result']['model']==config.get('attacker_model',config['model'])
            text=raw['request']['messages'][-1]['content']
            has_previous='PREVIOUS PARAMETERS:' in text
            assert has_previous==(row['round']>0 and row['feedback']!='none')
            if has_previous:
                prior=next(x for x in rows if (x['circuit'],x['feedback'],x['trajectory'],x['round'])==
                           (row['circuit'],row['feedback'],row['trajectory'],row['round']-1))
                previous_text=text.split('PREVIOUS PARAMETERS:\n',1)[1].split('\nREVIEWER FEEDBACK:',1)[0]
                assert json.loads(previous_text)==prior['parameters']
                feedback=json.loads(text.split('REVIEWER FEEDBACK:\n',1)[1])
                assert feedback==({'is_trojan':prior['detector']['is_trojan']} if row['feedback']=='binary' else prior['detector'])
        if row.get('detector_record'):
            raw=read(ROOT/row['detector_record'])
            assert raw['result']['output']==row['detector']
            assert raw['result']['model']==config.get('detector_model',config['model'])
            assert row['candidate_id'] not in json.dumps(raw['request']['messages'])
    for circuit in config['circuits']:
        for trajectory in range(config['trajectories']):
            initial=[r for r in rows if r['circuit']==circuit and r['trajectory']==trajectory and r['round']==0]
            assert len({r['candidate_id'] for r in initial})==1
    result={'passed':True,'attempt_rows':len(rows),'unique_candidates':len({r['candidate_id'] for r in rows}),
            'checks':['source and prompt freeze','complete balanced design','raw API parameters and verdicts',
                      'netlist hashes','saved simulation verdicts','success denominator',
                      'paired shared starts','actual feedback exposure and preceding-candidate identity']}
    (folder/'integrity_audit.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    main()
