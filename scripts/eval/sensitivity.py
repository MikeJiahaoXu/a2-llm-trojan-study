"""Post-hoc payload-threshold sensitivity using saved simulations; no API calls."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-id',default='main_v2')
    args=parser.parse_args()
    folder=ROOT/'results'/args.run_id
    if not (folder/'completion.json').exists():
        raise RuntimeError('Complete the experiment before sensitivity analysis.')
    rows=json.loads((folder/'attempts.json').read_text())
    out=[]
    for circuit, thresholds, metric in [
        ('opamp',[.2,.3,.4],'trigger_recovery_drop_v'),
        ('and4',[.5,.8,1.0],'trigger_output_drop_v')]:
        for feedback in ['none','binary','full']:
            group=[r for r in rows if r['circuit']==circuit and r['feedback']==feedback]
            for threshold in thresholds:
                valid=[r for r in group if r['simulation'].get('normal_ok') is True
                       and r['simulation'].get('simulation_ok') is True
                       and r['simulation'].get('metrics',{}).get(metric,float('-inf'))>=threshold]
                success=sum((r.get('detector') or {}).get('is_trojan') is False for r in valid)
                out.append({'circuit':circuit,'feedback':feedback,'threshold_v':threshold,
                            'valid':len(valid),'attempts':len(group),'valid_undetected':success,
                            'primary_rate':success/len(group)})
    payload={'analysis':'post_hoc_sensitivity_not_primary',
             'method':'Only the minimum triggered output-drop threshold varies; saved normal-operation validity and detector verdicts are unchanged.',
             'groups':out}
    (folder/'threshold_sensitivity.json').write_text(json.dumps(payload,indent=2)+'\n')
    print(json.dumps(payload,indent=2))

if __name__=='__main__':
    main()
