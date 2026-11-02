"""Archive reproducible code and evidence, explicitly excluding credentials."""
from pathlib import Path
import hashlib
import json
import zipfile
from dotenv import dotenv_values

ROOT=Path(__file__).resolve().parents[1]

def main():
    active=json.loads((ROOT/'configs/proposal_experiment.json').read_text())
    required=['main_v2/completion.json', 'strong_attacker_v1/completion.json',
              'cross_review_v1/completion.json', 'evasion_recheck_v1/summary.json']
    required.extend(run+'/completion.json' for run in active['run_seeds'])
    defense_config=ROOT/'configs/defense_comparison.json'
    defense_run=json.loads(defense_config.read_text())['run_id'] if defense_config.exists() else None
    if defense_run:
        required.append(defense_run+'/completion.json')
    for evidence in required:
        completion=ROOT/'results'/evidence
        if not completion.exists() or not json.loads(completion.read_text()).get('complete'):
            raise RuntimeError('Required experiment is incomplete: '+evidence)
    if not (ROOT/'output/pdf/A2_Trojan_LLM_Informal_Report.pdf').exists():
        raise RuntimeError('Final report missing.')
    for run in active['run_seeds']:
        audit=ROOT/'results'/run/'independent_audit.json'
        if not audit.exists() or not json.loads(audit.read_text()).get('passed'):
            raise RuntimeError('Final protocol audit missing: '+run)
    simulation_audit=ROOT/'results/proposal_audit/audit.json'
    if not simulation_audit.exists() or not json.loads(simulation_audit.read_text()).get('passed'):
        raise RuntimeError('Final simulation audit missing.')
    delivery=ROOT/'results/proposal_completion.json'
    if not delivery.exists() or not json.loads(delivery.read_text()).get('complete'):
        raise RuntimeError('Final delivery checks have not passed.')
    if defense_run:
        defense_audit=ROOT/'results'/defense_run/'independent_audit.json'
        if not defense_audit.exists() or not json.loads(defense_audit.read_text()).get('passed'):
            raise RuntimeError('Supplementary detector audit missing.')
        if not json.loads(delivery.read_text()).get('checks',{}).get('supplementary_defense',{}).get('passed'):
            raise RuntimeError('Final delivery checks do not include the supplementary detector experiment.')
    report=ROOT/'output/pdf/A2_Trojan_LLM_Informal_Report'
    provenance=json.loads(report.with_suffix('.provenance.json').read_text())
    if defense_run:
        for name in ('analysis.json','independent_audit.json'):
            source='results/'+defense_run+'/'+name
            if provenance.get('analysis_sha256',{}).get(source)!=hashlib.sha256((ROOT/source).read_bytes()).hexdigest():
                raise RuntimeError('Report is not bound to the supplementary evidence: '+source)
    for suffix,field in [('.pdf','pdf_sha256'),('.txt','text_sha256')]:
        if hashlib.sha256(report.with_suffix(suffix).read_bytes()).hexdigest()!=provenance[field]:
            raise RuntimeError('Report differs from its verified provenance: '+suffix)
    deck=ROOT/'output/slides/a2_feedback/output.pptx'
    deck_provenance=deck.with_name('provenance.json')
    deck_meta=json.loads(deck_provenance.read_text())
    if hashlib.sha256(deck.read_bytes()).hexdigest()!=deck_meta['pptx_sha256']:
        raise RuntimeError('Presentation differs from its verified provenance.')
    selected=[ROOT/n for n in ['README.md','LICENSE','requirements.txt','.gitignore','.gitattributes','.env.example','output/阅读说明.txt']]
    selected.extend([deck,deck_provenance])
    for directory in ['scripts','tests','configs','docs','netlists','results','output/pdf']:
        selected.extend(p for p in (ROOT/directory).rglob('*') if p.is_file()
                        and '__pycache__' not in p.parts and 'node_modules' not in p.parts and p.suffix!='.pyc'
                        and p.name!='.api.lock')
    selected=sorted(set(selected))
    secret=(dotenv_values(ROOT/'.env').get('OPENAI_API_KEY') or '').encode()
    manifest={}
    for path in selected:
        body=path.read_bytes()
        if secret and secret in body:
            raise RuntimeError('Credential found in a selected file; packaging refused: '+str(path.relative_to(ROOT)))
        manifest[str(path.relative_to(ROOT))]={'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
    out=ROOT/'output';out.mkdir(exist_ok=True)
    destination=out/'A2_Trojan_LLM_Project.zip'
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for path in selected:
            archive.write(path,'A2_Trojan_LLM_Project/'+str(path.relative_to(ROOT)))
        archive.writestr('A2_Trojan_LLM_Project/FILE_MANIFEST.json',json.dumps(manifest,indent=2))
    checksum=hashlib.sha256(destination.read_bytes()).hexdigest()
    (out/'A2_Trojan_LLM_Project.sha256').write_text(checksum+'  '+destination.name+'\n')
    print(json.dumps({'archive':str(destination),'files':len(selected),'bytes':destination.stat().st_size,'sha256':checksum}))

def package_current():
    """Package only the active main experiment and its reproduction dependencies."""
    active=json.loads((ROOT/'configs/active_experiment.json').read_text())
    run_id=active['run_id']
    run=ROOT/'results'/run_id
    completed=json.loads((run/'completion.json').read_text())
    audit=json.loads((run/'audit.json').read_text())
    delivery=json.loads((ROOT/active['delivery_check']).read_text())
    report=ROOT/active['report']
    provenance=json.loads(report.with_suffix('.provenance.json').read_text())
    if not completed.get('complete') or not audit.get('passed') or not delivery.get('complete'):
        raise RuntimeError('Active experiment, audit, and delivery check must all be complete.')
    if delivery.get('run_id')!=run_id or delivery['audit_sha256']!=hashlib.sha256((run/'audit.json').read_bytes()).hexdigest():
        raise RuntimeError('Current delivery verification is stale.')
    if delivery['checker_sha256']!=hashlib.sha256((ROOT/'scripts/stopstudy_v6/check_delivery.py').read_bytes()).hexdigest():
        raise RuntimeError('Current delivery checker changed.')
    for suffix,field in [('.pdf','pdf_sha256'),('.txt','text_sha256')]:
        if hashlib.sha256(report.with_suffix(suffix).read_bytes()).hexdigest()!=provenance[field]:
            raise RuntimeError('Current report differs from its provenance.')
    for name,expected in provenance['source_sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=expected:
            raise RuntimeError('Report source evidence changed: '+name)
    deck=ROOT/'output/slides/a2_feedback/output.pptx'
    deck_provenance=deck.with_name('provenance.json')
    deck_meta=json.loads(deck_provenance.read_text())
    if deck_meta.get('run_id')!=run_id or hashlib.sha256(deck.read_bytes()).hexdigest()!=deck_meta['pptx_sha256']:
        raise RuntimeError('Presentation is stale or differs from its current evidence.')
    for name,expected in deck_meta['source_sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=expected:
            raise RuntimeError('Presentation source evidence changed: '+name)
    selected=[ROOT/name for name in ['README.md','LICENSE','requirements.txt','.gitignore','.gitattributes',
              '.env.example','output/阅读说明.txt','results/cost_ledger.json',active['delivery_check'],
              'docs/Stratified_Stop_On_Escape_Protocol_2026-11-02.txt','docs/Final_Report_Revision_Notes_2026-11-02.txt']]
    selected.extend(report.with_suffix(suffix) for suffix in ('.pdf','.txt','.provenance.json'))
    selected.extend([deck,deck_provenance])
    for directory in ['scripts','tests','configs','docs/inputs','netlists/templates',
                      'results/proposal_validation','results/'+run_id,'output/pdf/stop_report_figures']:
        selected.extend(p for p in (ROOT/directory).rglob('*') if p.is_file()
                        and '__pycache__' not in p.parts and p.suffix!='.pyc' and p.name!='.api.lock')
    selected.extend((ROOT/'results/api').glob(run_id+'_*.json'))
    selected=sorted(set(selected))
    secret=(dotenv_values(ROOT/'.env').get('OPENAI_API_KEY') or '').encode()
    manifest={}
    for path in selected:
        body=path.read_bytes()
        if secret and secret in body:
            raise RuntimeError('Credential found in selected file; packaging refused.')
        manifest[str(path.relative_to(ROOT))]={'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
    destination=ROOT/'output/A2_Trojan_LLM_Project.zip'
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for path in selected:
            archive.write(path,'A2_Trojan_LLM_Project/'+str(path.relative_to(ROOT)))
        archive.writestr('A2_Trojan_LLM_Project/FILE_MANIFEST.json',json.dumps(manifest,indent=2))
    checksum=hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix('.sha256').write_text(checksum+'  '+destination.name+'\n')
    print(json.dumps({'archive':str(destination),'active_run':run_id,'files':len(selected),
                      'bytes':destination.stat().st_size,'sha256':checksum,'historical_results_included':False}))


if __name__=='__main__':
    if (ROOT/'configs/active_experiment.json').exists():
        package_current()
    else:
        main()
