"""Archive reproducible code and evidence, explicitly excluding credentials."""
from pathlib import Path
import hashlib
import json
import zipfile
from dotenv import dotenv_values

ROOT=Path(__file__).resolve().parents[1]

def main():
    for evidence in ['main_v2/completion.json', 'strong_attacker_v1/completion.json',
                     'cross_review_v1/completion.json', 'evasion_recheck_v1/summary.json']:
        completion=ROOT/'results'/evidence
        if not completion.exists() or not json.loads(completion.read_text()).get('complete'):
            raise RuntimeError('Required experiment is incomplete: '+evidence)
    if not (ROOT/'output/pdf/A2_Trojan_LLM_Informal_Report.pdf').exists():
        raise RuntimeError('Final report missing.')
    selected=[ROOT/n for n in ['README.md','LICENSE','requirements.txt','.gitignore','.gitattributes','.env.example','output/阅读说明.txt']]
    for directory in ['scripts','tests','configs','docs','netlists','results','output/pdf']:
        selected.extend(p for p in (ROOT/directory).rglob('*') if p.is_file()
                        and '__pycache__' not in p.parts and p.suffix!='.pyc'
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

if __name__=='__main__':
    main()
