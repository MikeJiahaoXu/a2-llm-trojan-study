"""Minimal explicit connectivity check for the supplementary model."""
from pathlib import Path
import sys,json
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.model_client import json_call,STRONGER_MODEL

if __name__=='__main__':
    result=json_call(messages=[{'role':'user','content':'Return the JSON object with ok true.'}],
        schema={'type':'object','properties':{'ok':{'type':'boolean'}},'required':['ok'],'additionalProperties':False},
        call_id='stronger_connectivity_v1',role='smoke',max_tokens=30,model=STRONGER_MODEL)
    print(json.dumps({k:result[k] for k in ['output','model','usage','cost_usd','reasoning_effort','seed_sent']},indent=2))
