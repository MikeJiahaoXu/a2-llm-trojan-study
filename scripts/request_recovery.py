"""One logged transport recovery, with both potential charges budgeted.

No retry for HTTP rejections or unusable model output. The second call uses a
different audit ID, keeps the first reservation, and is visible in the ledger.
"""
import json
from pathlib import Path
from scripts.llm_client import json_call as single_call, APIRequestError, APIOutputError

def json_call(*args, **kwargs):
    try:
        return single_call(*args, **kwargs)
    except APIOutputError:
        raise
    except APIRequestError:
        root = Path(__file__).resolve().parents[1]
        ledger = json.loads((root / 'results/cost_ledger.json').read_text())
        call_id = kwargs['call_id']
        if ledger.get('calls', {}).get(call_id, {}).get('status') != 'uncertain':
            raise
        retry_id = call_id + '_transport_retry1'
        print('Transport recovery: ' + retry_id + ' (original budget reservation retained)', flush=True)
        kwargs = dict(kwargs, call_id=retry_id)
        return single_call(*args, **kwargs)
