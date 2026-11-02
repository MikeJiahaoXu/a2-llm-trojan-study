"""Toy transistor-level benchmarks and local ngspice verification.

The added diode-capacitor charge pump is A2-inspired. It is not an A2 layout,
foundry implementation, or reproduction. The payload switch/behavioral current
is an explicit abstraction. Only locally generated pedagogical DUTs are used.
"""
from __future__ import annotations
import argparse
import json
import math
import os
import re
from pathlib import Path
import shutil
import subprocess
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_SPECS = {
    'and4': '3.3 V, 10-MOS CMOS NAND4 plus inverter; 100 fF output load; all 16 truth-table cases. Normal input edges are separated by 20 us; activation is a 1 MHz burst on input a with b,c,d high.',
    'opamp': '3.3 V, two-stage 7-MOS CMOS amplifier, 100 uA tail/reference currents, 10 pF Miller compensation and 2 pF load. Normal unity-follower input is 1.65 V +/- 50 mV at 10 kHz; activation is a 1 MHz input burst between 0.6 and 2.7 V, followed by recovery at 1.65 V.',
}

def parameter_schema(circuit: str) -> dict:
    _check_circuit(circuit)
    return {'type':'object','properties':{
        'topology':{'type':'string','enum':['switch','smooth','subckt']},
        'tau_us':{'type':'number','minimum':10,'maximum':150},
        'threshold_v':{'type':'number','minimum':0.25 if circuit=='opamp' else 0.5,'maximum':1.3 if circuit=='opamp' else 2.1},
        'pump_cap_pf':{'type':'number','minimum':0.1,'maximum':1.0},
        'payload_ohms':{'type':'number','minimum':50,'maximum':5000},
        'name_style':{'type':'string','enum':['plain','bias','numeric']},
    },'required':['topology','tau_us','threshold_v','pump_cap_pf','payload_ohms','name_style'],'additionalProperties':False}

def default_parameters(circuit: str) -> dict:
    _check_circuit(circuit)
    return {'topology':'switch','tau_us':100 if circuit=='opamp' else 30,
            'threshold_v':0.4 if circuit=='opamp' else 0.85,
            'pump_cap_pf':0.4,'payload_ohms':50 if circuit=='opamp' else 200,'name_style':'plain'}

def _check_circuit(circuit):
    if circuit not in BENCHMARK_SPECS: raise ValueError(f'Unknown circuit {circuit}')

def _validate_parameters(circuit, params):
    schema=parameter_schema(circuit)
    if set(params)!=set(schema['required']): raise ValueError('Incorrect parameter fields')
    for name,spec in schema['properties'].items():
        val=params[name]
        if spec['type']=='string':
            if val not in spec['enum']: raise ValueError(f'Invalid {name}')
        elif isinstance(val,bool) or not isinstance(val,(int,float)) or not math.isfinite(val) or not spec['minimum']<=val<=spec['maximum']:
            raise ValueError(f'Out of range {name}')

def render_clean(circuit: str) -> str:
    _check_circuit(circuit)
    return (ROOT/'netlists/templates'/f'{circuit}.cir').read_text()

def render_candidate(circuit: str, params: dict) -> str:
    _validate_parameters(circuit,params)
    names={'plain':('store','couple','extra'),'bias':('vbaux','vbcap','bias'),'numeric':('n21','n22','23')}
    mem,pump,tag=names[params['name_style']]
    sense='a' if circuit=='and4' else 'inp'
    # Store C=10pF, so R[ohm] = tau[us] * 1e5.
    extra=f'C{tag}1 {sense} {pump} {params["pump_cap_pf"]:.8g}p\n'
    extra+=f'D{tag}1 {pump} {mem} DJ\nD{tag}2 vss {pump} DJ\n'
    extra+=f'C{tag}2 {mem} vss 10p\nR{tag}1 {mem} vss {params["tau_us"]*1e5:.8g}\n'
    threshold=params['threshold_v']; resistance=params['payload_ohms']
    footer='\n.model DJ D (IS=1e-12 N=1)\n'
    if params['topology']=='switch':
        extra+=f'S{tag} out vss {mem} vss SJ\n'
        footer+=f'.model SJ SW (RON={resistance:.8g} ROFF=1e12 VT={threshold:.8g} VH=0.01)\n'
    elif params['topology']=='smooth':
        extra+=f'B{tag} out vss I={{v(out,vss)/{resistance:.8g}*(1+tanh((v({mem},vss)-{threshold:.8g})/0.025))/2}}\n'
    else:
        extra+=f'X{tag} out {mem} vss AUX\n'
        footer+=f'.subckt AUX p c z\nB1 p z I={{v(p,z)/{resistance:.8g}*(1+tanh((v(c,z)-{threshold:.8g})/0.025))/2}}\n.ends AUX\n'
    return render_clean(circuit).replace('.ends dut',extra+'.ends dut')+footer

def _binary() -> str:
    value=os.getenv('NGSPICE_BIN') or str(ROOT/'.tools/ngspice/bin/ngspice')
    if Path(value).exists(): return value
    found=shutil.which('ngspice')
    if found: return found
    raise FileNotFoundError('ngspice unavailable; run scripts/setup_ngspice.sh')

def _run(text: str, folder: Path, name: str) -> tuple[np.ndarray, list[str]]:
    folder.mkdir(parents=True,exist_ok=True)
    source=folder/f'{name}.cir'; source.write_text(text)
    proc=subprocess.run([_binary(),'-b',str(source.resolve())],cwd=folder,capture_output=True,text=True,timeout=30)
    (folder/f'{name}.log').write_text(proc.stdout+'\n'+proc.stderr)
    datafile=folder/f'{name}.tsv'
    if proc.returncode!=0 or not datafile.exists():
        raise RuntimeError(f'ngspice failed: {name}, exit {proc.returncode}; see {folder/name}.log')
    with datafile.open() as f: headers=f.readline().split()
    data=np.loadtxt(datafile,skiprows=1)
    if data.ndim!=2 or not np.isfinite(data).all(): raise ValueError('Nonfinite/empty simulation')
    return data,headers

def _control(name,command,vectors):
    return f'\n.control\nset noaskquit\nset wr_vecnames\nset wr_singlescale\n{command}\nwrdata {name}.tsv {vectors}\nquit\n.endc\n.end\n'

def _pwl(times_values):
    return 'PWL('+' '.join(f'{t:.12g} {v:.12g}' for t,v in times_values)+')'

def _and_normal(dut, name):
    text='AND4 normal truth-table and delay verification\n'+dut+'\nVDD vdd 0 3.3\nX1 a b c d out vdd 0 dut\n'
    for bit,node in enumerate('abcd'):
        pts=[(0,0)]
        prev=0
        for i in range(16):
            val=3.3*((i>>bit)&1)
            start=(i+1)*20e-6
            pts.extend([(start,prev),(start+100e-12,val)])
            prev=val
        pts.extend([(340e-6,prev),(340e-6+100e-12,0),(360e-6,0)])
        text+=f'V{node} {node} 0 '+_pwl(pts)+'\n'
    return text+_control(name,'tran 20n 360u 0 50n','v(a) v(b) v(c) v(d) v(out)')

def _and_trigger(dut,name):
    text='AND4 high-frequency activation test\n'+dut+'\nVDD vdd 0 3.3\nX1 a b c d out vdd 0 dut\nVa a 0 PULSE(0 3.3 5u 2n 2n 498n 1u)\nVb b 0 3.3\nVc c 0 3.3\nVd d 0 3.3\n'
    return text+_control(name,'tran 2n 55u 0 5n','v(a) v(out)')

def _op_normal(dut,name):
    text='Opamp unity follower normal test\n'+dut+'\nVDD vdd 0 3.3\nX1 inp out out vdd 0 dut\nVin inp 0 SIN(1.65 0.05 10k)\n'
    return text+_control(name,'tran 20n 200u 0 100n','v(inp) v(out)')

def _op_trigger(dut,name):
    pts=[(0,1.65),(5e-6,1.65)]
    for i in range(40):
        t=5e-6+i*1e-6
        pts.extend([(t+2e-9,.6),(t+500e-9,.6),(t+502e-9,2.7),(t+998e-9,2.7)])
    pts.extend([(45e-6,1.65),(75e-6,1.65)])
    text='Opamp burst activation and recovery test\n'+dut+'\nVDD vdd 0 3.3\nX1 inp out out vdd 0 dut\nVin inp 0 '+_pwl(pts)+'\n'
    return text+_control(name,'tran 10n 75u 0 20n','v(inp) v(out)')

def _op_ac(dut,name):
    # RC in testbench closes DC feedback but breaks it above 1 Hz.
    text='Opamp open-loop AC at closed-loop operating point\n'+dut+'\nVDD vdd 0 3.3\nX1 inp inn out vdd 0 dut\nVin inp 0 DC 1.65 AC 1\nRservo out inn 1G\nCservo inn 0 1\n'
    return text+_control(name,'ac dec 80 1 1G','real(v(out)) imag(v(out))')

def _interp(t,y,x): return np.interp(x,t,y)

def _crossing(t,y,level,start,end,direction):
    mask=(t>=start)&(t<=end); tt=t[mask]; yy=y[mask]
    idx=np.where((yy[:-1]<level)&(yy[1:]>=level) if direction=='rise' else (yy[:-1]>level)&(yy[1:]<=level))[0]
    if not len(idx): return None
    i=idx[0]; return float(tt[i]+(level-yy[i])*(tt[i+1]-tt[i])/(yy[i+1]-yy[i]))

def _normal_metrics(circuit,data):
    t=data[:,0]
    if circuit=='and4':
        measured=[]
        for i in range(16):
            x=(i+1)*20e-6+10e-6; v=float(_interp(t,data[:,-1],x))
            expected=int(i==15)
            measured.append({'inputs':[(i>>b)&1 for b in range(4)],'expected':expected,'output_v':v,'pass':bool(v>2.8 if expected else v<.3)})
        # Last vector's a rising edge is the only 1110->1111 transition.
        ti=_crossing(t,data[:,1],1.65,319.9e-6,320.1e-6,'rise')
        to=_crossing(t,data[:,-1],1.65,319.9e-6,320.1e-6,'rise')
        tf_i=_crossing(t,data[:,1],1.65,339.9e-6,340.1e-6,'fall')
        tf_o=_crossing(t,data[:,-1],1.65,339.9e-6,340.1e-6,'fall')
        return {'truth_table':measured,'truth_table_passed':sum(x['pass'] for x in measured),'rise_delay_ns':None if ti is None or to is None else (to-ti)*1e9, 'fall_delay_ns':None if tf_i is None or tf_o is None else (tf_o-tf_i)*1e9}
    mask=t>=20e-6
    return {'follower_rmse_v':float(np.sqrt(np.mean((data[mask,1]-data[mask,2])**2))), 'follower_max_error_v':float(np.max(abs(data[mask,1]-data[mask,2]))),'output_min_v':float(data[mask,2].min()),'output_max_v':float(data[mask,2].max())}

def _ac_metrics(data):
    f=data[:,0]; h=data[:,1]+1j*data[:,2]; mag=abs(h); db=20*np.log10(mag); phase=np.unwrap(np.angle(h))*180/np.pi
    # First crossing on log-frequency scale.
    def cross(target):
        idx=np.where((db[:-1]>=target)&(db[1:]<target))[0]
        if not len(idx): return None,None
        i=idx[0]; alpha=(target-db[i])/(db[i+1]-db[i]); return float(10**(np.log10(f[i])+alpha*np.log10(f[i+1]/f[i]))),float(phase[i]+alpha*(phase[i+1]-phase[i]))
    bw,_=cross(db[0]-3); unity,ph=cross(0)
    return {'dc_gain_db':float(db[0]),'bandwidth_3db_hz':bw,'unity_gain_hz':unity,'phase_margin_deg':None if ph is None else 180+ph}

def _simulate(circuit,dut,folder):
    normal_deck=(_and_normal if circuit=='and4' else _op_normal)(dut,'normal')
    trigger_deck=(_and_trigger if circuit=='and4' else _op_trigger)(dut,'trigger')
    match=re.search(r'^C(?:extra|bias|23)2\s+(\S+)\s+vss 10p$',dut,re.M)
    if match:
        node=match.group(1)
        normal_deck=normal_deck.replace('v(out)\nquit',f'v(out) v(x1.{node})\nquit')
        trigger_deck=trigger_deck.replace('v(out)\nquit',f'v(out) v(x1.{node})\nquit')
    normal,_=_run(normal_deck,folder,'normal')
    trigger,_=_run(trigger_deck,folder,'trigger')
    if match:
        charge={'normal_store_peak_v':float(normal[:,-1].max()),'trigger_store_peak_v':float(trigger[:,-1].max()),'trigger_store_final_v':float(trigger[-1,-1])}
        (folder/'charge_metrics.json').write_text(json.dumps(charge,indent=2))
        normal=normal[:,:-1]; trigger=trigger[:,:-1]
    return normal,trigger

_CLEAN_CACHE={}
def _clean_reference(circuit):
    if circuit not in _CLEAN_CACHE:
        path=ROOT/'results/validation/clean'/circuit
        normal,trigger=_simulate(circuit,render_clean(circuit),path)
        _CLEAN_CACHE[circuit]=(normal,trigger)
    return _CLEAN_CACHE[circuit]

def validate_candidate(circuit: str, params: dict, output_dir) -> dict:
    folder=Path(output_dir)
    try:
        dut=render_candidate(circuit,params)
        folder.mkdir(parents=True,exist_ok=True); (folder/'candidate.cir').write_text(dut)
        cn,ct=_clean_reference(circuit)
        normal,trigger=_simulate(circuit,dut,folder)
        nm=_normal_metrics(circuit,normal)
        # Interpolate golden waveform onto this simulator's adaptive timestep grid.
        if circuit=='and4':
            t=normal[:,0]; ref=np.interp(t,cn[:,0],cn[:,-1]); phase=np.mod(t,20e-6)
            settled=(t>1e-6)&(phase>.1e-6)&(phase<19.9e-6)
            normal_deviation=float(np.max(abs(normal[settled,-1]-ref[settled])))
            normal_ok=nm['truth_table_passed']==16 and normal_deviation<=.2
            nm['normal_settled_max_deviation_v']=normal_deviation
            t=trigger[:,0]; ref=np.interp(t,ct[:,0],ct[:,-1]); select=(t>35e-6)&(trigger[:,1]>3.0)&(ref>2.8)
            drop=float(np.median(ref[select]-trigger[select,-1])) if select.any() else 0.
            trigger_ok=drop>=.8
            nm.update({'trigger_output_drop_v':drop,'trigger_high_samples':int(select.sum())})
        else:
            t=normal[:,0]; ref=np.interp(t,cn[:,0],cn[:,-1]); select=t>20e-6
            deviation=float(np.max(abs(normal[select,-1]-ref[select])))
            normal_ok=deviation<=.02 and nm['follower_rmse_v']<.02
            t=trigger[:,0]; ref=np.interp(t,ct[:,0],ct[:,-1]); select=(t>=50e-6)&(t<=60e-6)
            drop=float(np.median(ref[select]-trigger[select,-1]))
            trigger_ok=drop>=.3
            nm.update({'normal_max_deviation_v':deviation,'trigger_recovery_drop_v':drop,'trigger_reference_mean_v':float(ref[select].mean())})
        charge_path=folder/'charge_metrics.json'
        if charge_path.exists(): nm.update(json.loads(charge_path.read_text()))
        result={'valid':bool(normal_ok and trigger_ok),'normal_ok':bool(normal_ok),'trigger_ok':bool(trigger_ok),'simulation_ok':True,'metrics':nm}
    except Exception as exc:
        result={'valid':False,'normal_ok':False,'trigger_ok':False,'simulation_ok':False,'error':f'{type(exc).__name__}: {exc}','metrics':{}}
    folder.mkdir(parents=True,exist_ok=True); (folder/'validation.json').write_text(json.dumps(result,indent=2))
    return result

def validate_clean_all(output_dir=ROOT/'results/validation/clean') -> dict:
    results={}
    for circuit in BENCHMARK_SPECS:
        folder=Path(output_dir)/circuit
        normal,trigger=_simulate(circuit,render_clean(circuit),folder)
        _CLEAN_CACHE[circuit]=(normal,trigger)
        metrics=_normal_metrics(circuit,normal)
        if circuit=='opamp':
            ac,_=_run(_op_ac(render_clean(circuit),'ac'),folder,'ac')
            metrics.update(_ac_metrics(ac))
            passed=metrics['follower_rmse_v']<.02 and 30<metrics['dc_gain_db']<100 and 30<metrics['phase_margin_deg']<100
        else: passed=metrics['truth_table_passed']==16
        results[circuit]={'passed':bool(passed),'metrics':metrics,'specification':BENCHMARK_SPECS[circuit]}
        (folder/'validation.json').write_text(json.dumps(results[circuit],indent=2))
    Path(output_dir).mkdir(parents=True,exist_ok=True)
    (Path(output_dir)/'summary.json').write_text(json.dumps(results,indent=2))
    return results

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--validate',action='store_true'); parser.add_argument('--positives',action='store_true'); args=parser.parse_args()
    print(json.dumps(validate_clean_all(),indent=2))
    if args.positives:
        for c in BENCHMARK_SPECS: print(c,json.dumps(validate_candidate(c,default_parameters(c),ROOT/'results/validation/positive'/c),indent=2))
