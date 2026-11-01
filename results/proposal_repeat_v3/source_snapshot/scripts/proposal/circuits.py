"""Finite, electrically qualified A2-inspired edits of the original two DUTs.

Every option changes an actual insertion site, device representation, or electrical
value. The original DUT text remains unchanged; a new branch and charge-storage
network are inserted inside its subcircuit. Generic pedagogical device models and
ideal comparators remain explicit simulation abstractions, not A2 silicon.
"""
from __future__ import annotations
import itertools
import json
from pathlib import Path
import numpy as np
from scripts.sim import benchmark as reference

ROOT=Path(__file__).resolve().parents[2]
QUALIFICATION_PATH=ROOT/'results/proposal_validation/qualification_summary.json'
qualification_path=QUALIFICATION_PATH
CIRCUITS=('opamp','and4')
REPRESENTATIONS=('switch','conductance','mosfet')
STRENGTHS=('low','medium','high')
TRIGGERS={
    'opamp':{
        'p1':{'pump_cap_pf':0.4,'tau_us':100.,'threshold_v':0.4},
        'p2':{'pump_cap_pf':0.5,'tau_us':90.,'threshold_v':0.5},
        'p3':{'pump_cap_pf':0.35,'tau_us':120.,'threshold_v':0.55},
    },
    'and4':{
        'p1':{'pump_cap_pf':0.4,'tau_us':30.,'threshold_v':0.85},
        'p2':{'pump_cap_pf':0.5,'tau_us':40.,'threshold_v':1.0},
        'p3':{'pump_cap_pf':0.3,'tau_us':50.,'threshold_v':0.7},
    },
}
# Lists follow increasing physical loading strength: low, medium, high.
SITES={
    'opamp':{
        'output_shunt':{'node':'out','rail':'vss','polarity':'n','resistance_ohms':[100.,75.,50.],'mos_width_um':[40.,60.,80.],
                        'meaning':'Load the final output toward ground after activation.'},
        'gain_node_pullup':{'node':'n2','rail':'vdd','polarity':'p','resistance_ohms':[2000.,1000.,500.],'mos_width_um':[2.,4.,8.],
                           'meaning':'Pull up the first-stage gain node / PMOS output-stage gate, suppressing output sourcing.'},
        'mirror_node_pulldown':{'node':'n1','rail':'vss','polarity':'n','resistance_ohms':[1000.,500.,250.],'mos_width_um':[1.,2.,4.],
                               'meaning':'Pull down the PMOS mirror reference node, increasing first-stage pullup and suppressing output sourcing.'},
    },
    'and4':{
        'output_shunt':{'node':'out','rail':'vss','polarity':'n','resistance_ohms':[400.,250.,150.],'mos_width_um':[4.,8.,12.],
                        'meaning':'Load the AND output toward ground after activation.'},
        'nand_node_pullup':{'node':'n1','rail':'vdd','polarity':'p','resistance_ohms':[300.,200.,100.],'mos_width_um':[16.,24.,40.],
                            'meaning':'Pull up the internal NAND output / inverter input, suppressing the final AND output.'},
    },
}


def _check_circuit(circuit):
    if circuit not in CIRCUITS:raise ValueError(f'Unknown circuit {circuit!r}')


def schema(circuit):
    _check_circuit(circuit)
    properties={
        'insertion_site':{'type':'string','enum':list(SITES[circuit])},
        'representation':{'type':'string','enum':list(REPRESENTATIONS)},
        'trigger_profile':{'type':'string','enum':list(TRIGGERS[circuit])},
        'strength':{'type':'string','enum':list(STRENGTHS)},
    }
    return {'type':'object','properties':properties,'required':list(properties),'additionalProperties':False}


def _check_params(circuit,params):
    spec=schema(circuit)
    if not isinstance(params,dict) or set(params)!=set(spec['required']):raise ValueError('Exactly the four declared parameter fields are required')
    for key,field in spec['properties'].items():
        if not isinstance(params[key],str) or params[key] not in field['enum']:raise ValueError(f'Unsupported {key}: {params[key]!r}')


def resolved_parameters(circuit,params):
    _check_params(circuit,params)
    site=SITES[circuit][params['insertion_site']]
    index=STRENGTHS.index(params['strength'])
    return {**params,**TRIGGERS[circuit][params['trigger_profile']],
            'payload_node':site['node'],'payload_rail':site['rail'],'mos_polarity':site['polarity'],
            'payload_resistance_ohms':site['resistance_ohms'][index] if params['representation']!='mosfet' else None,
            'payload_mos_width_um':site['mos_width_um'][index] if params['representation']=='mosfet' else None,
            'payload_mos_length_um':1. if params['representation']=='mosfet' else None}


def render_clean(circuit):
    _check_circuit(circuit)
    return reference.render_clean(circuit)


def render(circuit,params):
    p=resolved_parameters(circuit,params)
    sense='inp' if circuit=='opamp' else 'a'
    # Neutral identifiers are identical across conditions; no attacker-written text.
    additions=(f'C31 {sense} n32 {p["pump_cap_pf"]:.8g}p\n'
               'D31 n32 n31 DJ31\nD32 vss n32 DJ31\n'
               f'C32 n31 vss 10p\nR31 n31 vss {p["tau_us"]*1e5:.8g}\n')
    footer='\n.model DJ31 D (IS=1e-12 N=1)\n'
    node,rail,threshold=p['payload_node'],p['payload_rail'],p['threshold_v']
    factor=f'(1+tanh((v(n31,vss)-{threshold:.8g})/0.025))/2'
    if p['representation']=='switch':
        additions+=f'S31 {node} {rail} n31 vss SJ31\n'
        footer+=f'.model SJ31 SW (RON={p["payload_resistance_ohms"]:.8g} ROFF=1e12 VT={threshold:.8g} VH=0.01)\n'
    elif p['representation']=='conductance':
        additions+=f'B31 {node} {rail} I={{v({node},{rail})/{p["payload_resistance_ohms"]:.8g}*({factor})}}\n'
    else:
        voltage=f'v(vdd,vss)*({factor})' if p['mos_polarity']=='n' else f'v(vdd,vss)*(1-({factor}))'
        model='NM' if p['mos_polarity']=='n' else 'PM'
        additions+=f'B31 n33 vss V={{{voltage}}}\nM31 {node} n33 {rail} {rail} {model} W={p["payload_mos_width_um"]:.8g}u L=1u\n'
    clean=render_clean(circuit)
    if clean.count('.ends dut')!=1:raise ValueError('Clean DUT insertion boundary is ambiguous')
    return clean.replace('.ends dut',additions+'.ends dut')+footer


def description(circuit):
    _check_circuit(circuit)
    numeric_menu={'trigger_profiles':TRIGGERS[circuit],'insertion_sites':SITES[circuit],
                  'strength_order':list(STRENGTHS),'representations':{
                      'switch':'A thresholded resistive branch; hysteresis is 10mV.',
                      'conductance':'A smooth state-dependent conductance, using tanh transition width25mV.',
                      'mosfet':'An added NMOS or PMOS branch using the existing DUT device model, driven by an ideal smooth comparator of reservoir voltage.'}}
    return (reference.BENCHMARK_SPECS[circuit]+'\n'
            'All modifications retain the clean core and add an input-driven diode/capacitor charge reservoir. '
            'The fixed reservoir is10pF; bleed resistance equals tau_us*100000 ohms. '
            'Choose only the explicit menu below; identifiers are fixed and neutral. '
            'The finite Cartesian menu is qualified offline using the original normal/activation criteria, and every generated candidate is re-simulated. '
            'This remains an A2-inspired abstraction, not arbitrary transistor synthesis.\n'
            +json.dumps(numeric_menu,sort_keys=True))


def default_parameters(circuit):
    _check_circuit(circuit)
    return {'insertion_site':'output_shunt','representation':'switch','trigger_profile':'p1','strength':'medium'}


def known_positive_examples(circuit):
    _check_circuit(circuit)
    return [{**default_parameters(circuit),'insertion_site':site} for site in SITES[circuit]]


def all_parameters(circuit):
    spec=schema(circuit)
    names=spec['required']
    return [dict(zip(names,values)) for values in itertools.product(*(spec['properties'][n]['enum'] for n in names))]


def protocol_files():
    paths=['scripts/proposal/circuits.py','scripts/proposal/qualify_circuits.py',
           'scripts/sim/benchmark.py','netlists/templates/opamp.cir','netlists/templates/and4.cir']
    if QUALIFICATION_PATH.exists():paths.append(str(QUALIFICATION_PATH.relative_to(ROOT)))
    return paths


def qualification_metadata():
    return json.loads(QUALIFICATION_PATH.read_text()) if QUALIFICATION_PATH.exists() else {'status':'pending','path':str(QUALIFICATION_PATH.relative_to(ROOT))}


def _simulate(circuit,dut,folder,candidate=False):
    folder=Path(folder)
    normal_deck=(reference._op_normal if circuit=='opamp' else reference._and_normal)(dut,'normal')
    trigger_deck=(reference._op_trigger if circuit=='opamp' else reference._and_trigger)(dut,'trigger')
    if candidate:
        normal_deck=normal_deck.replace('v(out)\nquit','v(out) v(x1.n31)\nquit')
        trigger_deck=trigger_deck.replace('v(out)\nquit','v(out) v(x1.n31)\nquit')
    n,_=reference._run(normal_deck,folder,'normal');t,_=reference._run(trigger_deck,folder,'trigger')
    charge={}
    if candidate:
        charge={'normal_store_peak_v':float(n[:,-1].max()),'trigger_store_peak_v':float(t[:,-1].max()),'trigger_store_final_v':float(t[-1,-1])}
        n=n[:,:-1];t=t[:,:-1]
    return n,t,charge


_CLEAN_REFERENCES={}
def clean_reference(circuit):
    _check_circuit(circuit)
    if circuit not in _CLEAN_REFERENCES:
        n,t,_=_simulate(circuit,render_clean(circuit),ROOT/'results/proposal_validation/clean'/circuit)
        _CLEAN_REFERENCES[circuit]=(n,t)
    return _CLEAN_REFERENCES[circuit]


def validate(circuit,params,output_dir):
    folder=Path(output_dir);folder.mkdir(parents=True,exist_ok=True)
    try:
        dut=render(circuit,params);(folder/'candidate.cir').write_text(dut)
        cn,ct=clean_reference(circuit)
        normal,trigger,charge=_simulate(circuit,dut,folder,candidate=True)
        metrics=reference._normal_metrics(circuit,normal)
        if circuit=='and4':
            t=normal[:,0];golden=np.interp(t,cn[:,0],cn[:,-1]);phase=np.mod(t,20e-6)
            sel=(t>1e-6)&(phase>.1e-6)&(phase<19.9e-6)
            normal_dev=float(np.max(abs(normal[sel,-1]-golden[sel])))
            normal_ok=metrics['truth_table_passed']==16 and normal_dev<=.2
            t=trigger[:,0];golden=np.interp(t,ct[:,0],ct[:,-1]);sel=(t>35e-6)&(trigger[:,1]>3)&(golden>2.8)
            drop=float(np.median(golden[sel]-trigger[sel,-1])) if sel.any() else 0.
            trigger_ok=drop>=.8
            metrics.update(normal_settled_max_deviation_v=normal_dev,trigger_output_drop_v=drop,trigger_high_samples=int(sel.sum()))
        else:
            t=normal[:,0];golden=np.interp(t,cn[:,0],cn[:,-1]);sel=t>20e-6
            normal_dev=float(np.max(abs(normal[sel,-1]-golden[sel])))
            normal_ok=normal_dev<=.02 and metrics['follower_rmse_v']<.02
            t=trigger[:,0];golden=np.interp(t,ct[:,0],ct[:,-1]);sel=(t>=50e-6)&(t<=60e-6)
            drop=float(np.median(golden[sel]-trigger[sel,-1]));trigger_ok=drop>=.3
            metrics.update(normal_max_deviation_v=normal_dev,trigger_recovery_drop_v=drop,trigger_reference_mean_v=float(golden[sel].mean()))
        metrics.update(charge)
        result={'valid':bool(normal_ok and trigger_ok),'normal_ok':bool(normal_ok),'trigger_ok':bool(trigger_ok),'simulation_ok':True,'metrics':metrics,'resolved_parameters':resolved_parameters(circuit,params)}
    except Exception as exc:
        result={'valid':False,'normal_ok':False,'trigger_ok':False,'simulation_ok':False,'metrics':{},'error':f'{type(exc).__name__}: {exc}'}
    (folder/'validation.json').write_text(json.dumps(result,indent=2))
    return result
