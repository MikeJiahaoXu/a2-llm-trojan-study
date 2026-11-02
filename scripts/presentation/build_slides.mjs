import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { Presentation, PresentationFile } from '@oai/artifact-tool';

process.on('uncaughtException', error => {
 console.error(error.message);
 console.error(error.stack?.split('\n').slice(1,6).join('\n'));
 process.exit(1);
});

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUT = path.join(ROOT, 'output/slides/a2_feedback');
const SCRATCH = path.join(ROOT, 'tmp/slides/a2_feedback');
const PREVIEW = path.join(SCRATCH, 'preview');
const W = 1280, H = 720;
const C = { ink:'#20354A', teal:'#2A7F87', grey:'#59656F', pale:'#EEF4F4', rule:'#DCE3E7', white:'#FFFFFF', warm:'#86613E' };
const FONT = 'Arial';
const records = [];
const read = async p => JSON.parse(await fs.readFile(path.join(ROOT,p),'utf8'));
const config = await read('configs/proposal_experiment.json');
const runIDs = Object.keys(config.run_seeds);
const runs = await Promise.all(runIDs.map(r=>read(`results/${r}/attempts.json`)));
const diagnostic = await read('results/proposal_analysis/and_diagnostics.json');
if(config.model !== 'gpt-4o-mini-2024-07-18') throw new Error('Unexpected model.');
const count=(c,f,i)=>runs[i].filter(r=>r.circuit===c&&r.feedback===f&&r.success).length;
const conditions=['none','binary','full'];
const counts = Object.fromEntries(['opamp','and4'].map(c=>[c,runs.map((_,i)=>conditions.map(f=>count(c,f,i)))]));
if(JSON.stringify(counts)!==JSON.stringify({opamp:[[0,5,6],[0,8,7]],and4:[[4,6,5],[6,3,1]]})) throw new Error('Unexpected result counts.');
const andEvents=Object.values(Object.fromEntries(runs.flat().filter(r=>r.circuit==='and4').map(r=>[r.candidate_id,r])));
const common=andEvents.filter(r=>r.parameters.insertion_site==='output_shunt'&&r.parameters.representation==='mosfet'&&r.parameters.trigger_profile==='p2'&&r.parameters.strength==='medium');
const internal=andEvents.filter(r=>r.parameters.insertion_site==='nand_node_pullup');
if(common.length!==60||common.filter(r=>r.detector.is_trojan).length!==42||internal.length!==40||!internal.every(r=>r.detector.is_trojan)) throw new Error('AND diagnosis changed.');

const NOTES = [
`Imagine a circuit reviewer explaining why a suspicious modification looks malicious. That explanation could help an engineer fix the design, but it could also help an attacker revise it. Our question is whether more detailed detector feedback makes a functioning Trojan harder to detect. A2 provides the analog charge-accumulation idea. SPICED represents detection, and LATENT represents iterative insertion using feedback. We implemented a small version of that interaction on the two circuits in our proposal. We did not train a new model or reproduce either complete framework.`,
`The attacker chooses four fields: where to insert a branch, its device representation, the trigger profile, and its strength. Python turns these choices into a netlist while keeping the clean circuit core. An input-driven diode-capacitor network accumulates charge. Above a threshold, the added branch disturbs a node and changes the output. We qualified all 81 op-amp and 54 AND choices with ngspice before generation, then simulated every candidate again. The normal test must still pass, and the trigger must cause the specified disturbance. This is constrained selection and revision, not free-form circuit design.`,
`Both roles used the same GPT-4o-mini snapshot. The detector saw only the candidate netlist and nominal function, returning a verdict, confidence, suspicious nodes, and an explanation. None received a fresh task each time. Binary received its preceding parameters and only the Boolean verdict. Full received those parameters and the complete review. No attacker received simulator feedback. Each circuit and condition had two ten-attempt starts. We repeated that allocation with new seeds. The initial candidate and review were shared across conditions within each start; later calls were separate. None versus revision also changes candidate history, so binary versus full is the closer comparison of feedback detail.`,
`Each bar is successful attempts out of twenty. Success means electrically valid and not flagged by the detector. In none, binary, full order, the op-amp has zero, five, six in the first run, then zero, eight, seven in the repeat. For AND, the first run is four, six, five; the repeat is six, three, one. Full therefore does not consistently beat binary. Across both runs, 240 condition rows represent 224 actual candidate events and 29 distinct netlists. All passed the electrical checks. That validity comes from the qualified menu, rather than unrestricted model design ability.`,
`The AND records give us two concrete observations. Both no-feedback groups repeatedly chose the same output-shunt MOSFET design. Across all actual reviews, that exact netlist was flagged 42 times out of 60. The netlist did not change, but the verdict did. Meanwhile, each binary and full group used the internal NAND-node insertion in ten of twenty attempts. All forty such candidates were flagged. The revision groups changed their search, but the chosen alternatives were not reliably better. These observations make reviewer variability and limited search plausible explanations. We did not vary circuit complexity, so we cannot conclude that the benchmarks were simply too easy.`,
`One control limitation matters. Each clean design received zero flags out of five in both runs. Known positives were flagged four times initially, but only three times in the repeat, failing our four-of-five gate. A continuation exception was documented before repeat attacks. We kept the settings and results unchanged, so the repeat checks stability but weakens confirmation. Our conclusion is that full explanations had no consistent advantage over binary feedback in this bounded setup. We cannot infer improvement across model generations. LATENT also measures component-localization evasion, whereas we require a negative verdict on the whole candidate, so its percentages are not direct targets.`
];
const DURATIONS=[40,50,60,55,55,40];
const SOURCES=[
 'Proposal: docs/inputs/AmberT_JiahaoX_SecurityProposal.pdf. A2: Yang et al., IEEE S&P 2016, doi:10.1109/SP.2016.10. SPICED: Chaudhuri et al., arXiv:2408.16018. LATENT: Chaudhuri et al., arXiv:2505.06364.',
 'scripts/proposal/circuits.py; results/proposal_validation/qualification_summary.json; results/proposal_audit/audit.json.',
 'configs/proposal_experiment.json; configs/proposal_prompts/; scripts/proposal/prompts.py; results/proposal_main_v3/independent_audit.json.',
 'results/proposal_main_v3/attempts.json; results/proposal_repeat_v3/attempts.json. Counts include the shared initial candidate in each condition, as declared; rounds are not independent samples.',
 'results/proposal_analysis/and_diagnostics.json. Shared starts are deduplicated for the 60 and 40 actual-review counts. Internal-site allocation is equal in binary/full, not greater in full. Observational diagnosis, not a randomized comparison of insertion sites.',
 'results/proposal_main_v3/controls.json; results/proposal_repeat_v3/controls.json; results/proposal_repeat_v3/control_gate_deviation.json. Full paper references are on slide 1 notes and in the report.'
];

function shape(s,geom,x,y,w,h,fill=C.white,stroke=fill,width=0){
 return s.shapes.add({geometry:geom,position:{left:x,top:y,width:w,height:h},fill,line:{fill:stroke,width,style:'solid'}});
}
function text(s,n,role,value,x,y,w,h,size=26,color=C.ink,bold=false,align='left'){
 const sh=shape(s,'rect',x,y,w,h,'#FFFFFF00');
 sh.text=value; sh.text.fontSize=size; sh.text.typeface=FONT; sh.text.color=color;sh.text.bold=bold;
 sh.text.alignment=align;sh.text.verticalAlignment='top';sh.text.insets={left:0,right:0,top:0,bottom:0};
 records.push({kind:'textbox',slide:n,role,text:value,textChars:value.length,textLines:value.split('\n').length,bbox:[x,y,w,h]});
 return sh;
}
function line(s,x,y,w,color=C.rule){shape(s,'rect',x,y,w,2,color);}
function arrow(s,x,y,w=36,color=C.teal){shape(s,'rightArrow',x,y,w,18,color);}
function base(p,n,title,source){
 const s=p.slides.add();s.background.fill=C.white;
 text(s,n,'series','A2 TROJANS IN THE LLM ERA',64,32,950,22,16,C.grey,true);
 text(s,n,'title',title,64,83,1152,100,42,C.ink,true);
 line(s,64,657,1152);
 text(s,n,'source',source,64,675,1080,23,14,C.grey);
 text(s,n,'page',String(n),1172,674,44,24,16,C.grey,false,'right');
 s.speakerNotes.setText(`Target time: ${DURATIONS[n-1]} seconds.\n\n${NOTES[n-1]}\n\nSources (not spoken):\n${SOURCES[n-1]}`);
 return s;
}
function processBox(s,n,title,sub,x,y,w,h=96){
 shape(s,'rect',x,y,w,h,C.pale);
 text(s,n,'process-label',title,x+14,y+14,w-28,35,25,C.ink,true,'center');
 if(sub)text(s,n,'process-detail',sub,x+14,y+53,w-28,38,19,C.grey,false,'center');
}
function chartStyle(chart){
 chart.titleTextStyle.typeface=FONT;chart.titleTextStyle.fontSize=26;chart.titleTextStyle.fill=C.ink;
 chart.legend.textStyle.typeface=FONT;chart.legend.textStyle.fontSize=20;chart.legend.textStyle.fill=C.grey;
 chart.xAxis.textStyle.typeface=FONT;chart.xAxis.textStyle.fontSize=23;chart.xAxis.textStyle.fill=C.ink;
 chart.yAxis.textStyle.typeface=FONT;chart.yAxis.textStyle.fontSize=20;chart.yAxis.textStyle.fill=C.grey;
 chart.dataLabels.textStyle.typeface=FONT;chart.dataLabels.textStyle.fontSize=23;chart.dataLabels.textStyle.fill=C.ink;
 chart.xAxis.line.fill=C.rule;chart.xAxis.line.width=1;chart.xAxis.line.style='solid';
 chart.yAxis.line.fill='#FFFFFF00';chart.yAxis.line.width=0;
 chart.yAxis.majorGridlines.fill=C.rule;chart.yAxis.majorGridlines.width=1;
 chart.yAxis.min=0;chart.yAxis.max=10;chart.yAxis.majorUnit=2;
 chart.plotAreaFill=C.white;chart.hasLegend=true;chart.legend.position='bottom';
 chart.dataLabels.showValue=true;chart.dataLabels.position='outEnd';
 chart.barOptions.direction='column';chart.barOptions.grouping='clustered';chart.barOptions.gapWidth=95;
}

await fs.mkdir(PREVIEW,{recursive:true});await fs.mkdir(OUT,{recursive:true});
const p=Presentation.create({slideSize:{width:W,height:H}});

// 1: Question, scope, and the three research contributions.
{
 const s=base(p,1,"Can a detector's explanation\nhelp an attacker?",'Information Security course project | 2 November 2026');
 text(s,1,'question-detail','We test whether detailed feedback increases evasion\non two small, electrically verified circuits.',64,235,1120,84,30);
 const labels=[['A2 · 2016','Analog charge\naccumulation'],['SPICED · 2024','LLM detection\nand explanations'],['LATENT · 2025','Iterative insertion\nusing feedback']];
 labels.forEach(([a,b],i)=>{const x=64+i*396;line(s,x,368,360,C.teal);text(s,1,'paper',a,x,388,350,34,26,C.ink,true);text(s,1,'paper-role',b,x,433,350,85,27,C.grey);});
 text(s,1,'authors','Amber Tsao (cctsao)  ·  Jiahao Xu (e1583425)',64,576,1100,34,23,C.grey);
}
// 2: Concrete allowed edits and the physical validity test.
{
 const s=base(p,2,'What the attacker can change','Sources: circuit templates, qualification results and independent electrical audit');
 const fields=[['Insertion site','Output or internal node'],['Representation','Switch / conductance / MOS'],['Trigger profile','Charge and threshold settings'],['Strength','Low / medium / high']];
 fields.forEach(([a,b],i)=>{const x=64+i*292;line(s,x,189,270,C.teal);text(s,2,'field',a,x,210,270,35,25,C.ink,true);text(s,2,'field-detail',b,x,253,270,66,22,C.grey);});
 const stages=[['Input burst','Repeated input edges'],['Charge storage','Diode + capacitor'],['Threshold crossed','Conditional activation'],['Added branch','Output disturbance']];
 stages.forEach(([a,b],i)=>{const x=64+i*292;processBox(s,2,a,b,x,342,250);if(i<3)arrow(s,x+258,382,26);});
 text(s,2,'menu','81 op-amp choices + 54 AND choices; every choice verified before generation.',64,461,1152,36,25,C.ink,true);
 text(s,2,'validation-opamp','Op-amp: normal error ≤ 0.02 V; triggered output drop ≥ 0.3 V.',64,517,1150,36,25);
 text(s,2,'validation-and','AND: 16/16 truth-table cases; normal deviation ≤ 0.2 V; triggered drop ≥ 0.8 V.',64,563,1152,65,25);
}
// 3: Two distinct checks, and the exact information shown in each condition.
{
 const s=base(p,3,'Three feedback conditions','Both roles: gpt-4o-mini-2024-07-18, temperature 0.3 | No simulator feedback to attacker');
 processBox(s,3,'LLM attacker','Select four fields',64,186,244,86);arrow(s,319,218,34);
 processBox(s,3,'Python template','Render candidate netlist',367,186,244,86);arrow(s,622,218,34);
 processBox(s,3,'LLM reviewer','Netlist + nominal function',670,186,286,86);
 text(s,3,'validation-branch','ngspice checks:\nnormal operation +\ntriggered disturbance',974,187,242,86,22,C.grey);
 text(s,3,'feedback-caption','Information available for the next attempt',64,308,1148,36,25,C.ink,true);
 const rows=[['None','Fresh task each time; no previous candidate or review.'],['Binary','Previous parameters + only the Boolean verdict.'],['Full','Previous parameters + verdict, confidence, suspicious nodes and explanation.']];
 rows.forEach(([a,b],i)=>{const y=361+i*62;line(s,64,y-9,1152);text(s,3,'feedback-level',a,64,y,140,37,27,C.teal,true);text(s,3,'feedback-detail',b,235,y,975,52,25);});
 text(s,3,'allocation','2 starts × 10 attempts = 20 per group, in each of two executions.',64,565,1152,34,26,C.ink,true);
 text(s,3,'shared-start','First candidate + review shared across arms within each start; later calls are separate.',64,611,1152,30,21,C.grey);
}
// 4: Native editable result charts from the raw attempt rows.
{
 const s=base(p,4,'Results: no consistent increasing order','Source: both v3 attempt records. Shared starts and adaptive rounds are not independent samples.');
 text(s,4,'metric','Success = electrically valid AND not flagged. Each bar is out of 20 attempts.',64,166,1152,36,25,C.grey);
 text(s,4,'chart-heading','Op = two-stage op-amp; AND = four-input AND gate',64,219,1152,32,23,C.grey);
 const ch=s.charts.add('bar');ch.position={left:54,top:271,width:1172,height:305};
 ch.categories=['Op: None','Op: Binary','Op: Full','AND: None','AND: Binary','AND: Full'];chartStyle(ch);
 const allValues=[0,1].map(j=>[...counts.opamp[j],...counts.and4[j]]);
 allValues.forEach((values,j)=>{const ser=ch.series.add(j===0?'First run':'Repeat');ser.values=values;ser.categories=ch.categories;ser.fill=j===0?C.ink:C.teal;ser.stroke={fill:j===0?C.ink:C.teal,width:0,style:'solid'};});
 records.push({kind:'chart',slide:4,role:'both-circuits',categories:ch.categories,values:allValues,bbox:[54,271,1172,305]});
 text(s,4,'validity','240 valid analysis rows · 224 actual candidate events · 29 distinct netlists',64,599,1152,35,24,C.ink,true);
}
// 5: Evidence that distinguishes candidate changes from reviewer variability.
{
 const s=base(p,5,'AND: the same netlist gets different verdicts','Source: all recorded AND reviews; shared starts counted once for the 60 and 40 review totals.');
 text(s,5,'observation-left','Same output-shunt MOSFET netlist',64,181,550,65,28,C.ink,true);
 text(s,5,'same-netlist-count','42 / 60',64,258,550,85,68,C.teal,true);
 text(s,5,'same-netlist-label','reviews flagged it',64,350,550,36,27,C.ink);
 text(s,5,'same-netlist-detail','18 misses without changing the netlist.\nNone repeated this design in all 40 attempts.',64,409,550,100,25,C.grey);
 shape(s,'rect',626,182,2,344,C.rule);
 text(s,5,'observation-right','Internal NAND-node insertion',670,181,546,65,28,C.ink,true);
 text(s,5,'internal-count','40 / 40',670,258,546,85,68,C.teal,true);
 text(s,5,'internal-label','reviews flagged the candidate',670,350,546,36,27,C.ink);
 text(s,5,'internal-detail','Each binary and full group used this site\nin 10 of its 20 attempts.',670,409,546,100,25,C.grey);
 line(s,64,540,1152,C.teal);
 text(s,5,'inference','Revision groups explored different designs, without a reliable gain.\nAND has 54 allowed configurations; circuit complexity was not tested.',64,566,1152,70,27,C.ink);
}
// 6: Conclusion with the material control limitation, without overstating scope.
{
 const s=base(p,6,'More detail did not reliably improve evasion','References: A2 (2016); SPICED, arXiv:2408.16018; LATENT, arXiv:2505.06364 | Full citations in notes/report');
 text(s,6,'conclusion','Op-amp feedback groups had more escapes.\nFull explanations did not consistently outperform binary feedback.',64,176,1152,90,31,C.ink,true);
 line(s,64,297,1152);
 text(s,6,'control-heading','Control limitation',64,326,380,40,28,C.teal,true);
 text(s,6,'control-counts','Clean flags: 0/5 in both runs, for both circuits.\nKnown positives detected: 4/5 first run → 3/5 repeat.',64,380,1152,78,27);
 text(s,6,'gate-exception','Repeat fell below our 4/5 gate; a continuation exception was recorded\nbefore its attacks. This weakens confirmation of the first run.',64,476,1152,70,25,C.grey);
 text(s,6,'scope','We did not test larger circuits or newer model generations.\nLATENT’s component-localization metric differs from our whole-netlist verdict.',64,573,1152,65,23,C.grey);
}

for(const rec of records.filter(r=>r.bbox)){
 const [x,y,w,h]=rec.bbox;if(x<0||y<0||x+w>W+0.1||y+h>H+0.1)throw new Error(`Out of bounds: ${rec.role}`);
}
const logPath=path.join(SCRATCH,'render_verify_loops.ndjson');
let old='';try{old=await fs.readFile(logPath,'utf8');}catch{}
const loop=old.trim()?old.trim().split('\n').length+1:1;
if(loop>3)throw new Error('Maximum three render/verify loops reached.');
await fs.appendFile(logPath,JSON.stringify({loop,started_at:new Date().toISOString()})+'\n');
await fs.writeFile(path.join(SCRATCH,'inspect.ndjson'),records.map(x=>JSON.stringify(x)).join('\n')+'\n');
await fs.writeFile(path.join(SCRATCH,'speaker_notes.txt'),NOTES.map((n,i)=>`SLIDE ${i+1} — ${DURATIONS[i]} seconds\n${n}\n`).join('\n'));
for(let i=0;i<p.slides.count;i++){
 const blob=await p.export({slide:p.slides.getItem(i),format:'png',scale:1.3});
 await fs.writeFile(path.join(PREVIEW,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await blob.arrayBuffer()));
}
const dest=path.join(OUT,'output.pptx');const pptx=await PresentationFile.exportPptx(p);await pptx.save(dest);
const inputFiles=['configs/proposal_experiment.json',...runIDs.flatMap(r=>[`results/${r}/attempts.json`,`results/${r}/controls.json`]),'results/proposal_analysis/and_diagnostics.json','results/proposal_repeat_v3/control_gate_deviation.json'];
const hashes={};for(const f of inputFiles)hashes[f]=crypto.createHash('sha256').update(await fs.readFile(path.join(ROOT,f))).digest('hex');
const metadata={slides:6,planned_seconds:DURATIONS.reduce((a,b)=>a+b),spoken_words:NOTES.join(' ').split(/\s+/).length,model:config.model,counts,native_charts:1,source_sha256:hashes,pptx_sha256:crypto.createHash('sha256').update(await fs.readFile(dest)).digest('hex')};
await fs.writeFile(path.join(OUT,'provenance.json'),JSON.stringify(metadata,null,2)+'\n');
console.log(JSON.stringify({file:dest,slides:metadata.slides,seconds:metadata.planned_seconds,spoken_words:metadata.spoken_words,render_loop:loop}));
