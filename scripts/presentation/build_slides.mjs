import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { Presentation, PresentationFile } from '@oai/artifact-tool';

process.on('uncaughtException', error => {
  console.error(error.message);
  console.error(error.stack?.split('\n').slice(1, 6).join('\n'));
  process.exit(1);
});
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const OUT = path.join(ROOT, 'output/slides/a2_feedback');
const SCRATCH = path.join(ROOT, 'tmp/slides/a2_feedback_v6');
const PREVIEW = path.join(SCRATCH, 'preview');
const W = 1280, H = 720;
const C = { ink:'#20354A', teal:'#2A7F87', grey:'#59656F', pale:'#EEF4F4', rule:'#DCE3E7', white:'#FFFFFF', warm:'#86613E' };
const FONT = 'Arial';
const records = [];
const read = async relative => JSON.parse(await fs.readFile(path.join(ROOT, relative), 'utf8'));
const hash = async relative => crypto.createHash('sha256').update(await fs.readFile(path.join(ROOT, relative))).digest('hex');
const require = (ok, message) => { if (!ok) throw new Error(message); };
const active = await read('configs/active_experiment.json');
require(active.run_id === 'proposal_stop_v6', 'Reconcile this deck with the active experiment before building.');
const RUN = `results/${active.run_id}`;
const config = await read(active.config);
const summary = await read(`${RUN}/summary.json`);
const attempts = await read(`${RUN}/attempts.json`);
const audit = await read(`${RUN}/audit.json`);
const completion = await read(`${RUN}/completion.json`);
const reportMeta = await read('output/pdf/A2_Trojan_LLM_Informal_Report.provenance.json');
const FIGURE = 'output/pdf/stop_report_figures/cumulative_escape.png';
require(summary.complete && audit.passed && completion.complete, 'Completed and audited evidence is required.');
require(reportMeta.run_id === active.run_id && await hash(active.report) === reportMeta.pdf_sha256, 'Report provenance is stale.');
for (const [name, expected] of Object.entries(reportMeta.source_sha256)) require(await hash(name) === expected, `Report source changed: ${name}`);
require(await hash(FIGURE) === reportMeta.figure_sha256[FIGURE], 'The figure must be the exact current report figure.');
require(config.attacker_temperature === 0.3 && config.detector_temperature === 0 && config.detector_seed === 410001, 'Model settings changed.');
require(config.sessions_per_condition === 10 && config.max_attempts === 10, 'Session definition changed.');
const conditions = ['none', 'binary', 'full'];
const group = (c, f) => summary.groups.find(g => g.circuit === c && g.feedback === f);
const counts = Object.fromEntries(['opamp', 'and4'].map(c => [c, conditions.map(f => group(c, f).escaped_sessions)]));
const initial = Object.fromEntries(['opamp', 'and4'].map(c => [c, group(c, 'none').first_attempt_escapes]));
const reachTen = (c, f) => group(c, f).cumulative_curve.find(p => p.escaped_sessions === 10)?.attempt;
const reach = Object.fromEntries(['opamp', 'and4'].map(c => [c, {binary:reachTen(c, 'binary'), full:reachTen(c, 'full')}]));
require(JSON.stringify(counts) === JSON.stringify({opamp:[6,10,10], and4:[4,10,10]}), 'Reassess narrative for new outcomes.');
const noFeedback = Object.fromEntries(['opamp', 'and4'].map(c => {
  const rows = attempts.filter(r => r.circuit === c && r.feedback === 'none' && r.attempt > 1);
  require(new Set(rows.map(r => r.netlist_sha256)).size === 1 && rows.every(r => r.detector.is_trojan), 'No-feedback diagnosis changed.');
  return [c, rows.length];
}));
const example = attempts.filter(r => r.circuit === 'and4' && r.feedback === 'full' && r.session === 2).sort((a,b) => a.attempt-b.attempt);
require(example.length === 3 && example.every(r => r.simulation.valid) && !example[0].success && !example[1].success && example[2].success, 'AND trajectory changed.');
require(JSON.stringify(example.map(r => [r.parameters.insertion_site, r.parameters.representation, r.parameters.trigger_profile, r.parameters.strength])) === JSON.stringify([
  ['nand_node_pullup','conductance','p2','high'], ['output_shunt','mosfet','p1','medium'], ['nand_node_pullup','switch','p2','high']
]), 'AND choices changed.');

const DURATIONS = [30, 40, 45, 45, 50, 45, 45];
const NOTES = [
  `Can a detector's explanation help an attacker? That is our specific question. A2 shows how accumulated activity can trigger a small malicious analog circuit. SPICED uses LLMs to detect suspicious modifications and explain them. LATENT uses detector feedback to revise inserted Trojans. We study a small version of that interaction: does feedback help find a working modification that escapes review? We hold the model fixed, rather than comparing newer model generations.`,
  `We use a two-stage op-amp and a four-input AND gate. Repeated input activity charges a reservoir; crossing a threshold enables a branch that disturbs the circuit. A valid Trojan must preserve normal operation and cause the required output drop when activated. We first qualified a menu of eighty-one op-amp and fifty-four AND configurations. The attacker selects an insertion site, device representation, trigger profile and strength. Python renders the circuit, and ngspice checks every candidate again. This is constrained search, not unrestricted circuit synthesis.`,
  `Each benchmark has ten different starting configurations, selected before any detector calls and covering the insertion sites and representations. For each start, None, Binary and Full share the first candidate and review. Attempt one is rendered by Python, so it is not an LLM generation result. From attempt two, each active condition requests its own LLM proposal. A session stops immediately when electrical checks pass and the detector says no Trojan; otherwise it ends at attempt ten. Four separate basic controls passed before the sessions. They are not included in success counts.`,
  `From attempt two, None receives a fresh task without the previous candidate. Binary receives its preceding configuration and the Boolean verdict. Full receives the configuration and the complete review, including the explanation. Only the preceding attempt is supplied, not the full history. Both roles use the same GPT-4o-mini snapshot. The attacker temperature is point three; the detector temperature is zero with a fixed seed. Each exact review is cached, so repeating a circuit cannot obtain a new verdict. The detector sees only the netlist and nominal function. Neither LLM receives simulation results.`,
  `These are the report's cumulative escape curves. The vertical axis counts sessions that have escaped by each attempt, out of ten. Successful sessions stop; flat tails do not represent extra calls. At attempt one, six op-amp starts and four AND starts already escape in every condition. None stays at those counts. Binary and Full both reach ten for both circuits. Full reaches ten by attempt five for the op-amp and attempt three for AND. Binary reaches ten by attempts six and seven. The final counts tie, while Full reaches them earlier in this run.`,
  `Only four op-amp starts and six AND starts per condition need revision. None's later proposals repeatedly choose one flagged design in each circuit, so fresh requests add no successes. This AND Full session shows an actual search path. First, an internal conductance branch is detected. Next, an output MOSFET is also detected. At attempt three, an internal switch branch escapes. All three candidates pass the electrical checks. The cached reviewer did not change its answer for a repeated netlist; the attacker selected a different candidate. This trajectory illustrates how feedback can guide the search.`,
  `Our conclusion is limited: feedback helped this bounded search, and Full reached the same final success total sooner than Binary. None versus feedback also changes whether the preceding candidate is available, so Binary versus Full is the closer comparison of review detail. These are paired searches on small finite menus against one fixed, netlist-only reviewer. The detector does not learn online. Fresh runs can obtain different initial judgments even at temperature zero. We therefore do not establish a general model advantage or whether LLMs are beneficial overall for hardware security.`
];
const QA = [
  '为什么不直接用 LATENT 的 94.4% 比？其指标是插入组件逃过定位；这里统计找到电气有效且整份网表被判正常的 session。SPICED 使用仿真日志等信息，我们的 detector 只有 netlist 和功能说明。本项目没有完整复现这三篇论文。',
  '电路真实性：3.3V 教学模型，含理想化器件，无版图、流片或工艺角验证。菜单全部预验证，所以157/157有效不能证明LLM自由设计能力。Op-amp正常最大误差≤20mV，恢复期输出压降≥0.3V；AND需16/16逻辑正确、正常偏差≤0.2V、触发压降≥0.8V。',
  'Session是什么？从一份指定起点开始的搜索路径。20个不同起点×3个条件=60条条件级session，不是60个独立电路。初始选择覆盖运放9种、AND6种位置×表示形式，再无放回补足10份。四个控制为两份干净电路、两份菜单外的已知木马，全对只说明基本检查通过。',
  '为何温度0还需要cache？API的seed和温度不保证跨调用完全确定；缓存只固定本次运行。新旧版本重叠请求曾得到不同首次判决，因此不能把跨版本结果差异全部归因于起点修正。Detector固定是为了比较攻击者获取不同信息的效果，不是在测检测器训练。',
  '最终None/Binary/Full：运放6/10、10/10、10/10；AND4/10、10/10、10/10。157实际事件=20预设+137LLM，197条分析记录多出的40条来自首轮三条件共享。44份不同正式网表各检测一次，另有4个控制；185次API响应全部有效。成功者中位数：运放三组均1，AND为1/2/2。中位数受首轮成功影响，不能据此说后续修改同速。',
  '真实路径为AND/Full/session2：nand_node_pullup/conductance/p2/high → output_shunt/mosfet/p1/medium → nand_node_pullup/switch/p2/high。只有比较首尾时，差别才仅为representation；中间还改过位置、触发参数和强度。None的36次运放、54次AND后续提案各自重复同一被抓网表。',
  '能否说Full显著优于Binary？不能。这里只描述这10个配对起点下更早达到相同最终成功数，没有总体显著性或跨模型比较。None与反馈还差上一候选历史；Binary/Full才更直接比较反馈详细程度。标题问LLM正负影响，但本项目只测其中一个机制：防御反馈也可能给攻击者线索。'
];
const SOURCES = [
  'Report introduction/discussion. A2: Yang et al., IEEE S&P 2016, doi:10.1109/SP.2016.10. SPICED: Chaudhuri et al., arXiv:2408.16018v1. LATENT: Chaudhuri et al., arXiv:2505.06364v1.',
  'Report p.2; scripts/proposal/circuits.py; results/proposal_validation/qualification_summary.json; V6 audit.',
  `${RUN}/design.json; ${RUN}/controls.json; ${RUN}/controls_gate.json; ${RUN}/completion.json; report pp.1–2.`,
  `${active.config}; configs/proposal_prompts/; scripts/proposal/prompts.py; report pp.1–2.`,
  `Exact report Figure 1: ${FIGURE}; ${RUN}/summary.json; ${RUN}/cumulative.csv; report p.3.`,
  `${RUN}/attempts.json; AND / Full / session 2, attempts 1–3; report p.4.`,
  `${RUN}/summary.json; report p.4. API cache mapping is fixed within the recorded run; fresh calls are not guaranteed to repeat it.`
];

function shape(s, geometry, x, y, width, height, fill=C.white, stroke=fill, lineWidth=0) {
  return s.shapes.add({geometry, position:{left:x,top:y,width,height}, fill, line:{fill:stroke,width:lineWidth,style:'solid'}});
}
function text(s, n, role, value, x, y, w, h, size=26, color=C.ink, bold=false, align='left') {
  const sh=shape(s,'rect',x,y,w,h,'#FFFFFF00');
  sh.text=value; sh.text.fontSize=size; sh.text.typeface=FONT; sh.text.color=color; sh.text.bold=bold;
  sh.text.alignment=align; sh.text.verticalAlignment='top'; sh.text.insets={left:0,right:0,top:0,bottom:0};
  records.push({kind:'textbox',slide:n,role,text:value,textChars:value.length,textLines:value.split('\n').length,bbox:[x,y,w,h]});
  return sh;
}
function line(s,x,y,w,color=C.rule) { shape(s,'rect',x,y,w,2,color); }
function arrow(s,x,y,w=30) { shape(s,'rightArrow',x,y,w,18,C.teal); }
function base(p,n,title,source) {
  const s=p.slides.add(); s.background.fill=C.white;
  text(s,n,'series','A2 TROJANS IN THE LLM ERA',64,32,1050,22,16,C.grey,true);
  text(s,n,'title',title,64,83,1152,100,42,C.ink,true);
  line(s,64,657,1152);
  text(s,n,'source',source,64,675,1080,23,14,C.grey);
  text(s,n,'page',String(n),1172,674,44,24,16,C.grey,false,'right');
  s.speakerNotes.setText(`Target time: ${DURATIONS[n-1]} seconds.\n\nENGLISH TALK SCRIPT\n${NOTES[n-1]}\n\n中文答辩提醒（不计入演讲时间）\n${QA[n-1]}\n\nSources (not spoken):\n${SOURCES[n-1]}`);
  return s;
}
function box(s,n,title,body,x,y,w,h=110) {
  shape(s,'rect',x,y,w,h,C.pale);
  text(s,n,'process-title',title,x+16,y+15,w-32,36,25,C.ink,true,'center');
  text(s,n,'process-body',body,x+16,y+59,w-32,h-64,22,C.grey,false,'center');
}

await fs.mkdir(PREVIEW,{recursive:true}); await fs.mkdir(OUT,{recursive:true});
const p=Presentation.create({slideSize:{width:W,height:H}});
{
  const s=base(p,1,"Can a detector's explanation\nhelp an attacker?",'Information Security course project | A2, SPICED and LATENT');
  text(s,1,'question-detail','Does feedback help find a working circuit modification\nthat escapes an LLM reviewer?',64,236,1152,85,30);
  const papers=[['A2 · 2016','Analog charge\naccumulation'],['SPICED · 2024','LLM detection\nand explanations'],['LATENT · 2025','Iterative insertion\nusing feedback']];
  papers.forEach(([title,body],i)=>{const x=64+i*396;line(s,x,368,360,C.teal);text(s,1,'paper',title,x,389,360,36,26,C.ink,true);text(s,1,'paper-role',body,x,436,360,82,27,C.grey);});
  text(s,1,'authors','Amber Tsao (cctsao)  ·  Jiahao Xu (e1583425)',64,576,1152,36,23,C.grey);
}
{
  const s=base(p,2,'A functioning Trojan must pass two checks','Sources: report p.2; qualified circuit menu; independent electrical audit');
  text(s,2,'benchmarks','Two-stage op-amp and four-input AND gate · 3.3 V educational models',64,181,1152,36,26,C.grey);
  const stages=[['Input activity','Repeated transitions'],['Charge storage','Diode + capacitor'],['Threshold','Conditional activation'],['Added branch','Output disturbance']];
  stages.forEach(([title,body],i)=>{const x=64+i*292;box(s,2,title,body,x,247,250,110);if(i<3)arrow(s,x+258,291,26);});
  text(s,2,'normal-heading','1  Preserve normal function',64,393,545,38,28,C.ink,true);
  text(s,2,'normal-check','Op-amp: error ≤ 20 mV\nAND: 16/16 logic cases; deviation ≤ 0.2 V',64,448,550,82,25);
  text(s,2,'trigger-heading','2  Cause a triggered disturbance',665,393,551,38,28,C.ink,true);
  text(s,2,'trigger-check','Op-amp: output drop ≥ 0.3 V\nAND: output drop ≥ 0.8 V',665,448,551,82,25);
  line(s,64,552,1152,C.teal);
  text(s,2,'menu','81 op-amp choices + 54 AND choices; every candidate is simulated again.',64,573,1152,36,25,C.ink,true);
  text(s,2,'fields','LLM choices: insertion site · device representation · trigger profile · strength',64,614,1152,28,22,C.grey);
}
{
  const s=base(p,3,'Ten different starts, paired across conditions','Sources: frozen starting design and control gate; report pp.1–2');
  text(s,3,'starting-design','10 unique starting configurations per circuit, fixed before detector calls.\nThe sample covers every insertion-site / representation combination.',64,181,1152,79,28);
  box(s,3,'Attempt 1','Python renders a preset;\nno attacker API call.',64,300,360,139);
  box(s,3,'If no escape yet','Attempts 2–10:\nLLM proposes the next circuit.',460,300,360,139);
  box(s,3,'Stop at any attempt','Electrical checks pass\nand is_trojan = false.',856,300,360,139);
  arrow(s,431,357,23);
  text(s,3,'pairing','None, Binary and Full share each session’s first candidate and review.',64,481,1152,37,27,C.ink,true);
  text(s,3,'allocation','2 circuits × 3 conditions × 10 sessions · at most 10 attempts per session',64,528,1152,36,25,C.grey);
  text(s,3,'controls','Before the main sessions: two clean and two known-Trojan controls, all correct.\nThese basic checks are separate from the session results.',64,577,1152,62,23,C.grey);
}
{
  const s=base(p,4,'What each feedback condition receives','Sources: frozen prompts/settings; report pp.1–2 | Only the preceding attempt is supplied');
  text(s,4,'model',`Both roles: ${config.model}`,64,180,1152,36,26,C.grey);
  text(s,4,'temperatures','Temperatures: attacker 0.3 · detector 0.0 (fixed seed + cache)',64,228,1152,38,28,C.ink,true);
  const rows=[['None','Fresh task; no previous candidate or review.'],['Binary','Previous configuration + Boolean verdict.'],['Full','Previous configuration + verdict, confidence,\nsuspicious identifiers and explanation.']];
  rows.forEach(([title,body],i)=>{const y=307+i*76;line(s,64,y-13,1152);text(s,4,'feedback-level',title,64,y,150,42,29,C.teal,true);text(s,4,'feedback-detail',body,240,y,976,69,26);});
  text(s,4,'detector-input','Detector input: candidate netlist + nominal function only.',64,559,1152,36,27,C.ink,true);
  text(s,4,'no-learning','No simulation outputs to either LLM. No online detector learning.',64,608,1152,32,24,C.grey);
}
{
  const s=base(p,5,'Feedback reaches more escaped sessions','Source: current report, Figure 1 | Counts are sessions, not successful attempts');
  text(s,5,'plot-definition','Cumulative first escapes out of 10 sessions; each successful session stops.',64,146,1152,30,23,C.grey);
  const bytes=await fs.readFile(path.join(ROOT,FIGURE));
  const iw=bytes.readUInt32BE(16), ih=bytes.readUInt32BE(20);
  const chart=s.images.add({blob:bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength),fit:'contain',alt:'Report Figure 1: cumulative escaped sessions for op-amp and AND under None, Binary and Full feedback.'});
  const height=1100*ih/iw; chart.position={left:90,top:179,width:1100,height};
  records.push({kind:'report-figure',slide:5,role:'cumulative-escape',source:FIGURE,sha256:await hash(FIGURE),bbox:[90,179,1100,height],user_requested_source_reuse:true});
  text(s,5,'final-counts-opamp',`Op-amp: ${counts.opamp.map(n=>n+'/10').join('  ·  ')}`,64,620,550,31,25,C.ink,true);
  text(s,5,'final-counts-and',`AND: ${counts.and4.map(n=>n+'/10').join('  ·  ')}  (None / Binary / Full)`,637,620,579,31,23,C.ink,true);
}
{
  const s=base(p,6,'How feedback changes the search','Source: recorded attempts; AND / Full / session 2; report p.4');
  text(s,6,'revision-opportunities',`Only ${10-initial.opamp} op-amp and ${10-initial.and4} AND starts per condition need revision.`,64,180,1152,40,28,C.ink,true);
  text(s,6,'none-heading','None: later proposals',64,257,360,37,27,C.ink,true);
  text(s,6,'none-repetition',`${noFeedback.opamp} op-amp proposals\n${noFeedback.and4} AND proposals\n\nEach repeats one\nflagged netlist.`,64,316,355,190,27,C.grey);
  text(s,6,'example-heading','One AND / Full session',460,257,756,37,27,C.ink,true);
  const steps=[['Attempt 1','Internal node\nConductance','Detected'],['Attempt 2','Output node\nMOSFET','Detected'],['Attempt 3','Internal node\nSwitch','Escape']];
  steps.forEach(([title,body,status],i)=>{const x=460+i*262;shape(s,'rect',x,313,232,185,C.pale);text(s,6,'attempt',title,x+16,330,200,36,25,C.ink,true);text(s,6,'candidate',body,x+16,382,200,69,24,C.grey);text(s,6,'verdict',status,x+16,468,200,31,25,i===2?C.teal:C.warm,true);if(i<2)arrow(s,x+237,390,20);});
  text(s,6,'example-validity','All three candidates pass the electrical checks.',460,514,756,31,23,C.grey);
  line(s,64,563,1152,C.teal);
  text(s,6,'cache-meaning','Resubmitting a netlist cannot change its cached verdict.\nFeedback can help the attacker leave a repeated default.',64,585,1152,63,26);
}
{
  const s=base(p,7,'Full reaches the same total sooner','References: A2 (2016); SPICED (2024); LATENT (2025) | Full citations in notes and report');
  text(s,7,'speed-heading','Attempt when all 10 sessions escape',64,186,545,72,28,C.ink,true);
  text(s,7,'column-circuit','Circuit',64,283,238,35,24,C.grey,true);
  text(s,7,'column-full','Full',334,283,106,35,24,C.teal,true);
  text(s,7,'column-binary','Binary',478,283,130,35,24,C.ink,true);
  line(s,64,326,544);
  [['Op-amp','opamp'],['AND','and4']].forEach(([label,c],i)=>{const y=351+i*70;text(s,7,'speed-circuit',label,64,y,238,42,30);text(s,7,'speed-full',String(reach[c].full),334,y,106,42,31,C.teal,true);text(s,7,'speed-binary',String(reach[c].binary),478,y,130,42,31,C.ink,true);});
  text(s,7,'same-final','Final success: 10/10 for both\nfeedback conditions, on both circuits.',64,505,546,70,27,C.ink,true);
  shape(s,'rect',634,186,2,389,C.rule);
  text(s,7,'scope-heading','What this result supports',680,186,536,40,28,C.ink,true);
  text(s,7,'scope-menu','A search advantage in these finite menus,\nusing one model and a netlist-only reviewer.',680,253,536,77,24,C.grey);
  text(s,7,'scope-history','None also lacks candidate history.\nBinary vs Full more directly compares\nthe amount of review information.',680,354,536,101,24,C.grey);
  text(s,7,'scope-cache','The cache fixes judgments within this run.\nFresh runs can yield different verdicts.',680,477,536,77,24,C.grey);
  text(s,7,'conclusion','Defensive explanations can also give an attacker useful clues.',64,604,1152,35,28,C.teal,true);
}

for(const rec of records.filter(r=>r.bbox)) {
  const [x,y,w,h]=rec.bbox;
  require(x>=0 && y>=0 && x+w<=W+0.1 && y+h<=H+0.1, `Out of bounds: ${rec.role}`);
}
const logPath=path.join(SCRATCH,'render_verify_loops.ndjson');
let previous=''; try { previous=await fs.readFile(logPath,'utf8'); } catch {}
const loop=previous.trim()?previous.trim().split('\n').length+1:1;
require(loop<=3,'Maximum three render/verify loops reached.');
await fs.appendFile(logPath,JSON.stringify({loop,started_at:new Date().toISOString()})+'\n');
await fs.writeFile(path.join(SCRATCH,'inspect.ndjson'),records.map(r=>JSON.stringify(r)).join('\n')+'\n');
await fs.writeFile(path.join(SCRATCH,'speaker_notes.txt'),NOTES.map((n,i)=>`SLIDE ${i+1} — ${DURATIONS[i]} seconds\n${n}\n\n中文答辩提醒\n${QA[i]}\n`).join('\n'));
for(let i=0;i<p.slides.count;i++) {
  const blob=await p.export({slide:p.slides.getItem(i),format:'png',scale:1.3});
  await fs.writeFile(path.join(PREVIEW,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await blob.arrayBuffer()));
}
const dest=path.join(OUT,'output.pptx');
const pptx=await PresentationFile.exportPptx(p); await pptx.save(dest);
const sourceFiles=[
  'configs/active_experiment.json',active.config,'scripts/presentation/build_slides.mjs',active.report,
  'output/pdf/A2_Trojan_LLM_Informal_Report.txt','output/pdf/A2_Trojan_LLM_Informal_Report.provenance.json',FIGURE,
  ...['summary.json','attempts.json','design.json','controls.json','controls_gate.json','completion.json','audit.json','cumulative.csv'].map(n=>`${RUN}/${n}`)
];
const hashes={}; for(const f of sourceFiles) hashes[f]=await hash(f);
const metadata={run_id:active.run_id,slides:p.slides.count,planned_seconds:DURATIONS.reduce((a,b)=>a+b),spoken_words:NOTES.join(' ').split(/\s+/).length,
  model:config.model,attacker_temperature:config.attacker_temperature,detector_temperature:config.detector_temperature,counts,initial_escapes:initial,attempt_reaching_ten:reach,
  native_charts:0,reused_report_figures:[{path:FIGURE,sha256:hashes[FIGURE],slide:5}],editable_textboxes:records.filter(r=>r.kind==='textbox').length,
  source_sha256:hashes,pptx_sha256:await hash(path.relative(ROOT,dest))};
await fs.writeFile(path.join(OUT,'provenance.json'),JSON.stringify(metadata,null,2)+'\n');
console.log(JSON.stringify({file:dest,slides:metadata.slides,seconds:metadata.planned_seconds,spoken_words:metadata.spoken_words,render_loop:loop}));
