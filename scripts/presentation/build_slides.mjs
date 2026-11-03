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
const SCRATCH = path.join(ROOT, 'tmp/slides/a2_feedback_final_report_2026-11-03');
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
const PRESENTATION_REPORT = 'docs/inputs/Collaborator_Final_Report_2026-11-03.pdf';
const PRESENTATION_REPORT_SHA256 = '89c091c8477b1b6beaa8ab2fa4d085492cb0033d3c7d989fc56d7629167ae970';
const FIGURE = 'scripts/presentation/assets/collaborator_report_figure_2026-11-03.png';
require(summary.complete && audit.passed && completion.complete, 'Completed and audited evidence is required.');
require(reportMeta.run_id === active.run_id && await hash(active.report) === reportMeta.pdf_sha256, 'Report provenance is stale.');
for (const [name, expected] of Object.entries(reportMeta.source_sha256)) require(await hash(name) === expected, `Report source changed: ${name}`);
require(await hash(PRESENTATION_REPORT) === PRESENTATION_REPORT_SHA256, 'The supplied collaborator report must remain unchanged.');
require(await hash(FIGURE) === '6a703883db41a88754ec04e8ff923917aaf93363a9921c5f30eb3e690a16cc6a', 'The figure must be extracted unchanged from page 2 of the supplied report.');
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
const thirdRequest = await read(example[2].attacker_record);
const feedbackInPrompt = JSON.parse(thirdRequest.request.messages[1].content.split('REVIEWER FEEDBACK:\n')[1]);
for (const key of Object.keys(example[1].detector)) require(JSON.stringify(feedbackInPrompt[key]) === JSON.stringify(example[1].detector[key]), 'The feedback must be the actual review received before attempt 3.');
const FEEDBACK_SUMMARY = 'The added components could alter the output based on the voltage at n31,\nindicating a potential Trojan mechanism.';

const DURATIONS = [30, 50, 45, 60, 60, 55];
const NOTES = [
  `Does detector feedback help an attacker? SPICED uses LLMs to identify suspicious circuit changes and explain them, so that designers can improve their designs. But the same explanation may give an attacker useful clues. LATENT uses detector feedback when revising Trojan insertions. Taking A2's charge-accumulation trigger as background, we study this possible information leak: does more detailed feedback help an attacker find a functioning modification that escapes review?`,
  `We use a two-stage op-amp and a four-input AND gate. Each has ten different starting configurations selected from an electrically verified menu. Within each start, the three conditions share the first candidate and review. Python renders this preset; the attacker LLM proposes later configurations by selecting an insertion site, representation, trigger profile and strength. Ngspice checks normal operation and triggered disturbance. Separately, the detector judges the netlist. A valid negative verdict ends the session immediately, with at most ten attempts in total. We keep the detector fixed to observe how the attacker uses feedback.`,
  `The conditions differ in what reaches the next attacker request. None receives a fresh task, with no previous candidate or review. Binary receives its preceding configuration and the Boolean verdict. Full also receives suspicious identifiers, confidence and the explanation. Only the preceding attempt is included. Both roles use GPT-4o-mini, with attacker temperature point three and detector temperature zero. A fixed seed and cached exact requests keep the reviewer consistent within this run. It sees only the candidate netlist and nominal function. Simulation results are used for evaluation, not given to either LLM.`,
  `The figure comes directly from the report. Each curve counts sessions that have escaped by that attempt, out of ten. At the first attempt, six op-amp starts and four AND starts already escape. None remains at sixty and forty percent. With either Binary or Full feedback, both benchmarks reach ten out of ten. For the op-amp, Full reaches this total at attempt five and Binary at six. For AND, Full reaches it at attempt three and Binary at seven. Thus the final success counts are equal, while detailed feedback reaches them sooner in this execution. Successful sessions stop, so a flat tail does not represent additional attempts.`,
  `This is the AND Full condition, session two, used in the report. The initial internal conductance branch is detected. The next proposal uses an output MOSFET and is also detected. Its feedback identifies the added diode, capacitor and transistor circuitry as a mechanism that could change the output according to the voltage at node n31, suggesting a Trojan. That exact review is supplied before attempt three. The attacker then selects an internal switch branch, which passes both electrical tests and escapes detection. Relative to the initial configuration, the representation changes from conductance to switch. The detector identified a concern; it did not explicitly recommend using a switch.`,
  `The results support the report's hypothesis that detector feedback can benefit an attacker. Both feedback conditions reach full success on these benchmarks, and Full reaches it with fewer attempts. However, three questions remain untested. First, the detector does not learn or adapt, so we do not measure whether feedback could improve its defense. Second, we do not test designers using explanations to repair or strengthen circuits, which is an intended use of SPICED. Third, we use one GPT-4o-mini snapshot and do not compare newer models. We therefore observe an attacker-side benefit in this setup, while the overall security benefit of LLMs remains open.`
];
const QA = [
  '为什么不直接用 LATENT 的 94.4% 比？其指标是插入组件逃过定位；这里统计找到电气有效且整份网表被判正常的 session。SPICED 使用仿真日志等信息，我们的 detector 只有 netlist 和功能说明。本项目没有完整复现这三篇论文。',
  'Session从指定起点开始；20个不同起点×3条件=60条条件级session，不是60份独立电路。首轮由Python生成，第二轮起才调用attacker。运放3个位置、AND2个位置；菜单为81/54种，覆盖9/6种位置×表示形式。四个单独控制均通过但不进入session分母。正常/触发阈值：运放≤20mV/≥0.3V；AND16/16逻辑、≤0.2V/≥0.8V。教学仿真，未做流片或工艺角测试。',
  'None与反馈组同时还差上一候选历史，因此Binary/Full更直接比较解释的详细程度。温度0和seed并不保证跨API调用完全一致；缓存只固定本次运行。Detector不学习是为了观察攻击方对反馈的使用，并不证明防御方不能从反馈获益。',
  'Final None/Binary/Full：运放6/10、10/10、10/10；AND4/10、10/10、10/10。40条反馈条件session均成功，但其中20条在预设首轮就已成功，不能说40条都经过反馈修改。实际157个事件=20预设+137LLM，197分析记录含40个共享首轮副本；44正式检测+4控制+137attacker=185次API。None后续36/54次各重复一份被抓电路。Full更早达到最终总数，不是最终比Binary成功率高，也未检验统计显著性。',
  '完整路径：nand_node_pullup/conductance/p2/high → output_shunt/mosfet/p1/medium → nand_node_pullup/switch/p2/high。第3轮只收到第2轮配置及反馈：is_trojan=true, confidence=0.9, suspect_nodes=[n31,n32,out,vss,n33]。解释点名D31,D32,C31,C32,R31,B31,M31，称这些部件可根据n31电压改变输出、可能形成木马。它没有建议换成switch。conductance→switch只是在比较第1与第3轮；原始反馈也不等于可靠的电气分析。',
  '三项未测试的问题直接来自合作者报告：detector学习、设计者利用反馈改善电路、更新模型比较。不能声称这些一定会改善防御，也不能用本项目得出LLM总体为正或为负。结论限定为两个有限菜单、固定模型、固定检测映射下的攻击搜索。'
];
const SOURCES = [
  `${PRESENTATION_REPORT}, p.1. A2: Yang et al., IEEE S&P 2016, doi:10.1109/SP.2016.10. SPICED: arXiv:2408.16018v1. LATENT: arXiv:2505.06364v1.`,
  `${PRESENTATION_REPORT}, pp.1–2; ${RUN}/design.json; ${RUN}/completion.json; circuits.py.`,
  `${PRESENTATION_REPORT}, pp.1–2; ${active.config}; scripts/proposal/prompts.py.`,
  `${PRESENTATION_REPORT}, pp.2–3, Figure 1; ${FIGURE}; ${RUN}/summary.json; ${RUN}/cumulative.csv.`,
  `${PRESENTATION_REPORT}, p.3; ${RUN}/attempts.json; actual third-attempt request: ${example[2].attacker_record}; second-attempt detector reply: ${example[1].detector_records[0].path}.`,
  `${PRESENTATION_REPORT}, discussion p.3; ${RUN}/summary.json. The report itself is supplied unchanged.`
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
  const s=base(p,1,'Does detector feedback\nhelp an attacker?','Information Security course project | A2, SPICED and LATENT');
  text(s,1,'question-detail','Explanations intended to help designers\nmay also give an attacker useful clues.',64,236,1152,85,30);
  const papers=[['A2 · 2016','Analog charge\naccumulation'],['SPICED · 2024','LLM detection\nand explanations'],['LATENT · 2025','Iterative insertion\nusing feedback']];
  papers.forEach(([title,body],i)=>{const x=64+i*396;line(s,x,368,360,C.teal);text(s,1,'paper',title,x,389,360,36,26,C.ink,true);text(s,1,'paper-role',body,x,436,360,82,27,C.grey);});
  text(s,1,'authors','Amber Tsao (cctsao)  ·  Jiahao Xu (e1583425)',64,576,1152,36,23,C.grey);
}
{
  const s=base(p,2,'A fixed detector, ten paired starting points','Source: project report, Methodology, pp.1–2; recorded experiment design');
  text(s,2,'benchmarks','Two-stage op-amp + four-input AND · 10 different starting circuits each',64,181,1152,36,27,C.grey);
  box(s,2,'Attempt 1','Python renders a preset;\nno attacker API call.',64,263,360,139);
  box(s,2,'If no escape yet','Attempts 2–10:\nLLM proposes the next circuit.',460,263,360,139);
  box(s,2,'Stop at any attempt','Electrical checks pass\nand is_trojan = false.',856,263,360,139);
  arrow(s,431,320,23);
  text(s,2,'pairing','None, Binary and Full share each start and its first review.',64,437,1152,36,28,C.ink,true);
  text(s,2,'electrical-checks','ngspice verifies normal function and triggered disturbance.\nThe LLM detector reviews the netlist separately.',64,493,1152,72,27);
  line(s,64,584,1152,C.teal);
  text(s,2,'control-purpose','Keep the detector fixed to study how the attacker uses feedback.',64,607,1152,36,27,C.teal,true);
}
{
  const s=base(p,3,'What information does the attacker receive?','Source: project report, Methodology, pp.1–2 | Only the preceding attempt is supplied');
  text(s,3,'model',`Both roles: ${config.model}`,64,180,1152,36,26,C.grey);
  text(s,3,'temperatures','Temperatures: attacker 0.3 · detector 0.0 (fixed seed + cache)',64,228,1152,38,28,C.ink,true);
  const rows=[['None','Fresh task; no previous candidate or review.'],['Binary','Previous configuration + Boolean verdict.'],['Full','Previous configuration + verdict, confidence,\nsuspicious identifiers and explanation.']];
  rows.forEach(([title,body],i)=>{const y=307+i*76;line(s,64,y-13,1152);text(s,3,'feedback-level',title,64,y,150,42,29,C.teal,true);text(s,3,'feedback-detail',body,240,y,976,69,26);});
  text(s,3,'detector-input','Detector input: candidate netlist + nominal function only.',64,559,1152,36,27,C.ink,true);
  text(s,3,'evaluation-only','Simulation results are used for evaluation, not fed to either LLM.',64,608,1152,32,24,C.grey);
}
{
  const s=base(p,4,'Feedback improves success; Full gets there sooner','Source: project report, Figure 1, p.2 | Counts are sessions, not successful attempts');
  text(s,4,'plot-definition','Cumulative first escapes out of 10 sessions; each successful session stops.',64,146,1152,30,23,C.grey);
  const bytes=await fs.readFile(path.join(ROOT,FIGURE));
  const iw=bytes.readUInt32BE(16), ih=bytes.readUInt32BE(20);
  const chart=s.images.add({blob:bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength),fit:'contain',alt:'Report Figure 1: cumulative escaped sessions for op-amp and AND under None, Binary and Full feedback.'});
  const height=1100*ih/iw; chart.position={left:90,top:179,width:1100,height};
  records.push({kind:'report-figure',slide:4,role:'cumulative-escape',source:FIGURE,sha256:await hash(FIGURE),bbox:[90,179,1100,height],user_requested_source_reuse:true});
  text(s,4,'final-counts-opamp',`Op-amp: ${counts.opamp.map(n=>n+'/10').join('  ·  ')}`,64,620,550,31,25,C.ink,true);
  text(s,4,'final-counts-and',`AND: ${counts.and4.map(n=>n+'/10').join('  ·  ')}  (None / Binary / Full)`,637,620,579,31,23,C.ink,true);
}
{
  const s=base(p,5,'What did the detector actually reveal?','Source: project report, Discussion, p.3; actual feedback in the attempt 3 request');
  text(s,5,'example-heading','Four-input AND · Full feedback · Session 2',64,180,1152,36,27,C.grey);
  const steps=[['Attempt 1','Internal node · conductance','Detected'],['Attempt 2','Output node · MOSFET','Detected'],['Attempt 3','Internal node · switch','Escape']];
  steps.forEach(([title,body,status],i)=>{const x=64+i*396;shape(s,'rect',x,248,360,150,C.pale);text(s,5,'attempt',title,x+18,264,324,35,25,C.ink,true);text(s,5,'candidate',body,x+18,312,324,35,23,C.grey);text(s,5,'verdict',status,x+18,357,324,33,25,i===2?C.teal:C.warm,true);if(i<2)arrow(s,x+365,312,24);});
  text(s,5,'feedback-heading','Attempt 2 feedback, passed to attempt 3 (summary)',64,435,1152,37,27,C.ink,true);
  shape(s,'rect',64,490,1152,96,C.pale);
  text(s,5,'actual-feedback',FEEDBACK_SUMMARY,84,508,1112,69,26,C.ink);
  text(s,5,'example-validity','All three candidates pass the electrical checks; the third escapes detection.',64,610,1152,34,25,C.teal,true);
}
{
  const s=base(p,6,'Feedback helps the attacker in this setup','Source: project report, Discussion, p.3 | A2 (2016); SPICED (2024); LATENT (2025)');
  text(s,6,'speed-heading','Both feedback conditions reach 10/10.\nFull reaches that total sooner:',64,183,557,78,28,C.ink,true);
  text(s,6,'column-circuit','Circuit',64,299,238,35,24,C.grey,true);
  text(s,6,'column-full','Full',334,299,106,35,24,C.teal,true);
  text(s,6,'column-binary','Binary',478,299,130,35,24,C.ink,true);
  line(s,64,341,544);
  [['Op-amp','opamp'],['AND','and4']].forEach(([label,c],i)=>{const y=366+i*70;text(s,6,'speed-circuit',label,64,y,238,42,30);text(s,6,'speed-full',String(reach[c].full),334,y,106,42,31,C.teal,true);text(s,6,'speed-binary',String(reach[c].binary),478,y,130,42,31,C.ink,true);});
  text(s,6,'speed-label','Attempt when all 10 sessions have escaped',64,511,546,65,24,C.grey);
  shape(s,'rect',634,183,2,393,C.rule);
  text(s,6,'scope-heading','Three questions we did not test',680,183,536,40,28,C.ink,true);
  const limitations=[['Detector learning','Could feedback improve detection?'],['Designer use','Could explanations help repair circuits?'],['Newer models','Would another model change the result?']];
  limitations.forEach(([title,body],i)=>{const y=263+i*105;text(s,6,'limitation-title',title,680,y,536,35,26,C.teal,true);text(s,6,'limitation-detail',body,680,y+42,536,55,24,C.grey);});
  text(s,6,'conclusion','The attacker gains useful clues; LLMs’ overall security benefit remains open.',64,609,1152,36,27,C.teal,true);
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
  'configs/active_experiment.json',active.config,'scripts/presentation/build_slides.mjs',active.report,PRESENTATION_REPORT,
  'output/pdf/A2_Trojan_LLM_Informal_Report.txt','output/pdf/A2_Trojan_LLM_Informal_Report.provenance.json',FIGURE,
  ...['summary.json','attempts.json','design.json','controls.json','controls_gate.json','completion.json','audit.json','cumulative.csv'].map(n=>`${RUN}/${n}`),
  example[2].attacker_record,example[1].detector_records[0].path
];
const hashes={}; for(const f of sourceFiles) hashes[f]=await hash(f);
const metadata={run_id:active.run_id,slides:p.slides.count,planned_seconds:DURATIONS.reduce((a,b)=>a+b),spoken_words:NOTES.join(' ').split(/\s+/).length,
  model:config.model,attacker_temperature:config.attacker_temperature,detector_temperature:config.detector_temperature,counts,initial_escapes:initial,attempt_reaching_ten:reach,
  presentation_report:PRESENTATION_REPORT,presentation_report_sha256:PRESENTATION_REPORT_SHA256,report_modified:false,
  native_charts:0,reused_report_figures:[{path:FIGURE,sha256:hashes[FIGURE],slide:4,source_pdf:PRESENTATION_REPORT,source_pdf_page:2,source_xref:9}],editable_textboxes:records.filter(r=>r.kind==='textbox').length,
  feedback_example:{circuit:'and4',condition:'full',session:2,feedback_after_attempt:2,used_by_attempt:3,summary:FEEDBACK_SUMMARY,attacker_record:example[2].attacker_record},
  source_sha256:hashes,pptx_sha256:await hash(path.relative(ROOT,dest))};
await fs.writeFile(path.join(OUT,'provenance.json'),JSON.stringify(metadata,null,2)+'\n');
console.log(JSON.stringify({file:dest,slides:metadata.slides,seconds:metadata.planned_seconds,spoken_words:metadata.spoken_words,render_loop:loop}));
