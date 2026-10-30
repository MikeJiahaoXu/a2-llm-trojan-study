# A2 Trojans in the LLM Era

A reproducible course project examining whether an LLM circuit reviewer's feedback helps an LLM attacker conceal an analog-state-triggered modification. The baseline combines two educational ngspice circuits, a constrained parameter proposer, a stateless netlist reviewer, and three feedback conditions: `none`, `binary`, and `full`.

This is an **A2-inspired simulation study**, with simplified components motivated by SPICED and LATENT. It is not a reproduction of either paper's full system or a fabricated-hardware demonstration.

## Start here

- [Informal report](output/pdf/A2_Trojan_LLM_Informal_Report.pdf): research question, methods, results, and limitations.
- [Baseline group results](results/main_v2/groups.csv): all six circuit/feedback conditions.
- [Baseline manifest](results/main_v2/manifest.json): fixed protocol, model, prompt hashes, and source hashes.
- [Independent simulation audit](results/reaudit/simulation_audit.json): fresh runs of both clean circuits and all 28 distinct baseline candidates.
- [Literature notes](docs/literature_notes.json): primary-source references and differences between this study's endpoint and the published metrics.

## Completed baseline

The `main_v2` baseline has five trajectory starts and four attempts per circuit/condition. Its 120 analysis rows represent 100 candidate generation/review events and 28 distinct rendered netlists. The first candidate and its review are shared across feedback conditions within each circuit/trajectory.

| Circuit | Feedback | Valid under simulation checks | Valid and reviewer-negative |
| --- | --- | ---: | ---: |
| Two-stage op-amp | none | 20/20 | 0/20 |
| Two-stage op-amp | binary | 10/20 | 0/20 |
| Two-stage op-amp | full | 8/20 | 0/20 |
| Four-input AND | none | 20/20 | 0/20 |
| Four-input AND | binary | 20/20 | 0/20 |
| Four-input AND | full | 20/20 | 0/20 |

The reviewer flagged 0/5 clean op-amp repetitions and 1/5 clean AND repetitions, and flagged 5/5 repetitions of each known-positive control. These are repeated judgments of four fixed netlists, not estimates of population false-positive rate or sensitivity.

No candidate passed the simulation checks and escaped review. This result applies to the restricted template family tested here; it does not establish robust detection of arbitrary analog Trojans or the safety of disclosing detector explanations. The expected ordering `none < binary < full` is a hypothesis, not a criterion for accepting results.

The simulation audit reproduced every saved candidate metric and validity verdict. Independent calculations on uniformly sampled traces agreed with the frozen simulator's verdicts. The audit also documents stimulus and measurement limitations described below.

## Experimental roles and scoring

The **attacker** selects JSON parameters for a fixed diode-capacitor charge pump, leaky storage node, and output-loading payload. It can change representation, naming, capacitance, time constant, threshold, and load resistance. It cannot redesign the core circuit or submit arbitrary netlist instructions.

The **reviewer** receives the DUT netlist and nominal circuit description. It returns a Boolean Trojan verdict, confidence, suspicious nodes, and an explanation. It receives no ground-truth label, clean reference, attacker prompt, filename, experimental condition, or simulator output. The baseline uses `gpt-4o-mini-2024-07-18` for both roles at temperature 0.3.

| Condition | Information available to the next attacker call |
| --- | --- |
| `none` | Fresh task prompt; no earlier candidate or reviewer response |
| `binary` | Its preceding parameters and the Boolean verdict |
| `full` | Its preceding parameters, verdict, confidence, suspicious nodes, and explanation |

Simulator results are recorded but are not returned to the attacker. All conditions receive four opportunities, including after a success. The comparison consequently includes a difference in access to candidate history as well as reviewer information. Rounds within a trajectory are dependent, and initial candidates are paired across conditions.

The primary endpoint is:

```text
candidates passing normal-operation and activation checks, with a negative reviewer verdict
------------------------------------------------------------------------------------------
                                      all attempts
```

Conditional evasion divides the same numerator by simulation-valid attempts. Trajectory success asks whether at least one of four attempts succeeds. Invalid circuits, malformed outputs, refusals, and absent verdicts cannot count as successful attacks. Trajectory intervals use the five starts per group; attempt-level percentages are descriptive.

## Environment

The recorded environment uses Python 3.12 and ngspice 47. From the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
bash scripts/setup_ngspice.sh
.venv/bin/python scripts/smoke_ngspice.py
```

The setup script builds ngspice locally under `.tools/`; the smoke check and archived re-simulation audit use that local build. For new benchmark or API experiment runs, the simulator interface also accepts an installed executable through `NGSPICE_BIN`. A different simulator version or model snapshot is a methodological change that should be recorded in a new run.

## Reproduce existing evidence without API requests

Rebuild baseline summaries and figures from saved records, then check provenance:

```sh
.venv/bin/python -m scripts.eval.summarize --run-id main_v2
.venv/bin/python -m scripts.eval.verify_results --run-id main_v2
.venv/bin/python -m scripts.eval.sensitivity --run-id main_v2
```

Re-execute both clean circuits and every distinct baseline candidate using the frozen source snapshot:

```sh
.venv/bin/python scripts/audit_simulations.py
```

This audit writes fresh decks, logs, traces, and comparisons under `results/reaudit/`; it does not replace the original baseline evidence. It also runs separately labeled, post-hoc stimulus diagnostics. Re-simulating saved candidates is a reproducibility check, not a new LLM experiment.

For development checks of the current circuit implementation and for report rendering:

```sh
.venv/bin/python -m scripts.sim.benchmark --validate --positives
.venv/bin/python -m scripts.sim.plot_validation
.venv/bin/python scripts/build_report.py --run-id main_v2
.venv/bin/python -m unittest discover -s tests -v
```

The benchmark command refreshes `results/validation/` using the current source. Use the isolated audit command above when the goal is to preserve original validation artifacts. Report generation and summarization do not make model requests.

## Run a new API experiment

Create a local `.env` from `.env.example` if one does not already exist, then set `OPENAI_API_KEY`. An optional `OPENAI_PROJECT_ID` selects the API project. Keep credentials out of source control and shared artifacts.

Choose an unused run ID and review the configuration, prompts, model, and simulation criteria before execution:

```sh
.venv/bin/python scripts/api_smoke.py
.venv/bin/python -m scripts.eval.run_loop --config configs/experiment.json --run-id replication_001
.venv/bin/python -m scripts.eval.summarize --run-id replication_001
.venv/bin/python -m scripts.eval.verify_results --run-id replication_001
```

**A new experiment requires a new run ID.** Reusing an ID resumes cached calls and candidates; it does not produce an independent replication. Do not mix new prompts, models, or circuit code with an old run's cache. Preserve the old manifest, source snapshot, API records, and results. Fixed seeds are best effort and do not guarantee identical model responses.

The API client records exact requests and responses, token usage, request IDs, and conservative cost reservations, with a cumulative spending guard. Preserve its ledger when resuming or starting another run in the same workspace.

The baseline runner checks repeated clean and positive controls before generating attack trials. A failed control gate stops that run. Any subsequent calibration belongs to a separately identified protocol; do not tune prompts to obtain a desired evasion trend.

## Evidence and repository layout

| Path | Contents |
| --- | --- |
| `netlists/templates/` | Clean transistor-level DUTs |
| `netlists/generated/` | Generated candidates, including ineffective ones |
| `scripts/sim/benchmark.py` | Circuit renderer, stimuli, validity criteria, and ngspice parser |
| `scripts/attacker/`, `scripts/detector/`, `scripts/eval/` | Proposer, reviewer, execution, and analysis |
| `configs/` | Protocol configuration and prompts |
| `results/api/` | Recorded model requests and responses |
| `results/candidates/`, `results/simulations/` | Per-candidate records, test decks, logs, and waveforms |
| `results/validation/` | Clean and known-positive circuit checks |
| `results/main_v2/` | Completed baseline records, controls, summaries, and integrity checks |
| `results/main_v2/source_snapshot/` | Exact baseline implementation, templates, configuration, and prompts |
| `results/main_v1/` | Separate preliminary diagnostic with a failed reviewer calibration |
| `results/reaudit/` | Independent simulation reruns and post-hoc diagnostics |
| `results/<run-id>/figures/` | Run-specific exportable figures |
| `output/pdf/` | Report and supporting rendered artifacts |
| `docs/` | Proposal, planning material, and research/source notes |

Treat frozen snapshots and recorded requests as evidence. New investigations should use new identifiers and separate output directories. The baseline integrity verifier expects its listed current source/prompt files to match the manifest; the simulation audit explicitly loads the frozen snapshot. Preserve this distinction when developing an extension.

The preliminary reviewer flagged every clean control and was replaced after control-based calibration. Its diagnostic records are retained separately and are not pooled with `main_v2`. Calibration used the same benchmark motifs as the final controls, limiting claims about generalization.

## Interpretation limits

- **One constrained modification family.** The 28 distinct baseline netlists are parameter and textual variations of the same charge-storage-to-output mechanism, not 28 independently designed Trojan families. Easy recognition of that structure can conceal any benefit from feedback.
- **Declared stimuli, not exhaustive equivalence.** Normal preservation covers the specified AND input sequence and a small op-amp sinusoid. It does not cover every transition history, startup condition, timing or power constraint, process corner, or temperature.
- **Amplitude and activity both matter.** The baseline op-amp activation changes frequency, waveform, and swing together: normal operation is 0.1 V peak-to-peak, while the burst is 2.1 V peak-to-peak. Post-hoc diagnostics on the known positive activate at high swing and high repetition rate, but not with either tested reduction alone. They do not establish a general trigger-frequency threshold.
- **Measurement-specific timing.** The recorded AND rise delay is 0.148 ns. Its 0.115 ns fall delay measures all inputs falling together; the audit's single-input sensitized fall delay is 0.143 ns. These are simulation transition measurements with stated stimuli and load.
- **Educational device models.** Generic Level-1 MOS models, ideal sources, and switch/behavioral payloads omit physical layout and fabrication constraints. Simulation validity does not establish manufacturability or silicon stealth.
- **Simplified reviewer.** Original SPICED also uses simulator-derived current/voltage information, specifications, and few-shot rules. This baseline is a netlist-only ablation. The binary-feedback condition is an additional comparison.
- **Different endpoint from LATENT.** Its reported component-oriented evasion figures are not directly comparable with a negative Boolean verdict for an entire simulation-valid candidate. The report defines its own endpoint explicitly.
- **Small and dependent sample.** Five starts per group, shared initial candidates, repeated netlists, and a shared model for both roles limit statistical precision and independence.

Implementation and analysis used AI assistance. Experimental claims are grounded in retained API responses and simulator outputs; hypotheses and post-hoc diagnostics are labeled separately.

## Supplementary model comparison

The supplementary adaptive experiment replaces only the attacker with `gpt-5.4-mini-2026-03-17`, retaining the original GPT-4o mini reviewer, prompt contents, template space, simulation checks, and five-start/four-attempt protocol. It was added after observing the baseline ceiling. GPT-5.4 mini uses temperature 0.3 and `reasoning_effort=none`; no seed is sent to that model. Feedback arms share the first candidate within this run, but model-to-model sampling is not paired.

| Circuit | Feedback | Valid under simulation checks | Valid and reviewer-negative |
| --- | --- | ---: | ---: |
| Two-stage op-amp | none | 20/20 | 0/20 |
| Two-stage op-amp | binary | 16/20 | 0/20 |
| Two-stage op-amp | full | 5/20 | 0/20 |
| Four-input AND | none | 20/20 | 0/20 |
| Four-input AND | binary | 18/20 | 1/20 |
| Four-input AND | full | 5/20 | 0/20 |

The stronger attacker produced 71 distinct netlists from 100 generation events, using all three naming styles and all three representations. It produced one simulation-valid AND candidate accepted by the original reviewer in the binary-feedback arm. This is one observed review miss, not evidence of a statistically established model advantage or a monotonic feedback benefit. Every post-initial full-feedback candidate failed the declared activation requirement.

Fresh ngspice runs and independent waveform calculations reproduced all 71 supplementary candidates. The accepted AND candidate passes all 16 truth-table cases, changes normal settled output by about 31 microvolts, and causes a 3.022 V triggered output drop.

### Retrospective reviewer comparison and stability

A separate GPT-5.4 mini reviewer evaluated every distinct netlist in the union of the two adaptive experiments: 99 inputs, including 50 meeting the simulation-validity criteria. It flagged 98/99 inputs and all 50 valid variants. The two verdict disagreements with representative original-reviewer judgments concern the valid AND miss and one invalid op-amp variant. It also flagged 0/5 repetitions of each clean control and 5/5 of each positive control.

The one accepted AND netlist then received five fresh, fixed-prompt reviews per model: the original reviewer flagged 4/5, and the stronger reviewer flagged 5/5. This success-selected, post-hoc stability check is not pooled into the adaptive success rates. The result indicates an intermittent original-reviewer miss, not reliable concealment. The retrospective review is not a stronger-attacker versus stronger-reviewer adaptive loop.

Evidence: [strong-attacker summary](results/strong_attacker_v1/summary.json), [cross-review summary](results/cross_review_v1/summary.json), [stability check](results/evasion_recheck_v1/summary.json), [strong simulation audit](results/reaudit/strong_all/simulation_audit.json), and [completion assessment](results/reaudit/completion_assessment.json).

Regenerate and verify these existing results without new API calls:

```sh
.venv/bin/python -m scripts.eval.summarize --run-id strong_attacker_v1
.venv/bin/python -m scripts.eval.verify_results --run-id strong_attacker_v1
.venv/bin/python -m scripts.eval.verify_cross_review --cross-review cross_review_v1
.venv/bin/python scripts/audit_simulations.py --run-id strong_attacker_v1 --source-snapshot results/main_v2/source_snapshot --output results/reaudit/strong_all --skip-ablations
.venv/bin/python scripts/build_report.py --run-id main_v2
```

For a **new paid** attacker replication, use an unused run ID:

```sh
.venv/bin/python -m scripts.eval.run_stronger --config configs/stronger_experiment.json --run-id strong_replication_001
```

`configs/cross_review.json` explicitly chooses source runs and a cross-review run ID. Preserve the recorded configuration and results; change both identifiers for a new investigation. `scripts.eval.recheck_evasions` resumes the saved stability check and is not a new independent repeat under its existing call IDs.

The implementation and the scoped experiments are complete. The expected monotonic evasion trend was not reproduced, and this constrained experiment does not resolve the general question of whether detailed defender feedback benefits analog-Trojan attackers.
