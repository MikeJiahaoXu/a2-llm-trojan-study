# A2 Trojan LLM 專案執行規劃

Oct 30, 2026

## 目標與背景

本專案要在一門課程專案的時間範圍內，建立一個最小可行的「LLM 攻防閉環」，驗證 LLM 在 A2 類比木馬（Analog Trojan）問題上究竟是幫助防禦方，還是反而洩漏線索給攻擊方。

- **防禦端參考**：SPICED（Chaudhuri et al., 2024）——用 LLM 偵測類比/混訊電路中的語法錯誤與木馬特徵，並產生可回饋給設計者的修改建議。
- **攻擊端參考**：LATENT（Chaudhuri et al., 2025）——用 LLM 把木馬插入類比網表拓樸中；論文回報在有回饋的情況下，逃避偵測率可從單輪提示的 23.7% 提升到 94.4%。
- **核心問題**：SPICED 原本設計給設計者用來「找出弱點並改善設計」的回饋，是否也能被攻擊者用來把木馬藏得更好？LLM 在這個問題上到底是解方還是風險放大器？

**範圍限制（讓專案在課程時間內可行）**：

- 用開源 ngspice 取代論文中的 HSPICE 模擬器。
- 只選兩個精簡的 micro-benchmark 電路：2-stage op-amp、4-input AND gate。
- 不重現 SPICED 的語法修復（syntax-fixing）評估。
- 若 LLM 直接生成網表失敗率過高，退而求其次：讓 LLM 只輸出 JSON 參數，套用到已驗證過的電路範本（template）上。
- 若所選電路讓偵測器行為不穩定，保留更換電路的彈性。

## 環境建置（可直接照抄給執行 agent）

建議用容器或虛擬環境隔離，避免污染主機 Python 環境。以下以 Ubuntu 22.04 / Debian 系 Linux 為例（WSL2 亦可）。

### 1. 系統套件

```bash
sudo apt update
sudo apt install -y ngspice ngspice-dev build-essential git python3 python3-venv python3-pip
```

驗證安裝：

```bash
ngspice -v
```

### 2. 專案目錄結構

```
a2-llm-trojan/
├── netlists/
│   ├── templates/        # 已驗證過的乾淨電路範本（op-amp, AND gate）
│   ├── trojan/           # LATENT 產生的含木馬網表
│   └── generated/        # LLM 生成的中間結果（含失敗案例）
├── scripts/
│   ├── attacker/         # LATENT 風格的木馬插入腳本
│   ├── detector/         # SPICED 風格的偵測腳本
│   ├── sim/              # ngspice 模擬封裝（跑 .cir，解析結果）
│   └── eval/             # evasion rate 統計與報表
├── configs/
│   └── prompts/          # 各 feedback 等級（none/binary/full）的 prompt 模板
├── results/               # 每輪實驗的 JSON/CSV 結果
├── requirements.txt
└── README.md
```

### 3. Python 環境

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install openai pyspice numpy pandas matplotlib pytest python-dotenv
```

> 若 `pyspice` 安裝失敗，可改用 subprocess 直接呼叫系統的 `ngspice -b` 批次模式，不透過 Python binding，這樣耦合更低也更容易除錯。

### 4. OpenAI API 金鑰

```bash
cp .env.example .env
# 編輯 .env，填入：
# OPENAI_API_KEY=sk-xxxx
```

程式中一律用 `python-dotenv` 讀取，不把金鑰寫死在程式碼或提交進版本控制（`.env` 要加進 `.gitignore`）。

### 5. 驗證環境可跑通

寫一個最小的「hello world」網表（例如一個簡單 RC 電路），跑一次 `ngspice -b` 並確認能解析出模擬結果，再呼叫一次 OpenAI API 做連線測試。這兩個都過了才開始進入正式開發。

### 6. 版本控制

```bash
git init
git add .
git commit -m "chore: scaffold project structure"
```

建議用 feature branch 對應下面「任務拆解」的各階段（例如 `stage1-env`, `stage2-templates`, `stage3-attacker`, `stage4-detector`, `stage5-eval`）。

## 任務拆解與執行順序

六個階段依序進行，每階段都是一個可以獨立交給 agent 執行的工作包（work package）。每階段完成後才進入下一階段，因為後面階段都依賴前面的輸出。

| 階段 | 任務 | 輸入 | 輸出 | 驗證方式 |
| --- | --- | --- | --- | --- |
| 0. 環境準備 | 依「環境建置」章節建好環境與目錄結構 | 無 | 可執行的專案骨架 + hello-world 模擬通過 | ngspice -v 與 API 連線測試皆成功 |
| 1. 乾淨電路範本 | 手刻 2-stage op-amp、4-input AND gate 的乾淨 ngspice 網表，並確認可模擬出合理波形/真值表 | 電路規格（見下節） | netlists/templates/opamp.cir、netlists/templates/and4.cir | 模擬結果對照手算/教科書預期值（增益、延遲等） |
| 2. Attacker（LATENT 精簡版） | 寫出 LLM 驅動的木馬插入腳本：給定乾淨網表，LLM 輸出插入木馬後的網表或 JSON 參數 | 階段 1 的範本 + LATENT 論文的 prompt 設計 | scripts/attacker/、netlists/trojan/ 下的含木馬網表 | 木馬網表仍可被 ngspice 成功模擬，且木馬效果在特定條件下可觸發 |
| 3. Detector（SPICED 精簡版） | 寫出 LLM 驅動的偵測腳本：輸入網表，輸出是否含木馬與信心分數/理由 | 階段 1、2 的乾淨與含木馬網表 | scripts/detector/ | 偵測器在乾淨網表上低誤報，在已知木馬網表上有基本抓取能力 |
| 4. 攻防迴圈 | 串起 attacker、detector、依 feedback 等級回饋給 attacker 重試，形成可重複執行的閉環 | 階段 2、3 的腳本 | scripts/eval/run\_loop.py，每輪產生結構化紀錄（JSON/CSV） | 跑 10 到 20 輪小規模迴圈不崩潰，紀錄欄位齊全 |
| 5. Feedback 等級實驗 | 針對 none、binary、full 三種 feedback 等級各跑一組迴圈，統計 evasion rate | 階段 4 的迴圈 | results/ 下各等級的統計結果與圖表 | 三組結果可比較，並對照 LATENT 論文的 23.7% 到 94.4% 區間做合理性檢查 |

**給 agent 的指示**：每接到一個階段的任務，先讀本文件的「目標與背景」與「環境建置」取得脈絡，再讀對應章節取得該階段的詳細規格；完成後在對應目錄留下可重現的腳本與一份簡短的執行紀錄（跑了什麼指令、結果摘要），而不是只回報做完了。

## 兩個 Benchmark 電路規格

| 電路 | 規模 | 乾淨版驗證基準 | 木馬插入點（建議） |
| --- | --- | --- | --- |
| 2-stage op-amp | 約 10 到 20 個元件（電晶體、電阻、電容、電流源） | 直流增益、頻寬、相位邊際落在合理範圍（可用標準教科書設計值對照） | 偏壓電流源、補償電容附近，插入會改變增益或穩定度但靜態工作點看起來正常的小型木馬 |
| 4-input AND gate | 約 10 到 15 個元件（CMOS 邏輯閘） | 16 組輸入組合的真值表須與理論一致，上升/下降延遲落在合理範圍 | 在特定稀有輸入組合下才觸發的漏電路徑或延遲異常，模仿 A2 論文中「低活動度觸發」的設計 |

**原則**：兩個電路都要先有一份「乾淨網表」能跑出符合預期的模擬結果，再由 attacker 腳本對這份乾淨網表做修改或生成變體；避免一開始就讓 LLM 從零生成整份網表（失敗率高、除錯困難）。

## Attacker / Detector 腳本設計（最小可行實作）

### Attacker（仿 LATENT）

1. 輸入：乾淨網表 + 木馬插入目標（例如「插入一個在低頻活動度下才觸發的漏電路徑」）。
2. 呼叫 OpenAI API，prompt 包含：電路網表內容、木馬設計限制（例如不能改變靜態工作點太多）、輸出格式要求。
3. 若直接要求 LLM 輸出完整網表失敗率過高，改成要求 LLM 只輸出 JSON 形式的參數（例如插入哪個節點、哪個元件、數值多少），再由固定的 Python 程式碼套用到範本網表上，確保語法一定正確。
4. 輸出含木馬的網表，存進 netlists/trojan/，並記錄這次生成用了哪個 feedback 等級與第幾輪重試。

### Detector（仿 SPICED）

1. 輸入：一份網表（可能乾淨、可能含木馬）。
2. 呼叫 OpenAI API，prompt 包含：網表內容、要求輸出「是否疑似含木馬」「信心分數」「可疑節點/元件」「改善建議」。
3. 為了可比較，固定輸出格式為 JSON（is\_trojan, confidence, suspect\_nodes, feedback\_text）。
4. 這個 detector 的輸出之中的 feedback\_text，就是後續要回饋給 attacker 的素材。

### Feedback 的三種等級（給攻擊迴圈用）

- **none**：attacker 不拿到任何 detector 的回饋，每次都是獨立的單輪生成（對應論文的 one-shot baseline，23.7% 逃避率）。
- **binary**：attacker 只知道「這次被抓到了 / 沒被抓到」，不知道原因。
- **full**：attacker 拿到 detector 完整的 feedback\_text（可疑節點、改善建議），用來修改下一輪的木馬設計。

這三種等級的差異只在「要不要把 detector 的輸出餵回 attacker 的 prompt」，實作上可以共用同一套迴圈程式碼，用一個參數切換。

## Feedback 等級實驗設計

對兩個電路各自、三種 feedback 等級各自，跑固定輪數（例如每組 10 到 20 次嘗試）的攻防迴圈，紀錄每一輪的結果，最後統計 evasion rate（成功騙過 detector 的比例）。

| Feedback 等級 | Attacker 拿到什麼 | 預期對照（LATENT 論文數字） |
| --- | --- | --- |
| none | 無 | 約 23.7%（one-shot baseline） |
| binary | 只有「被抓到/沒被抓到」 | 介於 none 與 full 之間 |
| full | detector 完整 feedback\_text | 約 94.4%（論文最高值） |

每輪紀錄的欄位建議至少包含：電路名稱、feedback 等級、輪次、是否成功逃避偵測、detector 的信心分數、本輪使用的 prompt 版本。最後用 Python/pandas 彙整成表格與長條圖，比較三個等級與論文數字是否在同一量級，並討論差異可能的原因（例如電路規模較小、detector 本身能力不同）。

## 交付物與驗收標準

- [ ] 可執行的程式碼庫（attacker、detector、迴圈、評估腳本），含 README 說明如何重現
- [ ] 兩個電路的乾淨網表範本與驗證結果
- [ ] 三種 feedback 等級、兩個電路共六組實驗的原始紀錄（JSON/CSV）
- [ ] 一份彙整結果的圖表/表格，比較六組 evasion rate
- [ ] 一段討論：LLM 在這個問題上偏向幫助防禦還是幫助攻擊，佐以實驗數據與對照論文數字

驗收標準：每組實驗至少能重現、結果可重新跑出一致趨勢（不要求數字完全相同，但 none < binary < full 的大方向應成立）。

## 風險與備案

| 風險 | 因應方式 |
| --- | --- |
| LLM 直接生成的網表語法錯誤、無法模擬 | 改成 LLM 只輸出 JSON 參數，套用到已驗證範本上（見「環境建置」目錄結構中的 netlists/templates） |
| Detector 在所選電路上表現不穩定（誤報過高或完全抓不到） | 保留更換 benchmark 電路的彈性，或調整 detector prompt 的判斷門檻 |
| ngspice 與論文用的 HSPICE 行為有落差，導致結果不可比 | 在報告中明確標註此為已知限制，聚焦在「相對趨勢」而非「絕對數字」的比較 |
| OpenAI API 呼叫成本或速率限制 | 每組實驗先用小輪數（如 5 輪）試跑，確認流程正確後再跑完整輪數 |
| 時間不夠跑完三種 feedback 等級 × 兩個電路共六組 | 優先完成一個電路的三組 feedback 等級，當作核心結果；第二個電路作為延伸驗證，時間不足可省略 |
