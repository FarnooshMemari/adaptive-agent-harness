# Tasks: Adaptive Agent Harness for Cybersecurity Alert Investigation

Organized into 6 phases. Each task is sized for a hackathon — most are 30–90 minutes of focused work. Total estimated effort: ~12–16 hours for a solo developer or a small team over a weekend.

---

## Phase 1: Project Scaffold
*Goal: Runnable skeleton, dependencies installed, AWS connectivity verified.*

### Task 1.1 — Initialize project structure
Create the directory layout and empty files:
```
adaptive-agent-harness/
├── run.py
├── evaluate.py
├── config.py
├── requirements.txt
├── harness/__init__.py
├── harness/alert_loader.py
├── harness/selector.py
├── harness/llm_client.py
├── harness/metrics.py
├── strategies/__init__.py
├── strategies/base.py
├── strategies/panel.py
├── strategies/hierarchical.py
└── data/sample_alerts.json
```
Create `logs/` and add a `.gitkeep`. Add `results.jsonl` to `.gitignore`.

**Done when:** `python run.py --help` exits without import errors.

---

### Task 1.2 — Write `requirements.txt` and `config.py`
**`requirements.txt`:**
```
boto3>=1.34.0
python-dotenv>=1.0.0
tabulate>=0.9.0
```

**`config.py`** should define:
- `BEDROCK_MODEL_ID` (read from env, default `anthropic.claude-3-haiku-20240307-v1:0`)
- `AWS_REGION` (read from env, default `us-east-1`)
- Pricing constants: `HAIKU_INPUT_COST_PER_1K = 0.00025`, `HAIKU_OUTPUT_COST_PER_1K = 0.00125`
- `MAX_TOKENS = 512`
- `TEMPERATURE = 0.0`
- Selector thresholds: `COMPLEXITY_THRESHOLD = 3`, `AMBIGUITY_THRESHOLD = 2`, `EVIDENCE_AVAILABILITY_THRESHOLD = 0.5`

**Done when:** `pip install -r requirements.txt` succeeds and `python -c "import config"` runs cleanly.

---

### Task 1.3 — Verify AWS Bedrock connectivity
Write a throwaway script `check_bedrock.py` that sends a single "hello" prompt to Bedrock and prints the response. Confirm the model ID, IAM permissions, and region are working.

Delete or move to `scripts/` after confirming.

**Done when:** Response text is printed to stdout with no errors.

---

## Phase 2: Core Infrastructure
*Goal: Alert loading, LLM client, and metrics collection all work independently.*

### Task 2.1 — Implement `Alert` dataclass and `AlertLoader`
File: `harness/alert_loader.py`

- Define an `Alert` dataclass with fields matching the schema in `design.md`.
- `AlertLoader.load(path: str) -> Alert` reads a JSON file, validates required fields, raises `ValueError` with a clear message if a field is missing or `type`/`severity` is not in the allowed set.
- Also implement `AlertLoader.load_batch(path: str) -> list[Alert]` for reading a file that contains a JSON array.

**Done when:** Loading `data/sample_alerts.json` (once it exists) returns a list of `Alert` objects without error; loading a malformed file raises a clear `ValueError`.

---

### Task 2.2 — Implement `LLMClient`
File: `harness/llm_client.py`

- Wraps `boto3.client("bedrock-runtime")`.
- `LLMClient.invoke(system: str, user: str) -> LLMResponse` calls `invoke_model` using the Claude Messages API format.
- Returns `LLMResponse(text, input_tokens, output_tokens, latency_ms)`.
- Implements retry with exponential backoff (max 3 attempts) on `ThrottlingException`.
- Logs the full prompt and response to `logs/llm_{timestamp}.log`.

**Done when:** A direct call to `LLMClient().invoke("You are helpful.", "Say hello.")` returns a populated `LLMResponse` and creates a log file.

---

### Task 2.3 — Implement `MetricsCollector`
File: `harness/metrics.py`

- `MetricsCollector.record(result: RunResult)` appends a JSON line to `results.jsonl`, creating the file if needed.
- `MetricsCollector.compute_cost(input_tokens, output_tokens) -> float` applies the pricing constants from `config.py`.
- `RunResult` is a dataclass with all fields from `design.md` section 5, including: `mitigation_action`, `evidence_quality`, selector signals (`complexity_score`, `ambiguity_score`, `evidence_availability`, `selector_rule`), and ground-truth evaluation fields (`verdict_correct`, `mitigation_correct`).

**Done when:** Calling `record()` twice creates a `results.jsonl` with two lines, each valid JSON, containing all fields including the new evidence quality and mitigation fields.

---

## Phase 3: Strategy Selection
*Goal: Harness correctly routes alerts to the right strategy.*

### Task 3.1 — Implement `StrategySelector`
File: `harness/selector.py`

Implement the three signal scores and rule table from `design.md` section 2.2:

- `StrategySelector.compute_signals(alert: Alert) -> dict` returns `{"complexity": int, "ambiguity": int, "evidence_availability": float}`.
  - Complexity: count distinct indicator types in `raw_evidence` using simple regex patterns for IPs (`\d+\.\d+\.\d+\.\d+`), hashes (`[a-f0-9]{32,64}`), domains, user accounts, and process names.
  - Ambiguity: count occurrences of hedging keywords ("possibly", "unclear", "could be", "might", "unconfirmed", "legitimate", "normal") across `description` + `raw_evidence`, capped at 3.
  - Evidence availability: count non-empty fields among `raw_evidence`, `description`, `type`, `severity` divided by 4.
- `StrategySelector.select(alert: Alert) -> tuple[str, str]` returns `(strategy, rule_name)` using the priority-ordered rules from the design.
- Log all three signal scores, the matched rule, and the selected strategy to `logs/selector.log`.

**Done when:** Manually testing alerts that exercise each of the 5 rules produces the expected strategy selection and correct signal values.

---

### Task 3.2 — Implement `Strategy` abstract base class
File: `strategies/base.py`

```python
from abc import ABC, abstractmethod
from harness.alert_loader import Alert

class Strategy(ABC):
    @abstractmethod
    def investigate(self, alert: Alert) -> dict:
        """Returns a result dict with verdict, confidence, rationale, and strategy-specific fields."""
        ...
```

**Done when:** File exists and both concrete strategy classes can import and subclass it without errors.

---

## Phase 4: Implement Strategies
*Goal: Both strategies produce valid investigation results against a real alert.*

### Task 4.1 — Implement `PanelStrategy`
File: `strategies/panel.py`

Follow the flow in `design.md` section 3:

1. **Threat Analyst call**: Independent analysis of the alert from a threat intelligence perspective.
2. **Forensics Analyst call**: Independent analysis of artifacts and timeline from a forensics perspective.
3. **Risk Critic call**: Receives both assessments + alert; challenges weaknesses and rates evidence quality as `low / medium / high`. Returns JSON with `critique`, `unresolved_questions`, and `evidence_quality`.
4. **Consensus Agent call**: Receives all three outputs + alert; returns final JSON verdict with `verdict`, `confidence`, `rationale`, and `mitigation_action`.
5. Parse JSON from Risk Critic and Consensus Agent responses — use a helper that extracts the first JSON block from the response text to handle any extra prose.
6. Accumulate all `LLMResponse` objects; sum tokens and latency.
7. Return result dict matching the output schema in `design.md` section 3.

**Done when:** `PanelStrategy().investigate(alert)` returns a dict with `verdict`, `confidence`, `rationale`, `mitigation_action`, `evidence_quality`, and `assessments` for a sample alert.

---

### Task 4.2 — Implement `HierarchicalStrategy`
File: `strategies/hierarchical.py`

Follow the flow in `design.md` section 4:

1. **Evidence Validator call**: Assess quality of `raw_evidence`. Parse JSON response for `quality`, `gaps`, `reliable`, `notes`.
2. **Lead Investigator decomposition call**: Generate `network_question` and `threat_intel_question` as JSON, passing evidence report as context.
3. **Network Analyst call**: Answer `network_question` given the alert and evidence quality context.
4. **Threat Intel Analyst call**: Answer `threat_intel_question` given the alert and evidence quality context.
5. **Lead Investigator synthesis call**: Receive all findings; return final verdict JSON with `verdict`, `confidence`, `rationale`, and `mitigation_action`.
6. Accumulate tokens and latency across all 5 LLM calls.
7. Return result dict matching the output schema in `design.md` section 4.

**Done when:** `HierarchicalStrategy().investigate(alert)` returns a dict with `verdict`, `confidence`, `rationale`, `mitigation_action`, `evidence_quality`, and `sub_findings` (including `evidence_validation`) for a sample alert.

---

## Phase 5: Harness Wiring & Data
*Goal: End-to-end run works from CLI; sample data ready for demo.*

### Task 5.1 — Write `data/sample_alerts.json`
Create 10 synthetic alerts:
- 5 true positives: one per alert type (`phishing`, `lateral_movement`, `data_exfiltration`, `malware_execution`) + one extra
- 5 false positives: mix of types with benign explanations baked into `raw_evidence`
- Vary complexity, ambiguity, and evidence availability across alerts so the selector exercises all 5 rules across the batch
- Include a `ground_truth` object on each alert with `verdict`, `expected_mitigation`, and `evidence_quality`

Example alert:
```json
{
  "alert_id": "ALT-001",
  "type": "phishing",
  "severity": "high",
  "description": "User clicked link in email from external sender impersonating IT helpdesk.",
  "raw_evidence": "Email headers: From: it-helpdesk@company-support.net (external). Link target: http://185.220.101.47/login. User agent: Chrome/120. Login attempt at 02:14 UTC from geo: Moldova. Hash of attachment: d41d8cd98f00b204e9800998ecf8427e",
  "ground_truth": {
    "verdict": "true_positive",
    "expected_mitigation": "Block sender domain, reset user credentials, isolate endpoint",
    "evidence_quality": "high"
  }
}
```

Design alerts so that:
- At least 3 alerts route to hierarchical (high complexity or critical severity)
- At least 2 alerts route to debate via the ambiguity rule
- At least 1 alert routes to debate via the sparse evidence rule

**Done when:** `AlertLoader.load_batch("data/sample_alerts.json")` returns 10 alerts without errors and the selector distributes them across both strategies.

---

### Task 5.2 — Wire `run.py`
Implement the CLI entry point:

```
python run.py --alert data/sample_alerts.json        # run all alerts
python run.py --alert data/sample_alerts.json --id ALT-001   # run single alert
python run.py --alert data/sample_alerts.json --strategy panel  # force a strategy
```

Logic:
1. Parse args with `argparse`.
2. Load alert(s) via `AlertLoader`.
3. For each alert: run `StrategySelector.compute_signals()` + `select()` (unless `--strategy` is forced), instantiate `PanelStrategy` or `HierarchicalStrategy`, call `investigate()`.
4. Wrap in a timer; collect tokens from the result.
5. Evaluate mitigation correctness by comparing `result["mitigation_action"]` against `alert.ground_truth["expected_mitigation"]` (case-insensitive substring match is sufficient for MVP).
6. Build a `RunResult` (including selector signals and ground-truth evaluation fields) and call `MetricsCollector.record()`.
7. Print a one-line summary per alert: `[ALT-001] panel → true_positive (conf: 0.82) | ev: medium | 1,820 tokens | $0.0026 | 11.4s`

**Done when:** Running `python run.py --alert data/sample_alerts.json --id ALT-001` produces a summary line and appends a complete `RunResult` line to `results.jsonl`.

---

### Task 5.3 — Run all 10 sample alerts
Execute the full batch:
```bash
python run.py --alert data/sample_alerts.json
```
Fix any runtime errors. Note which alerts get routed to each strategy based on selector logic.

**Done when:** All 10 alerts complete, `results.jsonl` has 10 lines, no unhandled exceptions.

---

## Phase 6: Evaluation & Polish
*Goal: Comparison report works; project is demo-ready.*

### Task 6.1 — Implement `evaluate.py`
Read `results.jsonl` and print the three comparison tables from `design.md` section 6:
- **Table 1**: Strategy comparison — count, accuracy, mitigation correctness %, mean tokens, mean cost, mean latency.
- **Table 2**: Evidence quality distribution per strategy — count of low / medium / high ratings.
- **Table 3**: Per-alert detail — alert_id, strategy, verdict, verdict_correct, mitigation_correct, evidence_quality, cost, latency.
- Use `tabulate` for clean table formatting.
- Accuracy and mitigation correctness show `N/A` if ground truth is absent.

**Done when:** `python evaluate.py` prints all three tables with correct aggregated values matching the `results.jsonl` data.

---

### Task 6.2 — Write `README.md`
Cover:
1. What the project does (2–3 sentences)
2. Prerequisites (Python 3.11+, AWS credentials with Bedrock access)
3. Setup: `pip install -r requirements.txt`, set env vars
4. Run: `python run.py --alert data/sample_alerts.json`
5. Evaluate: `python evaluate.py`
6. Brief explanation of the two strategies and the selector logic
7. Sample output (paste the table from a real run)

**Done when:** A teammate unfamiliar with the project can run it end-to-end following only the README.

---

### Task 6.3 — Demo dry-run & cleanup
- Run the full pipeline once from a clean state (delete `results.jsonl`, clear `logs/`).
- Confirm all 10 alerts run, both strategies are exercised, and `evaluate.py` shows results for both.
- Remove any debug `print` statements; confirm log files capture enough detail for replay.
- Verify estimated costs are well under $1.00 total for 10 alerts.

**Done when:** End-to-end demo runs cleanly in under 10 minutes and produces a readable evaluation table.

---

## Task Summary

| Phase | Tasks | Est. Effort |
|---|---|---|
| 1 — Scaffold | 1.1, 1.2, 1.3 | 1 hr |
| 2 — Core Infrastructure | 2.1, 2.2, 2.3 | 2.5 hr |
| 3 — Strategy Selection | 3.1, 3.2 | 1 hr |
| 4 — Strategies | 4.1, 4.2 | 4 hr |
| 5 — Wiring & Data | 5.1, 5.2, 5.3 | 2.5 hr |
| 6 — Evaluation & Polish | 6.1, 6.2, 6.3 | 2 hr |
| **Total** | **13 tasks** | **~13 hr** |

---

## Suggested Team Split (2-person team)

**Person A** — Infrastructure & Harness
- Tasks 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 3.1, 3.2, 5.2

**Person B** — Strategies & Evaluation
- Tasks 4.1, 4.2, 5.1, 5.3, 6.1, 6.2, 6.3

Dependency order: Phase 1 → Phase 2 → Phase 3 & 4 (parallel) → Phase 5 → Phase 6.

> Note: `PanelStrategy` (4.1) and `HierarchicalStrategy` (4.2) are independent of each other and can be developed in parallel once Phase 2 infrastructure is in place.
