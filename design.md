# Design: Adaptive Agent Harness for Cybersecurity Alert Investigation

## 1. System Overview

The harness is a Python CLI application. It receives a cybersecurity alert, routes it to one of two multi-agent collaboration strategies, collects the investigation result, and records evaluation metrics. The two strategies — **Debate** and **Hierarchical** — are interchangeable black boxes from the harness's perspective: both accept the same alert input and return the same result schema.

```
                        ┌─────────────────────────────────────────┐
                        │              Harness (run.py)            │
                        │                                          │
  alert.json  ──────►  │  AlertLoader ──► StrategySelector        │
                        │                        │                 │
                        │          ┌─────────────┴──────────────┐  │
                        │          ▼                             ▼  │
                        │   DebateStrategy            HierarchicalStrategy  │
                        │          │                             │  │
                        │          └─────────────┬──────────────┘  │
                        │                        ▼                 │
                        │               MetricsCollector           │
                        │                        │                 │
                        │                        ▼                 │
                        │              results.jsonl + logs/       │
                        └─────────────────────────────────────────┘
```

---

## 2. Component Descriptions

### 2.1 AlertLoader
Reads and validates an alert JSON file. Ensures required fields are present. Returns an `Alert` dataclass.

**Alert schema:**
```json
{
  "alert_id": "string",
  "type": "phishing | lateral_movement | data_exfiltration | malware_execution",
  "severity": "low | medium | high | critical",
  "description": "string",
  "raw_evidence": "string",
  "ground_truth": "true_positive | false_positive"  // optional, for evaluation
}
```

### 2.2 StrategySelector
A lightweight rule-based classifier that scores three signals from the alert and maps the result to a strategy. Signals are computed deterministically from the alert fields — no LLM call required.

**Signal definitions:**

| Signal | How it is computed |
|---|---|
| **Complexity** | Count of distinct indicator types found in `raw_evidence`: IP addresses, file hashes, domain names, user account references, process names. Score = count (0–5). |
| **Ambiguity** | Count of hedging keywords in `description` + `raw_evidence`: "possibly", "unclear", "could be", "might", "unconfirmed", "legitimate", "normal". Score = count capped at 3. |
| **Evidence availability** | Number of non-empty evidence fields present divided by the total number of expected fields (`raw_evidence`, `description`, `type`, `severity`). Score = 0.0–1.0. |

**Selection rules (evaluated top-to-bottom, first match wins):**

| Condition | Strategy | Rationale |
|---|---|---|
| complexity ≥ 3 AND evidence_availability ≥ 0.75 | Hierarchical | Rich, multi-domain evidence benefits from specialist decomposition |
| ambiguity ≥ 2 | Debate | Contradictory signals call for adversarial scrutiny from multiple viewpoints |
| severity == "critical" | Hierarchical | High-stakes alerts warrant thorough structured analysis |
| evidence_availability < 0.5 | Debate | Sparse evidence is better interrogated through adversarial challenge than decomposition |
| All other cases | Debate | Default to the faster, lower-cost strategy |

The selector logs all three signal scores, the matched rule, and the selected strategy to `logs/selector.log`.

### 2.3 LLM Client
A thin wrapper around `boto3` that calls AWS Bedrock's `invoke_model` API. Handles:
- Prompt formatting (Claude Messages API format)
- Token counting from the response metadata
- Retry on throttling (up to 3 attempts with exponential backoff)
- Returning both the text response and usage stats

```python
@dataclass
class LLMResponse:
    text: str
    input_tokens: int
    output_tokens: int
    latency_ms: float
```

Model is configurable via `BEDROCK_MODEL_ID` env var (default: `anthropic.claude-3-haiku-20240307-v1:0`).

---

## 3. Strategy: Debate-Based Collaboration

### Concept
Four specialist agents analyze the alert from different professional angles, then a Consensus Agent synthesizes their perspectives into a final verdict. Unlike a binary prosecutor/defender framing, this structure produces richer analysis: a threat view, a forensic view, and an adversarial challenge, before convergence. It is best suited for ambiguous or evidence-sparse alerts where multiple interpretations are plausible.

### Agents

| Agent | Role | Prompt Focus |
|---|---|---|
| **Threat Analyst** | Independent analysis #1 | Identify threat actor TTPs, match alert to known attack patterns, assess intent |
| **Forensics Analyst** | Independent analysis #2 | Examine artifact integrity, timeline plausibility, indicator authenticity |
| **Risk Critic** | Adversarial challenge | Identify weaknesses in both analyses, flag over-confidence, surface unresolved questions; also rates evidence quality as `low / medium / high` |
| **Consensus Agent** | Synthesizer | Weigh all three inputs, produce final verdict, confidence, rationale, and a recommended mitigation action |

### Flow

```
Alert
  │
  ├──► Threat Analyst ──────────────────────► threat_assessment
  │
  ├──► Forensics Analyst ──────────────────► forensics_assessment
  │
  ├──► Risk Critic (reads both assessments + alert)
  │         ├── challenges weaknesses in each analysis
  │         └── rates evidence quality: low / medium / high
  │                        │
  │                        ▼
  │                  critic_report
  │
  └──► Consensus Agent (reads all three + alert)
             └──► { verdict, confidence, rationale,
                    mitigation_action, evidence_quality }
```

Threat Analyst and Forensics Analyst run independently (sequential for MVP). Risk Critic and Consensus Agent each depend on prior outputs.

### Prompt Structure (Threat Analyst)
```
System: You are a threat intelligence analyst. Analyze the alert below and assess whether
        it represents a genuine attack. Be concise (max 150 words). Identify specific TTPs
        or attack patterns from the evidence.

User: Alert: {alert_json}
      Provide your threat assessment.
```

### Prompt Structure (Risk Critic)
```
System: You are a senior security reviewer. You have received two independent assessments of
        an alert. Your job is to challenge both: identify gaps, over-confident claims, and
        unresolved questions. Also rate the overall evidence quality as low, medium, or high.
        Be concise (max 150 words). Return JSON:
        {"critique": "...", "unresolved_questions": ["..."], "evidence_quality": "low|medium|high"}

User: Alert: {alert_json}
      Threat Analyst assessment: {threat_assessment}
      Forensics Analyst assessment: {forensics_assessment}
```

### Prompt Structure (Consensus Agent)
```
System: You are a SOC lead making a final call on an alert. You have three analyst inputs.
        Weigh them carefully and produce a final verdict. Return JSON only:
        {"verdict": "true_positive|false_positive", "confidence": 0.0,
         "rationale": "...", "mitigation_action": "..."}

User: Alert: {alert_json}
      Threat Analyst: {threat_assessment}
      Forensics Analyst: {forensics_assessment}
      Risk Critic: {critic_report}
```

### Output Schema
```json
{
  "verdict": "true_positive | false_positive",
  "confidence": 0.0,
  "rationale": "string",
  "mitigation_action": "string",
  "evidence_quality": "low | medium | high",
  "assessments": {
    "threat": "string",
    "forensics": "string",
    "critic": "string"
  }
}
```

---

## 4. Strategy: Hierarchical Collaboration

### Concept
A Lead Investigator decomposes the alert into specialized questions and delegates to domain-specific sub-agents. An Evidence Validator runs before any analysis begins to establish a baseline assessment of evidence quality — protecting downstream agents from reasoning confidently on weak or incomplete data. Effective for complex, high-severity alerts where thoroughness and structured decomposition matter more than speed.

### Agents

| Agent | Role | Prompt Focus |
|---|---|---|
| **Lead Investigator** | Orchestrator | Decompose alert into sub-tasks; synthesize all findings into final verdict |
| **Evidence Validator** | Pre-analysis gate | Assess completeness, consistency, and reliability of `raw_evidence`; flag gaps |
| **Network Analyst** | Sub-agent | Analyze IPs, ports, traffic patterns, connection metadata |
| **Threat Intel Analyst** | Sub-agent | Match indicators against known TTPs, threat actors, CVEs |

### Flow

```
Alert
  │
  └──► Lead Investigator
         │  Step 1: "Generate investigation sub-tasks"
         │
         ├──► Evidence Validator (runs first, always)
         │         └──► evidence_report
         │               { quality: low|medium|high, gaps: [...], reliable: bool }
         │
         ├──► Network Analyst (receives alert + evidence_report)
         │         └──► network_finding
         │
         ├──► Threat Intel Analyst (receives alert + evidence_report)
         │         └──► threat_intel_finding
         │
         └──► Lead Investigator
                Step 2: "Synthesize all findings"
                Inputs: evidence_report + network_finding + threat_intel_finding
                │
                └──► { verdict, confidence, rationale,
                       mitigation_action, evidence_quality }
```

Sub-agents run **sequentially** for MVP. Evidence Validator always executes first; its `reliable` flag is passed to downstream agents so they can calibrate their confidence accordingly.

### Prompt Structure (Evidence Validator)
```
System: You are a forensic evidence quality analyst. Assess the raw evidence in the alert
        below for completeness, internal consistency, and reliability. Identify any gaps or
        red flags. Return JSON only:
        {"quality": "low|medium|high", "gaps": ["..."], "reliable": true|false,
         "notes": "..."}

User: Alert: {alert_json}
```

### Prompt Structure (Lead Investigator, decomposition step)
```
System: You are a senior SOC analyst. Given the alert and evidence quality report below,
        generate exactly 2 investigation questions: one about network indicators, one about
        threat intelligence context. Return JSON:
        {"network_question": "...", "threat_intel_question": "..."}

User: Alert: {alert_json}
      Evidence quality report: {evidence_report}
```

### Prompt Structure (Lead Investigator, synthesis step)
```
System: You are a senior SOC analyst making a final determination. Synthesize all findings
        below into a verdict. Account for evidence quality when setting confidence.
        Return JSON only:
        {"verdict": "true_positive|false_positive", "confidence": 0.0,
         "rationale": "...", "mitigation_action": "..."}

User: Alert: {alert_json}
      Evidence report: {evidence_report}
      Network finding: {network_finding}
      Threat intel finding: {threat_intel_finding}
```

### Output Schema
```json
{
  "verdict": "true_positive | false_positive",
  "confidence": 0.0,
  "rationale": "string",
  "mitigation_action": "string",
  "evidence_quality": "low | medium | high",
  "sub_findings": {
    "evidence_validation": "string",
    "network": "string",
    "threat_intel": "string"
  }
}
```

---

## 5. MetricsCollector

Wraps each strategy execution and records:

```python
@dataclass
class RunResult:
    alert_id: str
    strategy: str                   # "debate" | "hierarchical"
    verdict: str                    # "true_positive" | "false_positive"
    confidence: float
    rationale: str
    mitigation_action: str          # recommended action from the strategy
    evidence_quality: str           # "low" | "medium" | "high"
    total_input_tokens: int
    total_output_tokens: int
    estimated_cost_usd: float
    latency_seconds: float
    # Selector signals (for analysis)
    complexity_score: int
    ambiguity_score: int
    evidence_availability: float
    selector_rule: str              # which rule fired
    # Ground-truth evaluation (populated if ground_truth present in alert)
    ground_truth_verdict: str | None
    verdict_correct: bool | None
    expected_mitigation: str | None
    mitigation_correct: bool | None  # True if action matches expected_mitigation
    ground_truth_evidence_quality: str | None
```

Cost is calculated using published Bedrock pricing constants stored in `config.py`. Results are appended to `results.jsonl`.

---

## 6. Evaluation Script (`evaluate.py`)

Reads `results.jsonl` and prints three tables:

**Table 1 — Strategy comparison (core metrics):**
```
Strategy       | Alerts | Accuracy | Mitigation OK | Avg Tokens | Avg Cost ($) | Avg Latency (s)
---------------|--------|----------|---------------|------------|--------------|----------------
debate         |     5  |   80.0%  |        60.0%  |      1,820 |       0.0026 |          11.4
hierarchical   |     5  |   90.0%  |        80.0%  |      2,640 |       0.0041 |          17.2
```

**Table 2 — Evidence quality distribution per strategy:**
```
Strategy       | Low | Medium | High
---------------|-----|--------|-----
debate         |   1 |      3 |   1
hierarchical   |   0 |      2 |   3
```

**Table 3 — Per-alert detail:**
```
Alert ID  | Strategy      | Verdict        | Correct | Mitigation OK | Ev. Quality | Cost ($) | Latency (s)
----------|---------------|----------------|---------|---------------|-------------|----------|------------
ALT-001   | debate        | true_positive  | ✓       | ✓             | medium      |   0.0024 |        10.1
...
```

Accuracy and mitigation correctness columns show `N/A` if ground truth is not present.

---

## 7. Project Structure

```
adaptive-agent-harness/
├── run.py                  # CLI entry point
├── evaluate.py             # Metrics comparison script
├── config.py               # Model IDs, pricing constants, thresholds
├── requirements.txt
│
├── harness/
│   ├── __init__.py
│   ├── alert_loader.py     # AlertLoader + Alert dataclass
│   ├── selector.py         # StrategySelector (complexity/ambiguity/evidence signals)
│   ├── llm_client.py       # Bedrock wrapper + LLMResponse
│   └── metrics.py          # MetricsCollector + RunResult
│
├── strategies/
│   ├── __init__.py
│   ├── base.py             # Abstract Strategy base class
│   ├── panel.py            # PanelStrategy (Threat Analyst, Forensics Analyst,
│   │                       #   Risk Critic, Consensus Agent)
│   └── hierarchical.py     # HierarchicalStrategy (Lead Investigator,
│                           #   Evidence Validator, Network Analyst, Threat Intel Analyst)
│
├── data/
│   └── sample_alerts.json  # 10 synthetic alerts with ground_truth object
│
├── logs/                   # Per-run agent logs (auto-created)
└── results.jsonl           # Accumulated run results (auto-created)
```

---

## 8. Key Design Decisions

**Why rule-based selector with complexity/ambiguity/evidence signals?**  
These three signals are computable directly from the alert fields with zero LLM calls — no added cost or latency. They also map intuitively to the strengths of each strategy: hierarchical excels when there is rich, decomposable evidence; debate excels when the picture is ambiguous and needs adversarial scrutiny. Severity is still used as a fallback but is no longer the primary criterion, since a low-severity alert can still be highly ambiguous.

**Why replace Prosecutor/Defender/Judge with a four-agent panel?**  
Prosecutor/Defender forces a binary framing from the start, which can cause agents to argue past each other rather than actually analyze the evidence. The new panel (Threat Analyst + Forensics Analyst + Risk Critic + Consensus Agent) gives each agent a genuine analytical role rather than a predetermined conclusion. The Risk Critic as a separate adversarial step keeps the pressure without distorting the analysts' initial assessments. This also naturally produces an evidence quality rating as a by-product of the critic's job.

**Why Evidence Validator as a dedicated first step in hierarchical?**  
Downstream sub-agents have no way to know whether the evidence they are analyzing is reliable or sparse. Without a validation step, a confident-sounding network or threat intel finding built on incomplete evidence can mislead the synthesizer. Running Evidence Validator first gives every subsequent agent a calibrated baseline and feeds its quality score directly into the final `RunResult`.

**Why sequential sub-agents in hierarchical?**  
Parallel async calls add implementation complexity (asyncio, error handling, partial failures) that isn't justified at demo scale with 3 sub-agents. Sequential is simpler and still demonstrates the delegation pattern clearly.

**Why Claude Haiku as default?**  
Haiku is ~15x cheaper than Claude 3 Sonnet and fast enough for demo use. The panel strategy adds one extra LLM call and the hierarchical strategy adds two (Evidence Validator + synthesis update), so keeping token budgets tight via concise prompts remains important. Sonnet is available as an upgrade via config.

**Why JSONL for results?**  
Simple, append-friendly, readable without tooling, and trivially parseable by pandas or plain Python for the evaluation script. The expanded `RunResult` fields (selector signals, mitigation, evidence quality) serialize cleanly to JSON without schema changes.
