# Requirements: Adaptive Agent Harness for Cybersecurity Alert Investigation

## Overview

A research harness that investigates cybersecurity alerts using two multi-agent collaboration strategies — **debate-based** and **hierarchical** — and adaptively selects the appropriate strategy based on incident complexity, ambiguity, and evidence availability. The system captures accuracy, cost, latency, evidence quality, and mitigation correctness metrics for each run to support comparison.

---

## Functional Requirements

### FR-1: Alert Ingestion
- The system shall accept cybersecurity alerts as structured JSON input.
- Each alert shall include at minimum: `alert_id`, `type`, `severity`, `description`, and `raw_evidence` fields.
- The system shall support a small set of alert types for MVP: `phishing`, `lateral_movement`, `data_exfiltration`, and `malware_execution`.

### FR-2: Strategy Selection (Harness)
- The harness shall classify each incoming alert and select either the debate-based or hierarchical strategy.
- Selection criteria shall be based on three computed signal scores derived from the alert:
  - **Complexity score**: number of distinct indicator types present in `raw_evidence` (IPs, hashes, domains, user accounts, processes).
  - **Ambiguity score**: presence of contradictory or inconclusive signals (flagged by keywords such as "possibly", "unclear", "could be", "legitimate").
  - **Evidence availability score**: ratio of populated evidence fields to total expected fields.
- The harness shall log which strategy was selected, the three signal scores, and the matched rule.

### FR-3: Debate-Based Collaboration Strategy
- Four agents shall be instantiated: **Threat Analyst**, **Forensics Analyst**, **Risk Critic**, and **Consensus Agent**.
- The Threat Analyst and Forensics Analyst shall each independently analyze the alert and produce an initial assessment.
- The Risk Critic shall challenge both assessments, identify weaknesses, and surface unresolved questions.
- The Consensus Agent shall synthesize all three inputs and produce a final verdict.
- The final output shall include: verdict (true positive / false positive), confidence score, a brief rationale, and a recommended mitigation action.

### FR-4: Hierarchical Collaboration Strategy
- A **Lead Investigator** agent shall decompose the alert into sub-tasks and delegate to specialized sub-agents.
- An **Evidence Validator** sub-agent shall run first and assess the quality, completeness, and reliability of the raw evidence before any analytical sub-agents are invoked.
- Analytical sub-agents shall cover at least two specializations for MVP: **Network Analyst** and **Threat Intel Analyst**.
- The Lead Investigator shall synthesize all sub-agent findings — including the Evidence Validator's quality assessment — into a final report.
- The final output shall match the same schema as the debate strategy output (verdict, confidence, rationale, mitigation action).

### FR-5: Evaluation & Metrics
- The harness shall record for every alert run:
  - Strategy used
  - Verdict and confidence
  - Total LLM token usage (input + output)
  - Wall-clock latency (seconds)
  - Estimated cost (USD, based on model pricing)
  - **Evidence quality score**: the Evidence Validator's rating (hierarchical) or the Risk Critic's assessment of evidence sufficiency (debate), expressed as `low / medium / high`.
  - **Mitigation correctness**: whether the recommended mitigation action matches the expected action in the alert's ground-truth record, expressed as `correct / incorrect / n/a`.
- Results shall be written to a local `results.jsonl` file, one JSON object per line.

### FR-6: Comparison Report
- The system shall include a script that reads `results.jsonl` and prints a summary table comparing the two strategies across all metrics.
- If ground-truth labels are provided in the alert file, the script shall also compute accuracy and mitigation correctness per strategy.
- The script shall display evidence quality distribution (low / medium / high counts) per strategy.

### FR-7: Sample Alert Dataset
- The project shall ship with at least 10 synthetic alerts (5 true positives, 5 false positives) covering the supported alert types, for immediate demo use.
- Each alert shall include a `ground_truth` object with: `verdict`, `expected_mitigation` (a short action string), and `evidence_quality` (low / medium / high) to support all evaluation metrics.

---

## Non-Functional Requirements

### NFR-1: LLM Backend
- The system shall use AWS Bedrock as the primary LLM provider (Claude 3 Sonnet or Haiku for cost control).
- Model IDs shall be configurable via environment variables or a config file; no hard-coding.

### NFR-2: Cost Control
- Each individual alert investigation shall not exceed $0.10 in estimated LLM cost.
- Token budgets shall be enforced via prompt design (concise prompts, limited context windows).

### NFR-3: Latency
- Each investigation run shall complete within 60 seconds under normal conditions.

### NFR-4: Reproducibility
- A `seed` or `temperature=0` setting shall be used where supported so runs are deterministic for demo purposes.

### NFR-5: Simplicity
- The harness shall be runnable with a single CLI command: `python run.py --alert <file>`.
- Dependencies shall be limited to what can be installed via `pip install -r requirements.txt`.
- No external databases, message queues, or persistent services required.

### NFR-6: Observability
- All agent prompts and responses shall be logged to a local `logs/` directory for debugging and demo replay.

---

## Out of Scope (MVP)

- Real-time streaming alert ingestion (SIEM integration)
- More than two collaboration strategies
- Authentication or multi-user access
- Fine-tuned or custom models
- Automated remediation actions
- Production deployment or containerization
