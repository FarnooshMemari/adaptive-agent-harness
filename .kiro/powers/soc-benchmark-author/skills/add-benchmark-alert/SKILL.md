---
name: add-benchmark-alert
description: Add or edit a labelled security alert in the Adaptive Agent Harness benchmark, write matching deterministic mock responses for both strategies, and validate the dataset before re-running the benchmark.
---

# Add a benchmark alert

The benchmark is two files that must stay in lockstep:

- `data/sample_alerts.json` — labelled alerts (JSON array)
- `data/mock_responses.json` — canned output for every agent role, per alert, per strategy (used when `LLM_BACKEND=mock`)

A missing role does not crash a run: `MockLLMClient` returns a `[mock] No response defined...` placeholder and the alert silently scores wrong. Always finish with the validator in Step 4.

## Step 1: Pick the id and category

- Next id is one past the highest `ALT-NNN` in `data/sample_alerts.json`.
- `category` (and `type`) must be one of `credential_compromise`, `suspicious_access`, `malware_like_behavior`, `privilege_escalation`.
- Run the validator first (Step 4) and read its category table; prefer the category, verdict, or `preferred_strategy` that is under-represented.

## Step 2: Write the alert

Append an object to `data/sample_alerts.json`:

```json
{
  "alert_id": "ALT-041",
  "title": "Short human-readable title",
  "type": "privilege_escalation",
  "category": "privilege_escalation",
  "severity": "low | medium | high | critical",
  "description": "What was observed.",
  "raw_evidence": "Logs, process chains, IPs, hashes, timestamps.",
  "context": "Operational context NOT in raw_evidence (role, change tickets, business facts).",
  "indicators": "Key IOCs / behavioural indicators, comma-separated",
  "ground_truth": {
    "verdict": "true_positive | false_positive",
    "expected_mitigation": "Comma-separated actions, e.g. Revoke admin rights, reset credentials",
    "evidence_quality": "low | medium | high",
    "preferred_strategy": "panel_strategy | hierarchical_strategy"
  }
}
```

Rules:
- `raw_evidence` drives the selector's complexity/evidence signals; `context` is where insider, identity, and change-management facts belong. Hierarchical tends to miss `context`-only facts; panel's Risk Critic can argue real threats down.
- `preferred_strategy` is for analysis only. Never reference it from `harness/selector.py` (`test_selector_ignores_ground_truth` enforces this).
- `expected_mitigation` is matched loosely: the run counts as correct if at least half of its comma-separated phrases (minimum 1) appear in the strategy's `mitigation_action`.

## Step 3: Write the mock responses

Add an entry keyed by the same `alert_id` to `data/mock_responses.json`. Start with a `_note` describing the intended outcome, e.g. `"privilege_escalation | TP | preferred=panel. Hierarchical misses the change ticket context."`

| Strategy | Role | Format |
|---|---|---|
| `panel_strategy` | `threat_assessment`, `forensics_assessment` | free text |
| | `critic_report` | JSON string: `critique`, `unresolved_questions`, `evidence_quality` |
| | `consensus` | JSON string: `verdict`, `confidence` (0–1), `rationale`, `mitigation_action` |
| `hierarchical_strategy` | `evidence_validation` | JSON string: `quality`, `gaps`, `reliable`, `notes` |
| | `decomposition` | JSON string: `network_question`, `threat_intel_question` |
| | `network_finding`, `threat_intel_finding` | free text |
| | `synthesis` | JSON string: `verdict`, `confidence` (0–1), `rationale`, `mitigation_action` |

Copy an existing entry of the same category as a template. Keep outcomes realistic and imperfect, following the failure modes in the `_comment` at the top of the file, so that the strategy named in `preferred_strategy` scores at least as high as the other one.

## Step 4: Validate

From the repository root:

```bash
python .kiro/powers/soc-benchmark-author/skills/add-benchmark-alert/scripts/validate_benchmark.py --alert-id ALT-041
```

It uses the project's own `AlertLoader`, `extract_json`, and mitigation matcher, and reports:
- schema errors, duplicate ids, missing/orphan mock entries, missing roles or JSON keys, bad enums, and confidence outside [0, 1]
- the predicted verdict/mitigation correctness and score (`0.7 × verdict + 0.3 × mitigation`) for each strategy on the chosen alert
- an error when the mocks make the non-preferred strategy win
- a per-category balance table (TP/FP, preferred strategy, decisive alerts)

Fix every reported problem before continuing. Exit code 0 means the dataset is valid.

## Step 5: Re-run and test

```bash
python -m pytest tests/ -q
python experiments/run_benchmark.py --alert data/sample_alerts.json --compare-all
python evaluate.py --results experiments/results/benchmark_combined.jsonl
```

If the `harness` MCP server is enabled, use `get_alert` to inspect the new alert and `query_results` to check selector agreement on its category. Commit the alert, its mocks, and the regenerated `experiments/results/*.jsonl` together.
