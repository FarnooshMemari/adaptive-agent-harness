# Evaluation Methodology and Objective Metrics

## What gets measured

Every investigation run produces a `RunResult` (defined in `harness/metrics.py`) with three categories of measurement:

1. **Accuracy** — did the strategy reach the right verdict and recommend the right mitigation?
2. **Cost** — how many tokens were consumed and what did that cost?
3. **Selector quality** — did the adaptive selector pick the better strategy for each alert?

Results are persisted as one JSON line per run in a `.jsonl` file. The default is `results.jsonl`. Benchmark runs write to `experiments/results/`.

---

## Investigation score

The primary comparison metric is the **investigation score**, a number in [0, 1]:

```
score = 0.7 × verdict_correct + 0.3 × mitigation_correct
```

These weights (`_VERDICT_WEIGHT = 0.7`, `_MITIGATION_WEIGHT = 0.3`) are defined in `evaluate.py`. The verdict accounts for 70% because misclassifying a true positive as benign has higher operational cost than recommending an imprecise mitigation. Do not change these weights without updating the corresponding test in `tests/test_benchmark.py` (`test_score_weights`).

Possible score values:

| Verdict correct | Mitigation correct | Score |
|---|---|---|
| True | True | 1.0 |
| True | False | 0.7 |
| False | True | 0.3 |
| False | False | 0.0 |

`_score()` returns `None` when `verdict_correct` is `None` (i.e., the alert has no `ground_truth`). Never treat `None` as `0.0` — exclude those records from score averages.

---

## Mitigation correctness check

Mitigation is evaluated by `_mitigation_correct()` in `run.py`, which uses a **token-overlap heuristic** rather than exact match:

1. Case-insensitive substring: if `expected_mitigation` appears inside `mitigation_action`, return `True`.
2. Comma-phrase overlap fallback: split `expected_mitigation` on commas, require at least `max(1, n_phrases // 2)` phrases to appear in `mitigation_action`.

This is intentionally loose. LLM paraphrasing is expected when running with Bedrock. Do not tighten this to exact match — it would produce artificially low scores for correct but differently-worded responses.

---

## The five policies in Table 6

`_table6_policy_comparison()` compares five assignment policies on the same set of paired alerts. When working on `evaluate.py`, preserve all five:

| Policy | What it does | Purpose |
|---|---|---|
| `always panel` | Every alert → panel_strategy | Fixed baseline |
| `always hierarchical` | Every alert → hierarchical_strategy | Fixed baseline |
| `adaptive (selector)` | StrategySelector's choice | The system under test |
| `preferred_strategy label` | ground_truth.preferred_strategy | Human expert benchmark |
| `oracle` | Best-scoring strategy per alert | Upper bound (unknowable at inference time) |

The **selector's headroom** is the gap between adaptive and oracle scores. If this gap is small, the selector is near-optimal. If it is large, the selector's rule set has room for improvement.

The `preferred_strategy` label is read from `ground_truth.preferred_strategy` in the alert file — it is enriched onto records by `_enrich_from_alerts()` in `evaluate.py`. The selector **must never read this field** (see `harness/selector.py` — it only calls `compute_signals()` on alert fields, which does not touch `ground_truth`). The test `test_selector_ignores_ground_truth` in `tests/test_benchmark.py` enforces this.

---

## Benchmark modes

### Adaptive mode (default)
```
python experiments/run_benchmark.py --alert data/sample_alerts.json
```
Each alert runs through the selector's chosen strategy. Writes `experiments/results/benchmark_adaptive.jsonl`. Use this to measure the selector's real-world behaviour.

### Compare-all mode
```
python experiments/run_benchmark.py --alert data/sample_alerts.json --compare-all
```
Each alert runs through **both** strategies. Writes three files:
- `benchmark_panel.jsonl` — panel only
- `benchmark_hierarchical.jsonl` — hierarchical only
- `benchmark_combined.jsonl` — both strategies interleaved (80 records for 40 alerts)

Use `benchmark_combined.jsonl` for Tables 4–6, which require paired results. `_paired_alerts()` in `evaluate.py` groups records by `alert_id` and requires both strategies to be present.

---

## Selector agreement (Table 5)

Agreement is measured only on **decisive** alerts — those where one strategy strictly outscored the other. Ties (same score for both) are excluded from the agreement percentage because either choice would have been equally good.

```
agreement % = agreed / decisive_alerts   (ties excluded from denominator)
```

`Sel=Label %` compares the selector's choice against `ground_truth.preferred_strategy`. This is a secondary metric for validating whether the selector's rule-based logic aligns with domain expert intuition.

---

## Category breakdown (Table 4)

The four benchmark categories (`credential_compromise`, `suspicious_access`, `malware_like_behavior`, `privilege_escalation`) are read from `alert.category`. Legacy alerts (ALT-001 to ALT-012) use the original `type` field; `_enrich_from_alerts()` back-fills `category` for records that lack it by reading `data/sample_alerts.json`.

When adding new alerts, assign them to one of the four existing categories. Do not add new categories without updating the category filter in `experiments/run_benchmark.py` and any category-specific logic in `evaluate.py`.

---

## Cost estimation

Cost is computed by `MetricsCollector.compute_cost()` using Claude 3 Haiku pricing as of project creation:

```
cost = (input_tokens / 1000) × 0.00025 + (output_tokens / 1000) × 0.00125
```

Constants `HAIKU_INPUT_COST_PER_1K = 0.00025` and `HAIKU_OUTPUT_COST_PER_1K = 0.00125` live in `config.py`. Update them there if pricing changes. The cost estimate is for benchmark analysis only — it does not affect strategy selection or verdict output.

In mock mode, token counts are estimated from character length (`len(text) // 4`). These are approximate. Actual token counts from Bedrock will differ. Do not use mock-mode costs for production budgeting.
