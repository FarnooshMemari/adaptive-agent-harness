# adaptive-agent-harness

An AI security investigation assistant that uses adaptive multi-agent orchestration to analyze security alerts, evaluate reasoning strategies, and generate evidence-based incident reports.

Two multi-agent strategies investigate each alert: a **panel** of peers and a **hierarchy** with a coordinator. A rule-based selector routes each alert to the strategy most likely to get it right. The benchmark measures whether adaptive routing beats either fixed strategy.

## Architecture

```
alert JSON ─► AlertLoader ─► StrategySelector ─► PanelStrategy | HierarchicalStrategy ─► RunResult (JSONL) ─► evaluate.py
                              (signals + rules,      │                                     │
                               no LLM call)          └── BaseLLMClient: Mock | Amazon Bedrock
```

| Component | Path | Role |
|---|---|---|
| Alert schema | `harness/alert_loader.py` | Validates and loads labelled alerts |
| Selector | `harness/selector.py` | Computes complexity, ambiguity, and evidence-availability signals. Applies 5 priority rules. Never reads ground truth. |
| Panel strategy | `strategies/panel.py` | Threat analyst + forensic analyst → risk critic → SOC lead consensus |
| Hierarchical strategy | `strategies/hierarchical.py` | Evidence validator → decomposition → network and threat-intel investigators → synthesis |
| LLM backend | `harness/llm_client.py` | `mock`: deterministic, no credentials needed. `bedrock`: Claude on Amazon Bedrock. |
| Metrics | `harness/metrics.py` | Records verdict, mitigation, tokens, cost, latency, and selector signals for each run |
| Benchmark | `experiments/run_benchmark.py`, `evaluate.py` | Runs alerts through both strategies and prints 6 comparison tables |
| Dataset | `data/sample_alerts.json`, `data/mock_responses.json` | 40 labelled alerts in 4 categories, with mock responses for every agent role |

Thresholds, model ID, and pricing are in `config.py`.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate   # Python 3.10+ (needed by the MCP server)
pip install -r requirements.txt
cp .env.example .env                                  # LLM_BACKEND=mock by default
```

To use live Bedrock, set `LLM_BACKEND=bedrock` and your AWS credentials in `.env`, then run `python scripts/check_bedrock.py`.

## Run

```bash
# Single investigation with adaptive routing (or --strategy panel|hierarchical)
python run.py --alert data/sample_alerts.json --id ALT-001

# Full benchmark: every alert through both strategies
python experiments/run_benchmark.py --alert data/sample_alerts.json --compare-all

# Evaluation report (6 tables)
python evaluate.py --results experiments/results/benchmark_combined.jsonl
```

## Interactive demo

```bash
python demo/server.py          # then open http://localhost:8000  (--port to change)
```

1. Pick an alert, either from the four featured cards or from the dropdown of all 40.
2. Click **Run analysis**. Both teams investigate live: the Debate Team (panel) and the Hierarchical Team. Click any finished agent to see its full output.
3. Each team's decision is graded against the answer key.
4. **Why this strategy?** shows the selector's signals and rules, with the first matching rule highlighted.
5. **Selected strategy** shows the chosen team's metrics and whether it was the better choice.
6. **Benchmark** shows real numbers from `experiments/results/benchmark_combined.jsonl`.

The demo calls the real `StrategySelector`, `PanelStrategy`, and `HierarchicalStrategy`, and computes benchmark numbers with `evaluate.py`'s helpers. It uses `LLM_BACKEND` from `.env` (default `mock`), so no AWS credentials are needed. It needs nothing beyond `requirements.txt`, and there's no build step.

## Tests

```bash
python -m pytest tests/ -q
```

This runs 24 tests: the benchmark, selector, and mock-routing tests in `tests/test_benchmark.py`, plus the Hypothesis property tests in `tests/test_properties.py`.

## Benchmark results

These results come from 40 alerts × 2 strategies on the mock backend (`experiments/results/benchmark_combined.jsonl`).

| Policy | Verdict accuracy | Mitigation OK | Avg score |
|---|---|---|---|
| Always panel | 85.0% | 50.0% | 0.745 |
| Always hierarchical | 70.0% | 62.5% | 0.677 |
| **Adaptive selector** | **87.5%** | **77.5%** | **0.845** |
| Oracle (best per alert) | 97.5% | 97.5% | 0.975 |

Score = 0.7 × verdict correct + 0.3 × mitigation correct.

The adaptive selector beats both fixed strategies. It picked the better strategy on 75.8% of decisive alerts (25/33), and the remaining gap to the oracle is headroom for improving the selector. Panel scores better on suspicious access, and hierarchical scores better on privilege escalation.

## Kiro features used

| Kiro lesson | Where |
|---|---|
| Spec-driven development | `.kiro/specs/adaptive-agent-harness/` (`requirements.md`, `design.md`, `tasks.md`) |
| Steering | `.kiro/steering/`: `architecture.md`, `agent-prompts.md`, `evaluation.md`, `llm-backend.md` |
| Hooks | `.kiro/hooks/test-on-source-save.json` runs tests when files in `harness/` or `strategies/` are saved. `.kiro/hooks/validate-after-task.json` runs the tests and checks that alerts and mocks are in sync after each spec task. |
| Property-based testing | `tests/test_properties.py` (Hypothesis): signal ranges, selector validity and determinism, scoring invariants |
| Custom agents | `.kiro/agents/`: `threat-analyst.json`, `evidence-reviewer.json`, `evaluation-reviewer.json` |
| MCP | `.kiro/settings/mcp.json` registers `scripts/harness_mcp_server.py`, which provides the `list_alerts`, `get_alert`, `query_results`, and `get_strategy_summary` tools |
| Powers | `.kiro/powers/soc-benchmark-author/`: a Power with a `plugin.json` manifest and an `add-benchmark-alert` skill for extending the benchmark safely. Its `scripts/validate_benchmark.py` checks alert and mock consistency and predicts each strategy's score. To install it, open Kiro → Powers → Add Custom Power → Import from folder. |

Kiro starts the MCP server with `python3` from your `PATH`. Open Kiro from a shell where the venv is activated, or make sure `python3` is 3.10+ and has `requirements.txt` installed.
