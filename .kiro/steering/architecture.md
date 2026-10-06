# Project Architecture and Coding Conventions

## What this project does

This is a research harness that investigates cybersecurity alerts using two competing multi-agent collaboration strategies — **panel** and **hierarchical** — and adaptively routes each alert to the most appropriate strategy based on computed signals. The research goal is to measure whether adaptive selection produces better outcomes than either fixed strategy alone.

## Directory layout

```
adaptive-agent-harness/
├── run.py                        # CLI entry point: python run.py --alert data/sample_alerts.json
├── evaluate.py                   # 6-table evaluation report
├── config.py                     # All constants and env-var config — edit thresholds here
├── harness/
│   ├── alert_loader.py           # Alert dataclass + AlertLoader — sole source of truth for input schema
│   ├── selector.py               # StrategySelector — rule-based routing, no LLM call
│   ├── llm_client.py             # BaseLLMClient ABC + MockLLMClient + BedrockLLMClient + factory
│   └── metrics.py                # RunResult dataclass + MetricsCollector (appends to JSONL)
├── strategies/
│   ├── base.py                   # Strategy ABC + extract_json() shared utility
│   ├── panel.py                  # PanelStrategy — 4-agent panel
│   └── hierarchical.py           # HierarchicalStrategy — 5-agent hierarchy
├── experiments/
│   └── run_benchmark.py          # Benchmark runner — adaptive mode and --compare-all mode
├── data/
│   ├── sample_alerts.json        # 40 labelled alerts across 4 benchmark categories
│   └── mock_responses.json       # Alert-keyed canned responses for MockLLMClient
├── tests/
│   └── test_benchmark.py         # pytest test suite — run with: python -m pytest tests/
└── scripts/
    └── check_bedrock.py          # One-shot Bedrock connectivity verification
```

## Layer boundaries — strictly enforced

1. **`harness/` knows nothing about strategies.** Alert loading, signal computation, LLM invocation, and metrics recording are all strategy-agnostic.
2. **`strategies/` depend only on `harness/`.** `PanelStrategy` and `HierarchicalStrategy` receive a `BaseLLMClient` — they never call `get_llm_client()` or reference `MockLLMClient` / `BedrockLLMClient` directly.
3. **`config.py` is the only place for constants.** Do not hardcode thresholds, model IDs, pricing, or file paths anywhere else. All are read via `import config`.
4. **`run.py` and `evaluate.py` are the only entry points.** No module should print to stdout except through those two scripts.

## Python conventions

- **Python 3.9 compatible.** The system Python on this machine is 3.9.6. Do not use `str | None` union syntax, `match/case`, or any 3.10+ feature. Use `Optional[str]` from `typing` instead.
- **Dataclasses for data, ABCs for contracts.** `Alert`, `Signals`, `LLMResponse`, `RunResult` are all `@dataclass`. `Strategy` and `BaseLLMClient` are ABCs.
- **Enums as string literals, validated at load time.** Allowed values for `type`, `severity`, `verdict`, `evidence_quality`, and `strategy` are validated in `AlertLoader._parse()` and `AlertLoader._check_ground_truth()`. New values must be added to the relevant `VALID_*` constant in `alert_loader.py` as well as `config.py` if they affect selector thresholds.
- **`typing.Optional` not `| None`.** Always `Optional[str]`, not `str | None`.
- **No new top-level dependencies** without updating `requirements.txt`. Current deps: `boto3>=1.34.0`, `python-dotenv>=1.0.0`, `tabulate>=0.9.0`, `pytest`.

## Adding a third strategy

1. Create `strategies/newstrat.py` subclassing `Strategy` from `strategies/base.py`.
2. Add `"newstrat_strategy"` to `VALID_STRATEGIES` in `harness/alert_loader.py`.
3. Add a routing rule in `harness/selector.py` `_apply_rules()`.
4. Add `"newstrat"` to `_CLI_TO_KEY` in `run.py` and `experiments/run_benchmark.py`.
5. Add mock responses under a new strategy key in `data/mock_responses.json`.

## File naming conventions

- Strategy internal keys (stored in `RunResult.strategy`): `panel_strategy`, `hierarchical_strategy` — always with `_strategy` suffix.
- CLI argument values: `panel`, `hierarchical` — no suffix; translated via `_CLI_TO_KEY`.
- Benchmark output files: `benchmark_panel.jsonl`, `benchmark_hierarchical.jsonl`, `benchmark_combined.jsonl` in `experiments/results/`.
