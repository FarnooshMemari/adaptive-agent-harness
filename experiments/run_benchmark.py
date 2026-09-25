"""
experiments/run_benchmark.py — Benchmark runner for strategy comparison research.

Answers the question:
    "Does adaptive strategy selection provide value compared with
     using a fixed collaboration strategy?"

Two modes:

  Default (adaptive):
    Run each alert through the selector-chosen strategy.
    Results written to a single JSONL file.

  --compare-all:
    Run every alert through BOTH panel_strategy and hierarchical_strategy.
    Results for each strategy written to separate JSONL files so
    evaluate.py can compare them side-by-side.
    Also writes a combined file for convenience.

Usage:
    # Adaptive mode — let selector decide
    python experiments/run_benchmark.py --alert data/sample_alerts.json

    # Compare-all mode — run both strategies on every alert
    python experiments/run_benchmark.py --alert data/sample_alerts.json --compare-all

    # Restrict to benchmark alerts only (ALT-013 onward)
    python experiments/run_benchmark.py --alert data/sample_alerts.json \\
        --compare-all --category credential_compromise

    # Custom output directory
    python experiments/run_benchmark.py --alert data/sample_alerts.json \\
        --compare-all --out-dir experiments/results/

Output files (compare-all mode):
    <out-dir>/benchmark_panel.jsonl
    <out-dir>/benchmark_hierarchical.jsonl
    <out-dir>/benchmark_combined.jsonl   ← both strategies interleaved
"""

import argparse
import os
import sys
import time

# Allow running from the project root or from inside experiments/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from harness.alert_loader import Alert, AlertLoader  # noqa: E402
from harness.llm_client import get_llm_client  # noqa: E402
from harness.metrics import MetricsCollector, RunResult  # noqa: E402
from harness.selector import StrategySelector  # noqa: E402
from strategies.hierarchical import HierarchicalStrategy  # noqa: E402
from strategies.panel import PanelStrategy  # noqa: E402


# ─── Constants ────────────────────────────────────────────────────────────────

_PANEL_KEY        = "panel_strategy"
_HIERARCHICAL_KEY = "hierarchical_strategy"

_DEFAULT_OUT_DIR  = "experiments/results"


# ─── Argument parsing ─────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Benchmark runner — adaptive vs. fixed strategy comparison",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Adaptive (selector chooses strategy):\n"
            "  python experiments/run_benchmark.py --alert data/sample_alerts.json\n\n"
            "  # Compare both strategies on every alert:\n"
            "  python experiments/run_benchmark.py --alert data/sample_alerts.json --compare-all\n\n"
            "  # Filter to one incident category:\n"
            "  python experiments/run_benchmark.py --alert data/sample_alerts.json \\\n"
            "      --compare-all --category credential_compromise\n"
        ),
    )
    p.add_argument(
        "--alert", required=True, metavar="PATH",
        help="Path to alert JSON array file.",
    )
    p.add_argument(
        "--compare-all", action="store_true",
        help=(
            "Run every alert through BOTH strategies. "
            "Writes separate JSONL files per strategy plus a combined file."
        ),
    )
    p.add_argument(
        "--category", default=None, metavar="CATEGORY",
        help=(
            "Filter alerts to a specific incident category "
            "(credential_compromise | suspicious_access | "
            "malware_like_behavior | privilege_escalation). "
            "If omitted, all alerts are processed."
        ),
    )
    p.add_argument(
        "--out-dir", default=_DEFAULT_OUT_DIR, metavar="DIR",
        help=f"Output directory for benchmark JSONL files (default: {_DEFAULT_OUT_DIR}).",
    )
    return p


# ─── Strategy helpers ─────────────────────────────────────────────────────────

def _make_strategy(strategy_key: str, alert_id: str):
    client = get_llm_client(alert_id=alert_id, strategy=strategy_key)
    if strategy_key == _PANEL_KEY:
        return PanelStrategy(client)
    return HierarchicalStrategy(client)


def _mitigation_correct(actual: str, expected: str) -> bool:
    actual_lower   = actual.lower()
    expected_lower = expected.lower()
    if expected_lower in actual_lower:
        return True
    phrases = [p.strip() for p in expected_lower.split(",") if p.strip()]
    if not phrases:
        return False
    matches = sum(1 for phrase in phrases if phrase in actual_lower)
    return matches >= max(1, len(phrases) // 2)


# ─── Core run function ────────────────────────────────────────────────────────

def _run_single(
    alert: Alert,
    strategy_key: str,
    rule: str,
    selector: StrategySelector,
    collector: MetricsCollector,
    selector_strategy: str,
) -> RunResult:
    """
    Investigate one alert with one strategy, record metrics, print summary.
    Returns the populated RunResult.
    """
    signals  = selector.compute_signals(alert)
    strategy = _make_strategy(strategy_key, alert.alert_id)

    wall_start = time.perf_counter()
    result     = strategy.investigate(alert)
    wall_secs  = time.perf_counter() - wall_start

    gt = alert.ground_truth
    verdict_correct    = None
    mitigation_correct = None
    gt_verdict         = None
    gt_mitigation      = None
    gt_ev_quality      = None

    if gt:
        gt_verdict         = gt["verdict"]
        gt_mitigation      = gt["expected_mitigation"]
        gt_ev_quality      = gt["evidence_quality"]
        verdict_correct    = result["verdict"] == gt_verdict
        mitigation_correct = _mitigation_correct(result["mitigation_action"], gt_mitigation)

    cost = MetricsCollector.compute_cost(
        result["total_input_tokens"],
        result["total_output_tokens"],
    )

    run_result = RunResult(
        alert_id                    = alert.alert_id,
        strategy                    = strategy_key,
        verdict                     = result["verdict"],
        confidence                  = result["confidence"],
        rationale                   = result["rationale"],
        mitigation_action           = result["mitigation_action"],
        evidence_quality            = result["evidence_quality"],
        total_input_tokens          = result["total_input_tokens"],
        total_output_tokens         = result["total_output_tokens"],
        estimated_cost_usd          = cost,
        latency_seconds             = wall_secs,
        complexity_score            = signals.complexity,
        ambiguity_score             = signals.ambiguity,
        evidence_availability       = signals.evidence_availability,
        selector_rule               = rule,
        ground_truth_verdict        = gt_verdict,
        verdict_correct             = verdict_correct,
        expected_mitigation         = gt_mitigation,
        mitigation_correct          = mitigation_correct,
        ground_truth_evidence_quality = gt_ev_quality,
        selector_strategy           = selector_strategy,
    )

    collector.record(run_result)

    correct_flag = ""
    if verdict_correct is not None:
        correct_flag = " ✓" if verdict_correct else " ✗"
    mit_flag = ""
    if mitigation_correct is not None:
        mit_flag = " mit:✓" if mitigation_correct else " mit:✗"

    strategy_label = strategy_key.replace("_strategy", "")
    category_label = f"[{alert.category}] " if alert.category else ""

    print(
        f"  {category_label}[{alert.alert_id}] {strategy_label} ({rule})"
        f" → {result['verdict']}{correct_flag}"
        f" | conf:{result['confidence']:.2f}"
        f" | ev:{result['evidence_quality']}"
        f"{mit_flag}"
        f" | ${cost:.5f}"
    )

    return run_result


# ─── Adaptive mode ────────────────────────────────────────────────────────────

def _run_adaptive(alerts: list[Alert], out_path: str) -> int:
    """Run each alert through the selector-chosen strategy."""
    selector  = StrategySelector()
    collector = MetricsCollector(output_path=out_path)

    print(f"\n{'─'*60}")
    print(f"Mode     : adaptive (selector chooses strategy)")
    print(f"Alerts   : {len(alerts)}")
    print(f"Output   : {out_path}")
    print(f"Backend  : {config.LLM_BACKEND}")
    print(f"{'─'*60}\n")

    errors = 0
    for alert in alerts:
        try:
            strategy_key, rule = selector.select(alert)
            _run_single(alert, strategy_key, rule, selector, collector, strategy_key)
        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR [{alert.alert_id}]: {exc}", file=sys.stderr)
            errors += 1

    _print_run_summary(len(alerts), errors, out_path)
    return 0 if errors == 0 else 1


# ─── Compare-all mode ─────────────────────────────────────────────────────────

def _run_compare_all(alerts: list[Alert], out_dir: str) -> int:
    """
    Run every alert through both strategies.
    Writes three output files:
        benchmark_panel.jsonl
        benchmark_hierarchical.jsonl
        benchmark_combined.jsonl
    """
    os.makedirs(out_dir, exist_ok=True)

    panel_path    = os.path.join(out_dir, "benchmark_panel.jsonl")
    hier_path     = os.path.join(out_dir, "benchmark_hierarchical.jsonl")
    combined_path = os.path.join(out_dir, "benchmark_combined.jsonl")

    # Clear output files at the start of each benchmark run
    for path in (panel_path, hier_path, combined_path):
        open(path, "w").close()

    panel_collector    = MetricsCollector(output_path=panel_path)
    hier_collector     = MetricsCollector(output_path=hier_path)
    combined_collector = MetricsCollector(output_path=combined_path)

    selector = StrategySelector()

    print(f"\n{'─'*60}")
    print(f"Mode     : compare-all (both strategies on every alert)")
    print(f"Alerts   : {len(alerts)}")
    print(f"Backend  : {config.LLM_BACKEND}")
    print(f"Output   : {out_dir}/")
    print(f"  ├── benchmark_panel.jsonl")
    print(f"  ├── benchmark_hierarchical.jsonl")
    print(f"  └── benchmark_combined.jsonl")
    print(f"{'─'*60}\n")

    errors = 0
    for alert in alerts:
        # Selector's choice is recorded on both runs for selector agreement analysis.
        # It never sees ground_truth; preferred_strategy is used only by evaluate.py.
        try:
            selector_strategy, selector_rule = selector.select(alert)
        except Exception:  # noqa: BLE001
            selector_strategy, selector_rule = None, "error"

        print(f"  [selector → {(selector_strategy or 'error').replace('_strategy','')}]")

        # ── Panel ─────────────────────────────────────────────────────────────
        try:
            panel_rule = selector_rule if selector_strategy == _PANEL_KEY else "forced"
            rr = _run_single(alert, _PANEL_KEY, panel_rule, selector, panel_collector,
                             selector_strategy)
            combined_collector.record(rr)
        except Exception as exc:  # noqa: BLE001
            print(f"    ERROR panel [{alert.alert_id}]: {exc}", file=sys.stderr)
            errors += 1

        # ── Hierarchical ──────────────────────────────────────────────────────
        try:
            hier_rule = selector_rule if selector_strategy == _HIERARCHICAL_KEY else "forced"
            rr = _run_single(alert, _HIERARCHICAL_KEY, hier_rule, selector, hier_collector,
                             selector_strategy)
            combined_collector.record(rr)
        except Exception as exc:  # noqa: BLE001
            print(f"    ERROR hierarchical [{alert.alert_id}]: {exc}", file=sys.stderr)
            errors += 1

        print()

    total_runs = len(alerts) * 2
    _print_run_summary(total_runs, errors, combined_path)
    print(f"  Panel results     → {panel_path}")
    print(f"  Hierarchical      → {hier_path}")
    print(f"  Combined          → {combined_path}")
    print()
    print(f"  Evaluate with:")
    print(f"    python evaluate.py --results {combined_path}")
    print(f"    python evaluate.py --results {panel_path}")
    print(f"    python evaluate.py --results {hier_path}")

    return 0 if errors == 0 else 1


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _print_run_summary(total: int, errors: int, out_path: str) -> None:
    print(f"\n{'─'*60}")
    print(f"Completed: {total - errors}/{total} runs without errors.")
    print(f"Output   : {out_path}")
    print(f"{'─'*60}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = _build_parser()
    args   = parser.parse_args()

    # Load alerts
    try:
        alerts = AlertLoader.load_batch(args.alert)
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR loading alerts: {exc}", file=sys.stderr)
        return 1

    # Optional category filter
    if args.category:
        before = len(alerts)
        alerts = [
            a for a in alerts
            if (a.category or a.type) == args.category
        ]
        print(f"Category filter '{args.category}': {before} → {len(alerts)} alerts")
        if not alerts:
            print("No alerts match this category.", file=sys.stderr)
            return 1

    os.makedirs(args.out_dir, exist_ok=True)

    if args.compare_all:
        return _run_compare_all(alerts, args.out_dir)
    else:
        out_path = os.path.join(args.out_dir, "benchmark_adaptive.jsonl")
        # Clear file at start of run
        open(out_path, "w").close()
        return _run_adaptive(alerts, out_path)


if __name__ == "__main__":
    sys.exit(main())
