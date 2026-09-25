"""
run.py — CLI entry point for the Adaptive Agent Harness.

Usage:
    python run.py --alert data/sample_alerts.json           # run all alerts
    python run.py --alert data/sample_alerts.json --id ALT-001       # single alert
    python run.py --alert data/sample_alerts.json --strategy panel   # force strategy
    python run.py --alert data/sample_alerts.json --strategy hierarchical

Strategies:
    panel        → PanelStrategy      (Threat Analyst, Forensics Analyst,
                                        Risk Critic, Consensus Agent)
    hierarchical → HierarchicalStrategy (Evidence Validator, Lead Investigator,
                                         Network Analyst, Threat Intel Analyst)

Results are appended to results.jsonl (one JSON object per line).
"""

import argparse
import sys
import time
from typing import Optional

import config
from harness.alert_loader import Alert, AlertLoader
from harness.llm_client import get_llm_client
from harness.metrics import MetricsCollector, RunResult
from harness.selector import StrategySelector
from strategies.hierarchical import HierarchicalStrategy
from strategies.panel import PanelStrategy


# ─── Constants ────────────────────────────────────────────────────────────────

# Internal strategy names stored in RunResult / results.jsonl
_PANEL_KEY        = "panel_strategy"
_HIERARCHICAL_KEY = "hierarchical_strategy"

# CLI argument values accepted for --strategy
_CLI_TO_KEY = {
    "panel":        _PANEL_KEY,
    "hierarchical": _HIERARCHICAL_KEY,
}


# ─── Argument parsing ─────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Adaptive Agent Harness — Cybersecurity Alert Investigation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python run.py --alert data/sample_alerts.json\n"
            "  python run.py --alert data/sample_alerts.json --id ALT-001\n"
            "  python run.py --alert data/sample_alerts.json --strategy hierarchical\n"
        ),
    )
    p.add_argument(
        "--alert", required=True, metavar="PATH",
        help="Path to alert JSON file (single object or array).",
    )
    p.add_argument(
        "--id", dest="alert_id", default=None, metavar="ALERT_ID",
        help="Run only the alert with this ID (requires --alert to be an array file).",
    )
    p.add_argument(
        "--strategy", choices=list(_CLI_TO_KEY.keys()), default=None,
        help="Force a specific strategy instead of using the adaptive selector.",
    )
    return p


# ─── Strategy instantiation ───────────────────────────────────────────────────

def _make_strategy(strategy_key: str, alert_id: str):
    """Instantiate the correct strategy class with a pre-configured LLM client."""
    client = get_llm_client(alert_id=alert_id, strategy=strategy_key)
    if strategy_key == _PANEL_KEY:
        return PanelStrategy(client)
    return HierarchicalStrategy(client)


# ─── Mitigation correctness ───────────────────────────────────────────────────

def _mitigation_correct(actual: str, expected: str) -> bool:
    """
    Case-insensitive substring check: is the expected mitigation mentioned
    in the actual mitigation action?

    Uses token overlap: if any comma-separated phrase from expected appears
    in actual (after lowercasing), the mitigation is considered correct.
    This is deliberately loose — exact wording varies between LLM runs.
    """
    actual_lower   = actual.lower()
    expected_lower = expected.lower()

    # Direct substring match
    if expected_lower in actual_lower:
        return True

    # Token overlap: at least half of the expected phrases appear in actual
    phrases = [p.strip() for p in expected_lower.split(",") if p.strip()]
    if not phrases:
        return False
    matches = sum(1 for phrase in phrases if phrase in actual_lower)
    return matches >= max(1, len(phrases) // 2)


# ─── Single-alert runner ──────────────────────────────────────────────────────

def _run_alert(
    alert: Alert,
    forced_strategy: str | None,
    selector: StrategySelector,
    collector: MetricsCollector,
) -> RunResult:
    """Investigate one alert, record metrics, print summary line."""

    # ── Select strategy ───────────────────────────────────────────────────────
    signals = selector.compute_signals(alert)

    if forced_strategy:
        strategy_key = _CLI_TO_KEY[forced_strategy]
        rule         = "forced"
    else:
        strategy_key, rule = selector.select(alert)

    # ── Investigate ───────────────────────────────────────────────────────────
    strategy = _make_strategy(strategy_key, alert.alert_id)

    wall_start = time.perf_counter()
    result     = strategy.investigate(alert)
    wall_secs  = time.perf_counter() - wall_start

    # ── Ground-truth evaluation ───────────────────────────────────────────────
    gt = alert.ground_truth   # may be None

    verdict_correct    = None
    mitigation_correct = None
    gt_verdict         = None
    gt_mitigation      = None
    gt_evidence_quality = None

    if gt:
        gt_verdict          = gt["verdict"]
        gt_mitigation       = gt["expected_mitigation"]
        gt_evidence_quality = gt["evidence_quality"]
        verdict_correct     = result["verdict"] == gt_verdict
        mitigation_correct  = _mitigation_correct(
            result["mitigation_action"], gt_mitigation
        )

    # ── Cost ──────────────────────────────────────────────────────────────────
    cost = MetricsCollector.compute_cost(
        result["total_input_tokens"],
        result["total_output_tokens"],
    )

    # ── Build RunResult ───────────────────────────────────────────────────────
    run_result = RunResult(
        alert_id               = alert.alert_id,
        strategy               = strategy_key,
        verdict                = result["verdict"],
        confidence             = result["confidence"],
        rationale              = result["rationale"],
        mitigation_action      = result["mitigation_action"],
        evidence_quality       = result["evidence_quality"],
        total_input_tokens     = result["total_input_tokens"],
        total_output_tokens    = result["total_output_tokens"],
        estimated_cost_usd     = cost,
        latency_seconds        = wall_secs,
        complexity_score       = signals.complexity,
        ambiguity_score        = signals.ambiguity,
        evidence_availability  = signals.evidence_availability,
        selector_rule          = rule,
        ground_truth_verdict   = gt_verdict,
        verdict_correct        = verdict_correct,
        expected_mitigation    = gt_mitigation,
        mitigation_correct     = mitigation_correct,
        ground_truth_evidence_quality = gt_evidence_quality,
    )

    collector.record(run_result)

    # ── Summary line ──────────────────────────────────────────────────────────
    correct_flag = ""
    if verdict_correct is not None:
        correct_flag = " ✓" if verdict_correct else " ✗"

    mit_flag = ""
    if mitigation_correct is not None:
        mit_flag = " mit:✓" if mitigation_correct else " mit:✗"

    strategy_label = strategy_key.replace("_strategy", "")

    print(
        f"[{alert.alert_id}] {strategy_label} ({rule})"
        f" → {result['verdict']}{correct_flag}"
        f" | conf:{result['confidence']:.2f}"
        f" | ev:{result['evidence_quality']}"
        f"{mit_flag}"
        f" | {result['total_input_tokens'] + result['total_output_tokens']:,} tok"
        f" | ${cost:.5f}"
        f" | {wall_secs:.1f}s"
    )

    return run_result


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser   = _build_parser()
    args     = parser.parse_args()

    # Load alert(s)
    try:
        alerts = AlertLoader.load_batch(args.alert)
    except ValueError as exc:
        # Try loading as a single-alert file
        try:
            alerts = [AlertLoader.load(args.alert)]
        except Exception:
            print(f"ERROR loading alerts: {exc}", file=sys.stderr)
            return 1

    # Filter to a single alert if --id specified
    if args.alert_id:
        alerts = [a for a in alerts if a.alert_id == args.alert_id]
        if not alerts:
            print(
                f"ERROR: no alert with id={args.alert_id!r} found in {args.alert}",
                file=sys.stderr,
            )
            return 1

    if not alerts:
        print("No alerts to process.", file=sys.stderr)
        return 1

    selector  = StrategySelector()
    collector = MetricsCollector()

    print(f"Backend : {config.LLM_BACKEND}")
    print(f"Alerts  : {len(alerts)}")
    if args.strategy:
        print(f"Strategy: forced → {args.strategy}")
    print()

    errors = 0
    for alert in alerts:
        try:
            _run_alert(alert, args.strategy, selector, collector)
        except Exception as exc:  # noqa: BLE001
            print(f"[{alert.alert_id}] ERROR: {exc}", file=sys.stderr)
            errors += 1

    print()
    print(f"Done. {len(alerts) - errors}/{len(alerts)} alerts completed successfully.")
    print(f"Results written to: {config.RESULTS_FILE}")

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
