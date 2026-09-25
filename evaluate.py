"""
evaluate.py — Strategy comparison report.

Reads a JSONL results file and prints up to six tables:

  Table 1 — Overall strategy comparison (aggregated metrics)
  Table 2 — Evidence quality distribution per strategy
  Table 3 — Per-alert detail
  Table 4 — Performance by incident category (panel vs hierarchical)
  Table 5 — Selector agreement: selector choice vs best-performing strategy
  Table 6 — Policy comparison: always-panel / always-hierarchical /
            adaptive selector / preferred_strategy label / oracle

Tables 4–6 need both strategies on the same alerts
(experiments/run_benchmark.py --compare-all). "Best-performing" is decided
per alert by an investigation score: 0.7 × verdict correct + 0.3 × mitigation
correct. category and preferred_strategy are read from the alert file.

Usage:
    python evaluate.py
    python evaluate.py --results experiments/results/benchmark_combined.jsonl
    python evaluate.py --results experiments/results/benchmark_combined.jsonl --no-detail
"""

import argparse
import json
import sys
from collections import defaultdict
from typing import Optional

import config

try:
    from tabulate import tabulate
except ImportError:
    print("ERROR: 'tabulate' is not installed. Run: pip install tabulate", file=sys.stderr)
    sys.exit(1)


# ─── Argument parsing ─────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Evaluate and compare investigation strategy results.",
    )
    p.add_argument(
        "--results", default=config.RESULTS_FILE, metavar="PATH",
        help=f"Path to results JSONL file (default: {config.RESULTS_FILE}).",
    )
    p.add_argument(
        "--alerts", default="data/sample_alerts.json", metavar="PATH",
        help="Alert file used to look up category and preferred_strategy "
             "(default: data/sample_alerts.json).",
    )
    p.add_argument(
        "--no-detail", action="store_true",
        help="Skip Table 3 (per-alert detail).",
    )
    p.add_argument(
        "--no-category", action="store_true",
        help="Skip Table 4 (per-category breakdown).",
    )
    p.add_argument(
        "--no-selector", action="store_true",
        help="Skip Table 5 (selector agreement analysis).",
    )
    return p


# ─── Data loading ─────────────────────────────────────────────────────────────

def _load_results(path: str) -> list[dict]:
    """Read all JSON lines from the results file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = [line.strip() for line in fh if line.strip()]
    except FileNotFoundError:
        print(f"ERROR: results file not found: {path!r}", file=sys.stderr)
        print("Run benchmark first, e.g.:", file=sys.stderr)
        print("  python experiments/run_benchmark.py --alert data/sample_alerts.json --compare-all", file=sys.stderr)
        sys.exit(1)

    records = []
    for i, line in enumerate(lines, start=1):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(f"WARNING: skipping malformed line {i}: {exc}", file=sys.stderr)

    return records


# ─── Aggregation helpers ──────────────────────────────────────────────────────

def _pct(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "N/A"
    return f"{numerator / denominator * 100:.1f}%"


def _avg(values: list[float]) -> str:
    if not values:
        return "N/A"
    return f"{sum(values) / len(values):.5f}"


def _avg_int(values: list[int]) -> str:
    if not values:
        return "N/A"
    return f"{int(sum(values) / len(values)):,}"


def _avg_secs(values: list[float]) -> str:
    if not values:
        return "N/A"
    return f"{sum(values) / len(values):.2f}"


# ─── Table builders ───────────────────────────────────────────────────────────

def _table1_strategy_comparison(records: list[dict]) -> str:
    """
    Table 1: Per-strategy aggregated metrics.
    Columns: Strategy | Alerts | Accuracy | Mitigation OK | Avg Score | Avg Tokens | Avg Cost ($) | Avg Latency (s)
    """
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        groups[r["strategy"]].append(r)

    rows = []
    for strategy in sorted(groups.keys()):
        grp = groups[strategy]
        n   = len(grp)

        # Accuracy: only count records that have ground_truth
        gt_records  = [r for r in grp if r.get("verdict_correct") is not None]
        n_correct   = sum(1 for r in gt_records if r["verdict_correct"])

        # Mitigation correctness
        mit_records = [r for r in grp if r.get("mitigation_correct") is not None]
        n_mit_ok    = sum(1 for r in mit_records if r["mitigation_correct"])

        avg_tokens  = _avg_int([
            r["total_input_tokens"] + r["total_output_tokens"] for r in grp
        ])
        avg_cost    = _avg([r["estimated_cost_usd"] for r in grp])
        avg_latency = _avg_secs([r["latency_seconds"] for r in grp])

        label = strategy.replace("_strategy", "")
        rows.append([
            label,
            n,
            _pct(n_correct, len(gt_records)),
            _pct(n_mit_ok, len(mit_records)),
            _fmt_score([s for s in map(_score, grp) if s is not None]),
            avg_tokens,
            avg_cost,
            avg_latency,
        ])

    headers = [
        "Strategy", "Alerts", "Accuracy",
        "Mitigation OK", "Avg Score", "Avg Tokens", "Avg Cost ($)", "Avg Latency (s)",
    ]
    return tabulate(rows, headers=headers, tablefmt="github")


def _table2_evidence_quality(records: list[dict]) -> str:
    """
    Table 2: Evidence quality distribution per strategy.
    Columns: Strategy | Low | Medium | High
    """
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        groups[r["strategy"]].append(r)

    rows = []
    for strategy in sorted(groups.keys()):
        grp  = groups[strategy]
        low  = sum(1 for r in grp if r.get("evidence_quality") == "low")
        med  = sum(1 for r in grp if r.get("evidence_quality") == "medium")
        high = sum(1 for r in grp if r.get("evidence_quality") == "high")
        label = strategy.replace("_strategy", "")
        rows.append([label, low, med, high])

    headers = ["Strategy", "Low", "Medium", "High"]
    return tabulate(rows, headers=headers, tablefmt="github")


def _table3_per_alert(records: list[dict]) -> str:
    """
    Table 3: Per-alert detail row.
    Columns: Alert ID | Strategy | Verdict | Correct | Mitigation OK | Ev. Quality | Cost ($) | Latency (s)
    """
    rows = []
    for r in records:
        correct_str = (
            "✓" if r.get("verdict_correct") is True
            else "✗" if r.get("verdict_correct") is False
            else "N/A"
        )
        mit_str = (
            "✓" if r.get("mitigation_correct") is True
            else "✗" if r.get("mitigation_correct") is False
            else "N/A"
        )
        label = r["strategy"].replace("_strategy", "")
        rows.append([
            r["alert_id"],
            label,
            r["verdict"],
            correct_str,
            mit_str,
            r.get("evidence_quality", "N/A"),
            f"{r.get('estimated_cost_usd', 0):.5f}",
            f"{r.get('latency_seconds', 0):.2f}",
        ])

    headers = [
        "Alert ID", "Strategy", "Verdict",
        "Correct", "Mitigation OK", "Ev. Quality", "Cost ($)", "Latency (s)",
    ]
    return tabulate(rows, headers=headers, tablefmt="github")


# ─── Summary stats ────────────────────────────────────────────────────────────

def _print_summary(records: list[dict], results_path: str) -> None:
    """Print a one-line overall summary above the tables."""
    n  = len(records)
    gt = [r for r in records if r.get("verdict_correct") is not None]
    correct    = sum(1 for r in gt if r["verdict_correct"])
    total_cost = sum(r.get("estimated_cost_usd", 0) for r in records)
    strategies = sorted({r["strategy"].replace("_strategy", "") for r in records})
    categories = sorted({r.get("category", "") for r in records if r.get("category")})

    print(f"Results file : {results_path}")
    print(f"Total runs   : {n}")
    print(f"Strategies   : {', '.join(strategies)}")
    if categories:
        print(f"Categories   : {', '.join(categories)}")
    if gt:
        print(f"Overall accuracy : {_pct(correct, len(gt))} ({correct}/{len(gt)} with ground truth)")
    print(f"Total est. cost  : ${total_cost:.5f}")
    print()


# ─── Scoring and pairing helpers ──────────────────────────────────────────────

_PANEL = "panel_strategy"
_HIER  = "hierarchical_strategy"

# Per-run investigation score in [0, 1]. The verdict dominates; mitigation
# completeness separates two runs that reached the same verdict.
_VERDICT_WEIGHT    = 0.7
_MITIGATION_WEIGHT = 0.3


def _score(r: dict) -> Optional[float]:
    """Investigation score for one run, or None if the alert has no ground truth."""
    if r.get("verdict_correct") is None:
        return None
    return (
        _VERDICT_WEIGHT * bool(r["verdict_correct"])
        + _MITIGATION_WEIGHT * bool(r.get("mitigation_correct"))
    )


def _fmt_score(values: list[float]) -> str:
    if not values:
        return "N/A"
    return f"{sum(values) / len(values):.3f}"


def _accuracy_row(grp: list[dict]) -> tuple[int, int, int, int]:
    """Return (n, n_gt, n_correct, n_mit_ok) for a group of records."""
    n       = len(grp)
    gt_recs = [r for r in grp if r.get("verdict_correct") is not None]
    correct = sum(1 for r in gt_recs if r["verdict_correct"])
    mit_recs = [r for r in grp if r.get("mitigation_correct") is not None]
    mit_ok   = sum(1 for r in mit_recs if r["mitigation_correct"])
    return n, len(gt_recs), correct, mit_ok


def _selector_choice(p: dict, h: dict) -> Optional[str]:
    """The strategy the selector picked for this alert, if it can be determined."""
    choice = p.get("selector_strategy") or h.get("selector_strategy")
    if choice:
        return choice
    # Older result files: the selector's pick ran with its natural rule,
    # the other strategy ran with "forced".
    p_rule, h_rule = p.get("selector_rule"), h.get("selector_rule")
    if p_rule != "forced" and h_rule == "forced":
        return _PANEL
    if h_rule != "forced" and p_rule == "forced":
        return _HIER
    return None


def _paired_alerts(records: list[dict]) -> list[dict]:
    """
    Group compare-all records into one entry per alert that has BOTH strategies.

    Each entry:
        alert_id, category,
        runs     : {strategy: record}
        best     : strategy with the higher score | "tie" | None (no ground truth)
        selector : strategy the selector chose (None if unknown)
        label    : ground_truth.preferred_strategy (None if absent)
    """
    by_alert: dict[str, dict[str, dict]] = defaultdict(dict)
    for r in records:
        by_alert[r["alert_id"]][r["strategy"]] = r

    pairs = []
    for aid in sorted(by_alert):
        strats = by_alert[aid]
        if _PANEL not in strats or _HIER not in strats:
            continue
        p, h = strats[_PANEL], strats[_HIER]

        p_score, h_score = _score(p), _score(h)
        if p_score is None or h_score is None:
            best = None
        elif abs(p_score - h_score) < 1e-9:
            best = "tie"
        else:
            best = _PANEL if p_score > h_score else _HIER

        pairs.append({
            "alert_id": aid,
            "category": p.get("category") or h.get("category") or "uncategorised",
            "runs":     {_PANEL: p, _HIER: h},
            "best":     best,
            "selector": _selector_choice(p, h),
            "label":    p.get("preferred_strategy") or h.get("preferred_strategy"),
        })
    return pairs


# ─── Table 4: Performance by incident category ────────────────────────────────

def _table4_by_category(pairs: list[dict]) -> Optional[str]:
    """
    Table 4: Panel vs hierarchical within each incident category, on alerts
    that were run with both strategies.

    Columns:
        Category | Alerts | Panel/Hier Acc | Panel/Hier Mit | Panel/Hier Score |
        Wins P-H-T | Better
    """
    if not pairs:
        return None

    by_cat: dict[str, list[dict]] = defaultdict(list)
    for pair in pairs:
        by_cat[pair["category"]].append(pair)

    rows = [_category_row(cat.replace("_", " "), by_cat[cat]) for cat in sorted(by_cat)]
    rows.append(_category_row("TOTAL", pairs))

    headers = [
        "Category", "Alerts",
        "Panel Acc", "Hier Acc",
        "Panel Mit", "Hier Mit",
        "Panel Score", "Hier Score",
        "Wins P-H-T", "Better",
    ]
    note = (
        f"  Score = {_VERDICT_WEIGHT} × verdict correct + {_MITIGATION_WEIGHT} × mitigation correct (per run, 0–1)\n"
        "  Wins P-H-T = alerts where panel scored higher / hierarchical scored higher / tied\n"
        "  Better = strategy with the higher mean score in this category"
    )
    return tabulate(rows, headers=headers, tablefmt="github") + "\n" + note


def _category_row(label: str, pairs: list[dict]) -> list:
    panel = [pair["runs"][_PANEL] for pair in pairs]
    hier  = [pair["runs"][_HIER] for pair in pairs]
    _, p_gt, p_corr, p_mit = _accuracy_row(panel)
    _, h_gt, h_corr, h_mit = _accuracy_row(hier)

    p_scores = [s for s in map(_score, panel) if s is not None]
    h_scores = [s for s in map(_score, hier) if s is not None]

    wins_p = sum(1 for pair in pairs if pair["best"] == _PANEL)
    wins_h = sum(1 for pair in pairs if pair["best"] == _HIER)
    ties   = sum(1 for pair in pairs if pair["best"] == "tie")

    if not p_scores or not h_scores:
        better = "N/A"
    else:
        p_mean = sum(p_scores) / len(p_scores)
        h_mean = sum(h_scores) / len(h_scores)
        better = "panel" if p_mean > h_mean else "hierarchical" if h_mean > p_mean else "even"

    return [
        label, len(pairs),
        _pct(p_corr, p_gt), _pct(h_corr, h_gt),
        _pct(p_mit, p_gt), _pct(h_mit, h_gt),
        _fmt_score(p_scores), _fmt_score(h_scores),
        f"{wins_p}-{wins_h}-{ties}",
        better,
    ]


# ─── Table 5: Selector agreement analysis ────────────────────────────────────

def _table5_selector_analysis(pairs: list[dict]) -> Optional[str]:
    """
    Table 5: Does the selector pick the best-performing strategy?

    Per alert, "best" is the strategy with the higher investigation score.
    Agreement is measured only on decisive alerts (one strategy strictly
    better); on ties either choice is equally good.

    Sel=Label compares the selector against ground_truth.preferred_strategy.
    The selector never reads that label; it is used here for evaluation only.
    """
    pairs = [pair for pair in pairs if pair["selector"] is not None]
    if not pairs:
        return None

    by_cat: dict[str, list[dict]] = defaultdict(list)
    for pair in pairs:
        by_cat[pair["category"]].append(pair)

    rows = [_selector_row(cat.replace("_", " "), by_cat[cat]) for cat in sorted(by_cat)]
    rows.append(_selector_row("TOTAL", pairs))

    headers = [
        "Category", "Alerts",
        "Sel→Panel", "Sel→Hier",
        "Best=Panel", "Best=Hier", "Tie",
        "Agreement %", "Sel=Label %",
    ]
    note = (
        "  Agreement % = selector chose the higher-scoring strategy, over decisive alerts (ties excluded)\n"
        "  Sel=Label % = selector matched ground_truth.preferred_strategy (evaluation-only label)"
    )
    return tabulate(rows, headers=headers, tablefmt="github") + "\n" + note


def _selector_row(label: str, pairs: list[dict]) -> list:
    decisive = [pair for pair in pairs if pair["best"] in (_PANEL, _HIER)]
    agreed   = sum(1 for pair in decisive if pair["selector"] == pair["best"])
    labelled = [pair for pair in pairs if pair["label"]]
    label_ok = sum(1 for pair in labelled if pair["selector"] == pair["label"])
    return [
        label,
        len(pairs),
        sum(1 for pair in pairs if pair["selector"] == _PANEL),
        sum(1 for pair in pairs if pair["selector"] == _HIER),
        sum(1 for pair in pairs if pair["best"] == _PANEL),
        sum(1 for pair in pairs if pair["best"] == _HIER),
        sum(1 for pair in pairs if pair["best"] == "tie"),
        f"{_pct(agreed, len(decisive))} ({agreed}/{len(decisive)})",
        _pct(label_ok, len(labelled)),
    ]


# ─── Table 6: Policy comparison ───────────────────────────────────────────────

def _table6_policy_comparison(pairs: list[dict]) -> Optional[str]:
    """
    Table 6: What would each strategy-assignment policy have scored on the
    same set of alerts?

    Policies:
        always panel / always hierarchical  — fixed strategy baselines
        adaptive (selector)                 — the StrategySelector's choice
        preferred_strategy label            — the ground-truth label
        oracle (best per alert)             — upper bound; ties go to the cheaper run

    If the hypothesis holds, the oracle should beat both fixed baselines;
    the gap between adaptive and oracle is the selector's headroom.
    """
    if not pairs:
        return None

    def oracle(pair: dict) -> str:
        if pair["best"] in (_PANEL, _HIER):
            return pair["best"]
        runs = pair["runs"]
        return min(runs, key=lambda s: runs[s].get("estimated_cost_usd", 0.0))

    policies = [
        ("always panel",             lambda pair: _PANEL),
        ("always hierarchical",      lambda pair: _HIER),
        ("adaptive (selector)",      lambda pair: pair["selector"]),
        ("preferred_strategy label", lambda pair: pair["label"]),
        ("oracle (best per alert)",  oracle),
    ]

    rows = []
    for name, pick in policies:
        chosen = [pair["runs"][s] for pair in pairs if (s := pick(pair)) in pair["runs"]]
        _, n_gt, correct, mit_ok = _accuracy_row(chosen)
        scores = [s for s in map(_score, chosen) if s is not None]
        cost   = [r.get("estimated_cost_usd", 0.0) for r in chosen]
        rows.append([
            name,
            len(chosen),
            _pct(correct, n_gt),
            _pct(mit_ok, n_gt),
            _fmt_score(scores),
            _avg(cost),
        ])

    wins_p = sum(1 for pair in pairs if pair["best"] == _PANEL)
    wins_h = sum(1 for pair in pairs if pair["best"] == _HIER)
    ties   = sum(1 for pair in pairs if pair["best"] == "tie")

    headers = ["Policy", "Alerts", "Accuracy", "Mitigation OK", "Avg Score", "Avg Cost ($)"]
    note = (
        f"  Head-to-head on {len(pairs)} paired alerts: panel better on {wins_p}, "
        f"hierarchical better on {wins_h}, tied on {ties}\n"
        "  Alerts < total means the policy had no choice recorded for some alerts"
    )
    return tabulate(rows, headers=headers, tablefmt="github") + "\n" + note


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    args    = _build_parser().parse_args()
    records = _load_results(args.results)

    if not records:
        print("No results found. Run some alerts first.", file=sys.stderr)
        return 1

    # Attach category / preferred_strategy from the alert file
    # (RunResult records don't carry them)
    _enrich_from_alerts(records, args.alerts)

    _print_summary(records, args.results)

    print("── Table 1: Strategy Comparison ────────────────────────────────────")
    print(_table1_strategy_comparison(records))
    print()

    print("── Table 2: Evidence Quality Distribution ──────────────────────────")
    print(_table2_evidence_quality(records))
    print()

    if not args.no_detail:
        print("── Table 3: Per-Alert Detail ────────────────────────────────────────")
        print(_table3_per_alert(records))
        print()

    pairs = _paired_alerts(records)

    if not args.no_category:
        print("── Table 4: Performance by Incident Category ───────────────────────")
        t4 = _table4_by_category(pairs)
        print(t4 or "  (skipped — requires both strategies on the same alerts; run --compare-all)")
        print()

    if not args.no_selector:
        print("── Table 5: Selector Agreement Analysis ────────────────────────────")
        t5 = _table5_selector_analysis(pairs)
        print(t5 or "  (skipped — requires both strategies on the same alerts; run --compare-all)")
        print()

    print("── Table 6: Policy Comparison (fixed vs adaptive vs oracle) ────────")
    t6 = _table6_policy_comparison(pairs)
    print(t6 or "  (skipped — requires both strategies on the same alerts; run --compare-all)")
    print()

    return 0


def _enrich_from_alerts(records: list[dict], alert_path: str) -> None:
    """
    Back-fill 'category' and 'preferred_strategy' on records by matching
    alert_id against the alert file. Silently skips if unavailable.
    """
    try:
        with open(alert_path, "r", encoding="utf-8") as fh:
            alerts = {a["alert_id"]: a for a in json.load(fh)}
    except (OSError, ValueError, TypeError, KeyError):
        return  # Enrichment is best-effort; don't fail evaluation

    for r in records:
        alert = alerts.get(r["alert_id"])
        if not alert:
            continue
        if not r.get("category"):
            r["category"] = alert.get("category") or alert.get("type", "")
        if not r.get("preferred_strategy"):
            r["preferred_strategy"] = (alert.get("ground_truth") or {}).get("preferred_strategy")


if __name__ == "__main__":
    sys.exit(main())
