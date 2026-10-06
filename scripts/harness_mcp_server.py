"""
scripts/harness_mcp_server.py — MCP server for the Adaptive Agent Harness.

Exposes four tools that AI agents (threat-analyst, evaluation-reviewer) can
call directly from chat without having to read and parse raw files manually:

  list_alerts          — list all alerts with id, category, severity, verdict
  get_alert            — fetch one alert's full content by alert_id
  query_results        — summarise benchmark_combined.jsonl by strategy/category
  get_strategy_summary — per-alert selector choice vs. the higher-scoring strategy

Run standalone (for testing):
    python3.12 scripts/harness_mcp_server.py

Registered in .kiro/settings/mcp.json as the "harness" server.
"""

import asyncio
import json
import os
import sys
from collections import defaultdict
from typing import Any

# ── path setup so harness/ imports work when called as a subprocess ──────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from mcp.server.mcpserver import MCPServer

# ── constants mirroring config.py (no import to keep server self-contained) ──
_ALERTS_FILE  = os.path.join(ROOT, "data", "sample_alerts.json")
_RESULTS_DIR  = os.path.join(ROOT, "experiments", "results")
_DEFAULT_RESULTS = os.path.join(_RESULTS_DIR, "benchmark_combined.jsonl")


def _attach_categories(records: list) -> list:
    """Result records omit category; look it up from the alert file (as evaluate.py does)."""
    with open(_ALERTS_FILE) as f:
        cats = {a["alert_id"]: a.get("category") or a.get("type") for a in json.load(f)}
    for r in records:
        r.setdefault("category", cats.get(r.get("alert_id")))
    return records


# ── server definition ─────────────────────────────────────────────────────────

app = MCPServer(
    "harness",
    description=(
        "Adaptive Agent Harness — tools for inspecting benchmark alerts "
        "and evaluation results without reading raw files."
    ),
)


# ─── Tool 1: list_alerts ──────────────────────────────────────────────────────

@app.tool(
    description=(
        "List all alerts in data/sample_alerts.json. "
        "Returns a table with alert_id, title, category, severity, "
        "verdict, and evidence_quality for each alert. "
        "Use category to filter to one incident type."
    )
)
def list_alerts(category: str = "") -> str:
    """
    List all benchmark alerts, optionally filtered by category.

    Args:
        category: Optional filter — one of credential_compromise,
                  suspicious_access, malware_like_behavior,
                  privilege_escalation. Empty string returns all alerts.
    """
    try:
        with open(_ALERTS_FILE) as f:
            alerts = json.load(f)
    except FileNotFoundError:
        return f"ERROR: {_ALERTS_FILE} not found. Run from project root."

    rows = []
    for a in alerts:
        cat = a.get("category") or a.get("type", "")
        if category and cat != category:
            continue
        gt = a.get("ground_truth") or {}
        rows.append({
            "alert_id":       a["alert_id"],
            "title":          a.get("title") or a.get("description", "")[:60],
            "category":       cat,
            "severity":       a["severity"],
            "verdict":        gt.get("verdict", "unlabelled"),
            "evidence_quality": gt.get("evidence_quality", "—"),
            "preferred_strategy": gt.get("preferred_strategy", "—"),
        })

    if not rows:
        return f"No alerts found for category={category!r}."

    lines = [
        f"{'alert_id':<10} {'category':<25} {'sev':<9} {'verdict':<15} "
        f"{'ev_quality':<12} {'preferred_strategy':<20} title",
        "-" * 110,
    ]
    for r in rows:
        lines.append(
            f"{r['alert_id']:<10} {r['category']:<25} {r['severity']:<9} "
            f"{r['verdict']:<15} {r['evidence_quality']:<12} "
            f"{r['preferred_strategy']:<20} {r['title']}"
        )
    lines.append(f"\nTotal: {len(rows)} alerts")
    return "\n".join(lines)


# ─── Tool 2: get_alert ────────────────────────────────────────────────────────

@app.tool(
    description=(
        "Fetch the full details of a single alert by its alert_id "
        "(e.g. ALT-013). Returns all fields including description, "
        "raw_evidence, context, indicators, and ground_truth."
    )
)
def get_alert(alert_id: str) -> str:
    """
    Return full alert content for a given alert_id.

    Args:
        alert_id: The alert identifier, e.g. "ALT-013".
    """
    try:
        with open(_ALERTS_FILE) as f:
            alerts = json.load(f)
    except FileNotFoundError:
        return f"ERROR: {_ALERTS_FILE} not found."

    alert = next((a for a in alerts if a["alert_id"] == alert_id), None)
    if alert is None:
        ids = [a["alert_id"] for a in alerts]
        return f"Alert {alert_id!r} not found. Available IDs: {ids}"

    # Pretty-print with sections
    lines = [f"=== {alert_id} ==="]
    lines.append(f"Title    : {alert.get('title', '—')}")
    lines.append(f"Category : {alert.get('category') or alert.get('type', '—')}")
    lines.append(f"Severity : {alert['severity']}")
    lines.append("")
    lines.append("Description:")
    lines.append(f"  {alert['description']}")
    lines.append("")

    if alert.get("context"):
        lines.append("Context:")
        lines.append(f"  {alert['context']}")
        lines.append("")

    if alert.get("indicators"):
        lines.append("Indicators:")
        lines.append(f"  {alert['indicators']}")
        lines.append("")

    lines.append("Raw evidence:")
    lines.append(f"  {alert['raw_evidence']}")
    lines.append("")

    gt = alert.get("ground_truth")
    if gt:
        lines.append("Ground truth:")
        for k, v in gt.items():
            lines.append(f"  {k}: {v}")

    return "\n".join(lines)


# ─── Tool 3: query_results ────────────────────────────────────────────────────

@app.tool(
    description=(
        "Query benchmark results from a JSONL results file. "
        "Returns per-strategy accuracy, mitigation correctness, "
        "and investigation scores broken down by incident category. "
        "Defaults to experiments/results/benchmark_combined.jsonl."
    )
)
def query_results(
    results_file: str = "",
    category: str = "",
) -> str:
    """
    Summarise benchmark results from a JSONL file.

    Args:
        results_file: Path to a .jsonl results file. Defaults to
                      experiments/results/benchmark_combined.jsonl.
        category:     Optional — filter to one incident category.
    """
    path = results_file.strip() or _DEFAULT_RESULTS
    if not os.path.isabs(path):
        path = os.path.join(ROOT, path)

    try:
        with open(path) as f:
            records = _attach_categories([json.loads(line) for line in f if line.strip()])
    except FileNotFoundError:
        return (
            f"ERROR: {path} not found.\n"
            "Run: python experiments/run_benchmark.py "
            "--alert data/sample_alerts.json --compare-all"
        )

    if category:
        records = [r for r in records if r.get("category") == category]
        if not records:
            return f"No records for category={category!r} in {path}."

    # Group by strategy
    VERDICT_W, MIT_W = 0.7, 0.3
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in records:
        groups[r["strategy"]].append(r)

    lines = [f"Results: {os.path.basename(path)}  ({len(records)} records)"]
    if category:
        lines[0] += f"  category={category}"
    lines.append("")

    for strategy in sorted(groups):
        grp = groups[strategy]
        gt = [r for r in grp if r.get("verdict_correct") is not None]
        n_correct = sum(1 for r in gt if r["verdict_correct"])
        mit = [r for r in grp if r.get("mitigation_correct") is not None]
        n_mit = sum(1 for r in mit if r["mitigation_correct"])

        scores = []
        for r in gt:
            s = VERDICT_W * bool(r["verdict_correct"]) + MIT_W * bool(r.get("mitigation_correct"))
            scores.append(s)

        avg_score = sum(scores) / len(scores) if scores else None
        avg_cost  = sum(r.get("estimated_cost_usd", 0) for r in grp) / len(grp)
        avg_tok   = sum(r.get("total_input_tokens", 0) + r.get("total_output_tokens", 0)
                        for r in grp) / len(grp)

        label = strategy.replace("_strategy", "")
        acc  = f"{n_correct}/{len(gt)} = {n_correct/len(gt)*100:.1f}%" if gt else "N/A"
        mitc = f"{n_mit}/{len(mit)} = {n_mit/len(mit)*100:.1f}%" if mit else "N/A"
        sc   = f"{avg_score:.3f}" if avg_score is not None else "N/A"

        lines.append(f"Strategy      : {label}")
        lines.append(f"  Alerts      : {len(grp)}")
        lines.append(f"  Accuracy    : {acc}")
        lines.append(f"  Mitigation  : {mitc}")
        lines.append(f"  Avg score   : {sc}  (0.7×verdict + 0.3×mitigation)")
        lines.append(f"  Avg tokens  : {avg_tok:,.0f}")
        lines.append(f"  Avg cost    : ${avg_cost:.5f}")
        lines.append("")

    # Per-category breakdown if not already filtered
    if not category:
        lines.append("── By category ──────────────────────────────────────────────")
        cats: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
        for r in records:
            if r.get("category"):
                cats[r["category"]][r["strategy"]].append(r)

        for cat in sorted(cats):
            lines.append(f"\n  {cat.replace('_', ' ')}:")
            for strat in sorted(cats[cat]):
                grp = cats[cat][strat]
                gt = [r for r in grp if r.get("verdict_correct") is not None]
                n_corr = sum(1 for r in gt if r["verdict_correct"])
                label = strat.replace("_strategy", "")
                acc = f"{n_corr}/{len(gt)} = {n_corr/len(gt)*100:.1f}%" if gt else "N/A"
                lines.append(f"    {label:<14}: {acc}")

    return "\n".join(lines)


# ─── Tool 4: get_strategy_summary ────────────────────────────────────────────

@app.tool(
    description=(
        "Compare panel vs hierarchical strategy performance and show "
        "which strategy the selector chose for each alert versus which "
        "strategy actually scored higher (the 'better' strategy). "
        "Highlights alerts where the selector made the wrong choice."
    )
)
def get_strategy_summary(results_file: str = "") -> str:
    """
    Show selector agreement analysis: for each alert, which strategy did
    the selector pick, which strategy actually scored higher, and whether
    they agree.

    Args:
        results_file: Path to benchmark_combined.jsonl (both strategies
                      required). Defaults to experiments/results/benchmark_combined.jsonl.
    """
    path = results_file.strip() or _DEFAULT_RESULTS
    if not os.path.isabs(path):
        path = os.path.join(ROOT, path)

    try:
        with open(path) as f:
            records = _attach_categories([json.loads(line) for line in f if line.strip()])
    except FileNotFoundError:
        return f"ERROR: {path} not found."

    PANEL, HIER = "panel_strategy", "hierarchical_strategy"
    VERDICT_W, MIT_W = 0.7, 0.3

    # Group by alert_id
    by_alert: dict[str, dict[str, dict]] = defaultdict(dict)
    for r in records:
        by_alert[r["alert_id"]][r["strategy"]] = r

    lines = ["alert_id   selector    better      agree  category               score_panel  score_hier"]
    lines.append("-" * 100)

    agreed = 0
    decisive = 0
    for aid in sorted(by_alert):
        runs = by_alert[aid]
        if PANEL not in runs or HIER not in runs:
            continue

        p, h = runs[PANEL], runs[HIER]

        # Selector choice
        sel = p.get("selector_strategy") or h.get("selector_strategy")
        if not sel:
            p_rule = p.get("selector_rule", "")
            h_rule = h.get("selector_rule", "")
            if p_rule != "forced" and h_rule == "forced":
                sel = PANEL
            elif h_rule != "forced" and p_rule == "forced":
                sel = HIER

        # Scores
        def score(r: dict) -> Any:
            if r.get("verdict_correct") is None:
                return None
            return VERDICT_W * bool(r["verdict_correct"]) + MIT_W * bool(r.get("mitigation_correct"))

        p_sc, h_sc = score(p), score(h)
        if p_sc is None or h_sc is None:
            best = None
        elif abs(p_sc - h_sc) < 1e-9:
            best = "tie"
        else:
            best = PANEL if p_sc > h_sc else HIER
            decisive += 1
            if sel == best:
                agreed += 1

        sel_label  = (sel or "?").replace("_strategy", "")
        best_label = (best or "?").replace("_strategy", "") if best not in ("tie", None) else (best or "?")
        agree_mark = "✓" if sel == best else ("—" if best in ("tie", None) else "✗")

        cat = (p.get("category") or h.get("category") or "")[:22]
        p_str = f"{p_sc:.2f}" if p_sc is not None else "N/A"
        h_str = f"{h_sc:.2f}" if h_sc is not None else "N/A"

        lines.append(
            f"{aid:<10} {sel_label:<12} {best_label:<12} {agree_mark:<7}"
            f"{cat:<23} {p_str:<13} {h_str}"
        )

    pct = f"{agreed/decisive*100:.1f}%" if decisive else "N/A"
    lines.append("-" * 100)
    lines.append(f"Selector agreement: {agreed}/{decisive} decisive alerts = {pct}")
    lines.append("(✓ = selector picked better strategy  ✗ = selector picked worse  — = tie/no ground truth)")
    return "\n".join(lines)


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    asyncio.run(app.run_stdio_async())
