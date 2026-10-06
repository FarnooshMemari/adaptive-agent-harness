"""
validate_benchmark.py — dataset gate for the soc-benchmark-author power.

Checks data/sample_alerts.json and data/mock_responses.json together, using the
project's own parsers so the rules never drift from runtime behaviour:

  1. Every alert passes AlertLoader validation; alert_ids are unique.
  2. Every alert has a mock entry with all agent roles for BOTH strategies,
     and there are no orphan mock entries.
  3. Roles parsed as JSON by the strategies (critic_report, consensus,
     evidence_validation, decomposition, synthesis) contain the keys the
     strategies read, with valid enum values.
  4. Predicts each strategy's verdict/mitigation correctness and score from the
     mocks (same scoring as run_benchmark.py / evaluate.py), so an author can
     see whether a new alert is discriminative before running the benchmark.

Usage (from the repository root):
    python .kiro/powers/soc-benchmark-author/skills/add-benchmark-alert/scripts/validate_benchmark.py
    python .../validate_benchmark.py --alert-id ALT-041   # detail for one alert

Exit code 0 = valid, 1 = errors found.
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict

ROOT = os.getcwd()
sys.path.insert(0, ROOT)

from harness.alert_loader import AlertLoader            # noqa: E402
from strategies.base import extract_json                # noqa: E402
from experiments.run_benchmark import _mitigation_correct  # noqa: E402

ALERTS_FILE = os.path.join("data", "sample_alerts.json")
MOCKS_FILE = os.path.join("data", "mock_responses.json")

PANEL, HIER = "panel_strategy", "hierarchical_strategy"
ROLES = {
    PANEL: ["threat_assessment", "forensics_assessment", "critic_report", "consensus"],
    HIER: ["evidence_validation", "decomposition", "network_finding",
           "threat_intel_finding", "synthesis"],
}
# role -> keys the strategy code reads from the parsed JSON
JSON_ROLES = {
    (PANEL, "critic_report"): ["evidence_quality"],
    (PANEL, "consensus"): ["verdict", "confidence", "rationale", "mitigation_action"],
    (HIER, "evidence_validation"): ["quality"],
    (HIER, "decomposition"): ["network_question", "threat_intel_question"],
    (HIER, "synthesis"): ["verdict", "confidence", "rationale", "mitigation_action"],
}
FINAL_ROLE = {PANEL: "consensus", HIER: "synthesis"}
VERDICTS = {"true_positive", "false_positive"}
QUALITIES = {"low", "medium", "high"}
VERDICT_W, MIT_W = 0.7, 0.3


def _check_mock(aid, entry, errors):
    """Validate one alert's mock entry; return {strategy: parsed final JSON}."""
    finals = {}
    for strat, roles in ROLES.items():
        block = entry.get(strat)
        if not isinstance(block, dict):
            errors.append(f"{aid}: mock missing strategy '{strat}'")
            continue
        for role in roles:
            text = block.get(role)
            if not isinstance(text, str) or not text.strip():
                errors.append(f"{aid}: {strat}.{role} missing or empty")
                continue
            keys = JSON_ROLES.get((strat, role))
            if keys is None:
                continue
            try:
                data = extract_json(text)
            except ValueError as exc:
                errors.append(f"{aid}: {strat}.{role} is not parseable JSON ({exc})")
                continue
            missing = [k for k in keys if k not in data]
            if missing:
                errors.append(f"{aid}: {strat}.{role} missing key(s) {missing}")
            if "verdict" in data and str(data["verdict"]).lower() not in VERDICTS:
                errors.append(f"{aid}: {strat}.{role} verdict {data['verdict']!r} invalid")
            q = data.get("evidence_quality", data.get("quality"))
            if q is not None and str(q).lower() not in QUALITIES:
                errors.append(f"{aid}: {strat}.{role} evidence quality {q!r} invalid")
            if "confidence" in data:
                try:
                    if not 0.0 <= float(data["confidence"]) <= 1.0:
                        raise ValueError
                except (TypeError, ValueError):
                    errors.append(f"{aid}: {strat}.{role} confidence must be in [0, 1]")
            if role == FINAL_ROLE[strat]:
                finals[strat] = data
    return finals


def _predict(gt, final):
    """Expected (verdict_correct, mitigation_correct, score) for one strategy."""
    if not gt or not final:
        return None
    v_ok = str(final.get("verdict", "")).lower() == gt["verdict"]
    m_ok = _mitigation_correct(final.get("mitigation_action", ""), gt["expected_mitigation"])
    return v_ok, m_ok, VERDICT_W * v_ok + MIT_W * m_ok


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--alert-id", help="Print predicted outcome detail for one alert.")
    args = p.parse_args()

    errors = []
    try:
        alerts = AlertLoader.load_batch(ALERTS_FILE)
    except (ValueError, OSError) as exc:
        print(f"FAIL: {exc}")
        return 1
    with open(MOCKS_FILE, encoding="utf-8") as fh:
        mocks = json.load(fh)

    ids = [a.alert_id for a in alerts]
    for aid, n in Counter(ids).items():
        if n > 1:
            errors.append(f"{aid}: duplicate alert_id ({n} occurrences)")
    mock_ids = {k for k in mocks if not k.startswith("_")}
    for aid in sorted(mock_ids - set(ids)):
        errors.append(f"{aid}: orphan mock entry (no matching alert)")

    by_cat = defaultdict(Counter)
    for alert in alerts:
        aid = alert.alert_id
        gt = alert.ground_truth or {}
        cat = alert.category or alert.type
        by_cat[cat]["alerts"] += 1
        if gt:
            by_cat[cat][gt["verdict"]] += 1
            by_cat[cat][gt.get("preferred_strategy", "no_preference")] += 1
        if aid not in mocks:
            errors.append(f"{aid}: no entry in {MOCKS_FILE}")
            continue
        finals = _check_mock(aid, mocks[aid], errors)
        pp, hp = _predict(gt, finals.get(PANEL)), _predict(gt, finals.get(HIER))
        if pp and hp:
            winner = "tie" if pp[2] == hp[2] else (PANEL if pp[2] > hp[2] else HIER)
            by_cat[cat]["decisive"] += winner != "tie"
            pref = gt.get("preferred_strategy")
            if pref and winner not in ("tie", pref):
                errors.append(
                    f"{aid}: preferred_strategy={pref} but mocks make {winner} score higher "
                    f"(panel {pp[2]:.1f} vs hierarchical {hp[2]:.1f})"
                )
        if aid == args.alert_id:
            print(f"\n{aid} — {alert.title or ''} [{cat}, {alert.severity}]")
            print(f"  ground truth: {gt.get('verdict')} | pref={gt.get('preferred_strategy')}")
            for name, pred in (("panel", pp), ("hierarchical", hp)):
                if pred:
                    print(f"  {name:<13} verdict_ok={pred[0]!s:<5} mitigation_ok={pred[1]!s:<5} score={pred[2]:.1f}")

    print(f"\n{'category':<24}{'alerts':>7}{'TP':>5}{'FP':>5}{'pref_P':>8}{'pref_H':>8}{'decisive':>10}")
    for cat in sorted(by_cat):
        c = by_cat[cat]
        print(f"{cat:<24}{c['alerts']:>7}{c['true_positive']:>5}{c['false_positive']:>5}"
              f"{c[PANEL]:>8}{c[HIER]:>8}{c['decisive']:>10}")

    if errors:
        print(f"\nFAIL: {len(errors)} problem(s)")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"\nOK: {len(alerts)} alerts, {len(mock_ids)} mock entries, all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
