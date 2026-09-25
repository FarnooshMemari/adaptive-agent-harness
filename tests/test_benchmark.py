"""
tests/test_benchmark.py — Benchmark dataset, label isolation, and evaluation checks.

Run from the project root:
    python -m pytest tests/
"""

import copy
import json
from collections import Counter

import pytest

import evaluate
from experiments import run_benchmark
from harness.alert_loader import AlertLoader
from harness.llm_client import BaseLLMClient, LLMResponse, MockLLMClient
from harness.selector import StrategySelector
from strategies.hierarchical import HierarchicalStrategy
from strategies.panel import PanelStrategy

ALERTS_PATH = "data/sample_alerts.json"
CATEGORIES  = {"credential_compromise", "suspicious_access",
               "malware_like_behavior", "privilege_escalation"}
PANEL, HIER = "panel_strategy", "hierarchical_strategy"


@pytest.fixture(scope="module")
def alerts():
    return AlertLoader.load_batch(ALERTS_PATH)


@pytest.fixture(scope="module")
def pairs(alerts, tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("bench")
    assert run_benchmark._run_compare_all(alerts, str(out_dir)) == 0
    records = evaluate._load_results(str(out_dir / "benchmark_combined.jsonl"))
    evaluate._enrich_from_alerts(records, ALERTS_PATH)
    return evaluate._paired_alerts(records)


# ─── Dataset ──────────────────────────────────────────────────────────────────

def test_dataset_covers_four_categories(alerts):
    assert 35 <= len(alerts) <= 45
    counts = Counter(a.category for a in alerts)
    assert set(counts) == CATEGORIES
    assert min(counts.values()) >= 5


def test_every_alert_is_fully_labelled(alerts):
    for a in alerts:
        gt = a.ground_truth
        assert gt, a.alert_id
        assert {"verdict", "expected_mitigation", "evidence_quality",
                "preferred_strategy"} <= gt.keys(), a.alert_id
        assert a.title and a.context and a.raw_evidence, a.alert_id


def test_mock_responses_cover_every_alert(alerts):
    for a in alerts:
        # Raises KeyError if either strategy is missing for this alert
        MockLLMClient(a.alert_id, PANEL)
        MockLLMClient(a.alert_id, HIER)


# ─── Label isolation ──────────────────────────────────────────────────────────

def test_selector_ignores_ground_truth(alerts):
    selector = StrategySelector()
    for a in alerts:
        flipped = copy.deepcopy(a)
        flipped.ground_truth["preferred_strategy"] = (
            HIER if a.ground_truth["preferred_strategy"] == PANEL else PANEL
        )
        stripped = copy.deepcopy(a)
        stripped.ground_truth = None
        assert selector.select(a) == selector.select(flipped) == selector.select(stripped)


class _RecordingClient(BaseLLMClient):
    """Wraps a client and records every prompt sent to it."""

    def __init__(self, inner: BaseLLMClient) -> None:
        self.inner   = inner
        self.prompts = []

    def invoke(self, system: str, user: str) -> LLMResponse:
        self.prompts.append(system + "\n" + user)
        return self.inner.invoke(system, user)


@pytest.mark.parametrize("strategy_cls,key", [(PanelStrategy, PANEL), (HierarchicalStrategy, HIER)])
def test_prompts_never_contain_ground_truth(alerts, strategy_cls, key):
    for a in alerts:
        client = _RecordingClient(MockLLMClient(a.alert_id, key))
        strategy_cls(client).investigate(a)
        for prompt in client.prompts:
            assert "ground_truth" not in prompt
            assert "preferred_strategy" not in prompt
            assert a.ground_truth["expected_mitigation"] not in prompt


# ─── Benchmark outcomes ───────────────────────────────────────────────────────

def test_each_strategy_wins_some_alerts(pairs):
    best = Counter(p["best"] for p in pairs)
    assert best[PANEL] > 0 and best[HIER] > 0 and best["tie"] > 0


def test_neither_strategy_is_perfect(pairs):
    for key in (PANEL, HIER):
        assert not all(p["runs"][key]["verdict_correct"] for p in pairs)


def test_compare_all_records_selector_choice(pairs):
    for p in pairs:
        assert p["selector"] in (PANEL, HIER)
        # Both runs of an alert agree on what the selector chose
        assert p["runs"][PANEL]["selector_strategy"] == p["runs"][HIER]["selector_strategy"]


# ─── Evaluation ───────────────────────────────────────────────────────────────

def test_score_weights():
    assert evaluate._score({"verdict_correct": True,  "mitigation_correct": True})  == pytest.approx(1.0)
    assert evaluate._score({"verdict_correct": True,  "mitigation_correct": False}) == pytest.approx(0.7)
    assert evaluate._score({"verdict_correct": False, "mitigation_correct": False}) == 0.0
    assert evaluate._score({"verdict_correct": None}) is None


def test_best_strategy_uses_score():
    base = {"alert_id": "X", "category": "c", "selector_strategy": PANEL,
            "verdict_correct": True, "estimated_cost_usd": 0.001}
    records = [
        {**base, "strategy": PANEL, "mitigation_correct": False},
        {**base, "strategy": HIER,  "mitigation_correct": True},
    ]
    [pair] = evaluate._paired_alerts(records)
    assert pair["best"] == HIER
    assert pair["selector"] == PANEL


def test_selector_choice_falls_back_to_forced_rule():
    # Result files written before selector_strategy existed
    assert evaluate._selector_choice({"selector_rule": "default"}, {"selector_rule": "forced"}) == PANEL
    assert evaluate._selector_choice({"selector_rule": "forced"}, {"selector_rule": "rich_evidence"}) == HIER


def test_evaluation_tables_render(pairs):
    for table in (evaluate._table4_by_category, evaluate._table5_selector_analysis,
                  evaluate._table6_policy_comparison):
        assert table(pairs)
    assert evaluate._table4_by_category([]) is None
