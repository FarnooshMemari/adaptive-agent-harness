"""
harness/metrics.py — RunResult dataclass and MetricsCollector.

RunResult captures every field produced by an investigation run.
MetricsCollector persists results to results.jsonl, one JSON object per line.
"""

import json
import os
from dataclasses import dataclass, asdict
from typing import Optional

import config


# ─── RunResult ────────────────────────────────────────────────────────────────

@dataclass
class RunResult:
    """
    Complete record of a single alert investigation run.

    Fields are grouped into four logical sections:
    1. Identity
    2. Investigation output  (verdict, confidence, rationale, mitigation, evidence quality)
    3. Cost / performance    (tokens, cost, latency)
    4. Selector signals      (the three computed scores + which rule fired)
    5. Ground-truth evaluation (populated only when ground_truth is present in the alert)
    """

    # ── 1. Identity ───────────────────────────────────────────────────────────
    alert_id: str
    strategy: str               # "panel_strategy" | "hierarchical_strategy"

    # ── 2. Investigation output ───────────────────────────────────────────────
    verdict: str                # "true_positive" | "false_positive"
    confidence: float
    rationale: str
    mitigation_action: str
    evidence_quality: str       # "low" | "medium" | "high"

    # ── 3. Cost / performance ─────────────────────────────────────────────────
    total_input_tokens: int
    total_output_tokens: int
    estimated_cost_usd: float
    latency_seconds: float

    # ── 4. Selector signals ───────────────────────────────────────────────────
    complexity_score: int
    ambiguity_score: int
    evidence_availability: float
    selector_rule: str          # which rule fired, e.g. "rich_evidence"

    # ── 5. Ground-truth evaluation (None when no ground_truth in alert) ───────
    ground_truth_verdict: Optional[str] = None
    verdict_correct: Optional[bool] = None
    expected_mitigation: Optional[str] = None
    mitigation_correct: Optional[bool] = None
    ground_truth_evidence_quality: Optional[str] = None

    # ── 6. Benchmark bookkeeping (None outside experiments/run_benchmark.py) ──
    # The strategy the selector would pick for this alert, recorded even when
    # this run was forced to the other strategy in --compare-all mode.
    selector_strategy: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


# ─── MetricsCollector ─────────────────────────────────────────────────────────

class MetricsCollector:
    """
    Appends RunResult records to a JSONL file (one JSON object per line).

    Usage:
        collector = MetricsCollector()           # writes to config.RESULTS_FILE
        collector = MetricsCollector("out.jsonl")  # custom path
    """

    def __init__(self, output_path: Optional[str] = None) -> None:
        self.output_path = output_path or config.RESULTS_FILE

    # ── public interface ──────────────────────────────────────────────────────

    def record(self, result: RunResult) -> None:
        """Append a RunResult as a single JSON line to the output file."""
        with open(self.output_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(result.to_dict()) + "\n")

    @staticmethod
    def compute_cost(input_tokens: int, output_tokens: int) -> float:
        """
        Estimate cost in USD using Bedrock Claude 3 Haiku pricing constants.
        Both panel_strategy and hierarchical_strategy use the same model by default.
        """
        input_cost  = (input_tokens  / 1_000) * config.HAIKU_INPUT_COST_PER_1K
        output_cost = (output_tokens / 1_000) * config.HAIKU_OUTPUT_COST_PER_1K
        return round(input_cost + output_cost, 6)
