"""
harness/selector.py — Adaptive strategy selector.

StrategySelector maps an Alert to either "panel_strategy" or
"hierarchical_strategy" using three deterministic signal scores computed
directly from alert fields (no LLM call required).

Interface is intentionally simple so it can be swapped out for a contextual
bandit or learned policy in the future without changing any call sites.
"""

import logging
import os
import re
from dataclasses import dataclass

import config
from harness.alert_loader import Alert

# ─── Logging setup ────────────────────────────────────────────────────────────

os.makedirs(config.LOGS_DIR, exist_ok=True)

_log = logging.getLogger("selector")
_log.setLevel(logging.DEBUG)

_file_handler = logging.FileHandler(
    os.path.join(config.LOGS_DIR, "selector.log"), encoding="utf-8"
)
_file_handler.setFormatter(
    logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s")
)
_log.addHandler(_file_handler)


# ─── Signal computation helpers ───────────────────────────────────────────────

# Regex patterns for distinct indicator types in raw_evidence.
# Each pattern represents one indicator *type* (not occurrence count).
_INDICATOR_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ip_address",   re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    ("file_hash",    re.compile(r"\b[a-fA-F0-9]{32,64}\b")),
    ("domain",       re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}\b"
    )),
    ("user_account", re.compile(
        r"\b(?:user|account|svc_|admin_|dev_)\w+\b", re.IGNORECASE
    )),
    ("process_name", re.compile(
        r"\b\w+\.exe\b|\b/(?:bin|usr/bin|sbin)/\w+\b", re.IGNORECASE
    )),
]

# Hedging keywords that signal ambiguity.
_AMBIGUITY_KEYWORDS = [
    "possibly", "unclear", "could be", "might", "unconfirmed",
    "legitimate", "normal",
]

# Evidence fields used for availability scoring.
_EVIDENCE_FIELDS = ["raw_evidence", "description", "type", "severity"]


# ─── Signals dataclass ────────────────────────────────────────────────────────

@dataclass
class Signals:
    complexity: int             # 0–5: distinct indicator types found
    ambiguity: int              # 0–3: hedging keyword count (capped)
    evidence_availability: float  # 0.0–1.0: fraction of expected fields present


# ─── StrategySelector ─────────────────────────────────────────────────────────

class StrategySelector:
    """
    Rule-based strategy selector.

    Usage:
        selector = StrategySelector()
        signals  = selector.compute_signals(alert)
        strategy, rule = selector.select(alert)
        # strategy is "panel_strategy" or "hierarchical_strategy"
        # rule    is the name of the matched rule (for logging / RunResult)

    Replacing this class with a learned policy requires no changes elsewhere
    as long as the return signature of select() is preserved.
    """

    # ── public interface ──────────────────────────────────────────────────────

    def compute_signals(self, alert: Alert) -> Signals:
        """Compute the three selection signals from alert fields."""
        complexity           = self._complexity(alert.raw_evidence)
        ambiguity            = self._ambiguity(alert.description, alert.raw_evidence)
        evidence_availability = self._evidence_availability(alert)
        return Signals(
            complexity=complexity,
            ambiguity=ambiguity,
            evidence_availability=evidence_availability,
        )

    def select(self, alert: Alert) -> tuple[str, str]:
        """
        Select a strategy for the given alert.

        Returns:
            (strategy_name, rule_name)
            strategy_name: "panel_strategy" | "hierarchical_strategy"
            rule_name:     label of the matched rule
        """
        signals = self.compute_signals(alert)
        strategy, rule = self._apply_rules(alert, signals)

        _log.info(
            "alert=%s | complexity=%d ambiguity=%d availability=%.2f "
            "| rule=%s → %s",
            alert.alert_id,
            signals.complexity,
            signals.ambiguity,
            signals.evidence_availability,
            rule,
            strategy,
        )

        return strategy, rule

    # ── rule engine ───────────────────────────────────────────────────────────

    @staticmethod
    def _apply_rules(alert: Alert, s: Signals) -> tuple[str, str]:
        """
        Evaluate rules in priority order; return on first match.

        Rules (priority order):
        1. rich_evidence    — complexity ≥ threshold AND availability ≥ 0.75
                             → hierarchical (rich multi-domain evidence)
        2. ambiguous        — ambiguity ≥ threshold
                             → panel (adversarial scrutiny for unclear signals)
        3. critical_severity — severity == "critical"
                             → hierarchical (high-stakes, thorough analysis)
        4. sparse_evidence  — availability < threshold
                             → panel (adversarial challenge on weak data)
        5. default          — everything else
                             → panel (faster, lower cost)
        """
        if (s.complexity >= config.COMPLEXITY_THRESHOLD
                and s.evidence_availability >= 0.75):
            return "hierarchical_strategy", "rich_evidence"

        if s.ambiguity >= config.AMBIGUITY_THRESHOLD:
            return "panel_strategy", "ambiguous"

        if alert.severity == "critical":
            return "hierarchical_strategy", "critical_severity"

        if s.evidence_availability < config.EVIDENCE_AVAILABILITY_THRESHOLD:
            return "panel_strategy", "sparse_evidence"

        return "panel_strategy", "default"

    # ── signal computation ────────────────────────────────────────────────────

    @staticmethod
    def _complexity(raw_evidence: str) -> int:
        """
        Count distinct indicator *types* present in raw_evidence.
        Each type (IP, hash, domain, user account, process) scores at most 1.
        Maximum score: 5.
        """
        count = 0
        for _name, pattern in _INDICATOR_PATTERNS:
            if pattern.search(raw_evidence):
                count += 1
        return count

    @staticmethod
    def _ambiguity(description: str, raw_evidence: str) -> int:
        """
        Count hedging keyword occurrences across description + raw_evidence.
        Result is capped at 3 to prevent a single verbose alert from dominating.
        """
        text  = (description + " " + raw_evidence).lower()
        count = sum(1 for kw in _AMBIGUITY_KEYWORDS if kw in text)
        return min(count, 3)

    @staticmethod
    def _evidence_availability(alert: Alert) -> float:
        """
        Fraction of expected evidence fields that are non-empty.
        Expected fields: raw_evidence, description, type, severity.
        """
        populated = sum(
            1 for field in _EVIDENCE_FIELDS
            if getattr(alert, field, None)
        )
        return populated / len(_EVIDENCE_FIELDS)
