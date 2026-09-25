"""
strategies/base.py — Strategy abstract base class and shared utilities.

All strategy implementations subclass Strategy and override investigate().
The extract_json() helper is used by both strategies to parse JSON from
LLM response text that may contain surrounding prose.
"""

import json
import re
from abc import ABC, abstractmethod

from harness.alert_loader import Alert


# ─── Strategy ABC ─────────────────────────────────────────────────────────────

class Strategy(ABC):
    """
    Abstract base class for investigation strategies.

    Both PanelStrategy and HierarchicalStrategy implement this interface.
    run.py and any future orchestration code depend only on this class.
    """

    @abstractmethod
    def investigate(self, alert: Alert) -> dict:
        """
        Investigate an alert and return a result dict.

        Required keys in the returned dict:
            verdict          : "true_positive" | "false_positive"
            confidence       : float 0.0–1.0
            rationale        : str
            mitigation_action: str
            evidence_quality : "low" | "medium" | "high"
            total_input_tokens : int
            total_output_tokens: int
            latency_ms       : float   (sum across all LLM calls)

        Strategy-specific keys may be added (e.g. assessments, sub_findings).
        """


# ─── Shared utilities ─────────────────────────────────────────────────────────

def extract_json(text: str) -> dict:
    """
    Extract the first JSON object from an LLM response string.

    Handles three common LLM output patterns:
    1. Pure JSON:          {"key": "value"}
    2. Markdown code block: ```json\n{...}\n```
    3. JSON embedded in prose: "Here is my analysis: {...} Thank you."

    Args:
        text: Raw LLM response text.

    Returns:
        Parsed dict.

    Raises:
        ValueError: If no valid JSON object is found in the text.
    """
    # Strip markdown code fences if present
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        candidate = fenced.group(1)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # Find the outermost {...} span in the text
    start = text.find("{")
    if start == -1:
        raise ValueError(f"No JSON object found in response: {text[:200]!r}")

    # Walk forward tracking brace depth to find the matching closing brace
    depth = 0
    for i, ch in enumerate(text[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Found JSON-like block but could not parse it: {exc}\n"
                        f"Block: {candidate[:300]!r}"
                    ) from exc

    raise ValueError(f"Unmatched braces in response: {text[:200]!r}")
