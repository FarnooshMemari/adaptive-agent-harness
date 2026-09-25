"""
harness/alert_loader.py — Alert dataclass and AlertLoader.

AlertLoader validates and deserialises alert JSON files into Alert objects.
The Alert dataclass is a plain data holder with no validation logic of its own.

v2 additions (benchmark expansion):
  - New fields: title, category, context, indicators
  - ground_truth gains preferred_strategy (for analysis only — selector must NOT use it)
  - VALID_TYPES expanded with four benchmark categories; original types kept for
    backward compatibility with the first 12 alerts
"""

import json
from dataclasses import dataclass, field
from typing import Optional

# ─── Valid field values ───────────────────────────────────────────────────────

# Original alert types (ALT-001 to ALT-012) kept for backward compatibility.
# New benchmark categories used for ALT-013 onward.
VALID_TYPES = {
    # Original types
    "phishing",
    "lateral_movement",
    "data_exfiltration",
    "malware_execution",
    # Benchmark categories
    "credential_compromise",
    "suspicious_access",
    "malware_like_behavior",
    "privilege_escalation",
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_STRATEGIES = {"panel_strategy", "hierarchical_strategy"}

# Core fields required on every alert.
REQUIRED_FIELDS = {"alert_id", "type", "severity", "description", "raw_evidence"}


# ─── Alert dataclass ──────────────────────────────────────────────────────────

@dataclass
class Alert:
    """
    Represents a single cybersecurity alert.

    Core fields (all alerts):
        alert_id        : unique identifier, e.g. "ALT-013"
        type            : alert type / benchmark category
        severity        : "low" | "medium" | "high" | "critical"
        description     : free-text summary of what was observed
        raw_evidence    : logs, process data, network events (used by selector signals)

    Extended fields (benchmark alerts, optional on legacy alerts):
        title           : short human-readable title
        category        : one of the four benchmark categories
                          ("credential_compromise" | "suspicious_access" |
                           "malware_like_behavior" | "privilege_escalation")
        context         : additional operational context not in raw_evidence
        indicators      : key IOCs / behavioural indicators as a plain string

    ground_truth (optional, present on labelled datasets):
        verdict              : "true_positive" | "false_positive"
        expected_mitigation  : short action description
        evidence_quality     : "low" | "medium" | "high"
        preferred_strategy   : "panel_strategy" | "hierarchical_strategy"
                               *** FOR ANALYSIS ONLY — selector must NOT read this ***
    """
    # ── Required ──────────────────────────────────────────────────────────────
    alert_id: str
    type: str
    severity: str
    description: str
    raw_evidence: str

    # ── Optional extended fields ──────────────────────────────────────────────
    title: Optional[str] = field(default=None)
    category: Optional[str] = field(default=None)
    context: Optional[str] = field(default=None)
    indicators: Optional[str] = field(default=None)

    # ── Ground truth ──────────────────────────────────────────────────────────
    ground_truth: Optional[dict] = field(default=None)

    def to_dict(self) -> dict:
        """Serialise to a plain dict suitable for JSON encoding."""
        return {
            "alert_id":    self.alert_id,
            "type":        self.type,
            "severity":    self.severity,
            "description": self.description,
            "raw_evidence": self.raw_evidence,
            "title":       self.title,
            "category":    self.category,
            "context":     self.context,
            "indicators":  self.indicators,
            "ground_truth": self.ground_truth,
        }

    def to_prompt_dict(self) -> dict:
        """
        Serialise for LLM prompts. Excludes ground_truth so agents never see the
        expected verdict, mitigation, or preferred_strategy label.
        """
        data = self.to_dict()
        data.pop("ground_truth")
        return data


# ─── AlertLoader ──────────────────────────────────────────────────────────────

class AlertLoader:
    """
    Reads and validates alert JSON files.

    Supports two formats:
    - Single alert: a JSON object  → load()
    - Alert batch:  a JSON array   → load_batch()
    """

    # ── public interface ──────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: str) -> Alert:
        """Load and validate a single alert from a JSON object file."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError(
                f"{path}: expected a JSON object for a single alert, "
                f"got {type(data).__name__}"
            )
        return cls._parse(data, source=path)

    @classmethod
    def load_batch(cls, path: str) -> list[Alert]:
        """Load and validate a list of alerts from a JSON array file."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise ValueError(
                f"{path}: expected a JSON array for a batch, "
                f"got {type(data).__name__}"
            )
        return [cls._parse(item, source=f"{path}[{i}]") for i, item in enumerate(data)]

    # ── private helpers ───────────────────────────────────────────────────────

    @classmethod
    def _parse(cls, data: dict, source: str) -> Alert:
        """Validate a raw dict and return an Alert. Raises ValueError on bad input."""
        cls._check_required_fields(data, source)
        cls._check_enum("type", data["type"], VALID_TYPES, source)
        cls._check_enum("severity", data["severity"], VALID_SEVERITIES, source)

        ground_truth = data.get("ground_truth")
        if ground_truth is not None:
            cls._check_ground_truth(ground_truth, source)

        return Alert(
            alert_id=str(data["alert_id"]),
            type=data["type"],
            severity=data["severity"],
            description=data["description"],
            raw_evidence=data["raw_evidence"],
            title=data.get("title"),
            category=data.get("category"),
            context=data.get("context"),
            indicators=data.get("indicators"),
            ground_truth=ground_truth,
        )

    @staticmethod
    def _check_required_fields(data: dict, source: str) -> None:
        missing = REQUIRED_FIELDS - data.keys()
        if missing:
            raise ValueError(
                f"{source}: missing required field(s): {sorted(missing)}"
            )

    @staticmethod
    def _check_enum(field_name: str, value: str, valid: set, source: str) -> None:
        if value not in valid:
            raise ValueError(
                f"{source}: invalid {field_name!r} value {value!r}. "
                f"Must be one of: {sorted(valid)}"
            )

    @staticmethod
    def _check_ground_truth(gt: dict, source: str) -> None:
        required = {"verdict", "expected_mitigation", "evidence_quality"}
        missing = required - gt.keys()
        if missing:
            raise ValueError(
                f"{source}: ground_truth is missing field(s): {sorted(missing)}"
            )
        valid_verdicts = {"true_positive", "false_positive"}
        if gt["verdict"] not in valid_verdicts:
            raise ValueError(
                f"{source}: ground_truth.verdict must be one of {sorted(valid_verdicts)}, "
                f"got {gt['verdict']!r}"
            )
        valid_quality = {"low", "medium", "high"}
        if gt["evidence_quality"] not in valid_quality:
            raise ValueError(
                f"{source}: ground_truth.evidence_quality must be one of "
                f"{sorted(valid_quality)}, got {gt['evidence_quality']!r}"
            )
        # preferred_strategy is optional; validate only if present
        ps = gt.get("preferred_strategy")
        if ps is not None and ps not in VALID_STRATEGIES:
            raise ValueError(
                f"{source}: ground_truth.preferred_strategy must be one of "
                f"{sorted(VALID_STRATEGIES)}, got {ps!r}"
            )
