"""
strategies/hierarchical.py — Hierarchical multi-specialist investigation strategy.

Five agents run in a structured delegation chain:

  1. Evidence Validator      — assesses quality/reliability of raw evidence (always first)
  2. Lead Investigator       — decomposes alert into two specialist questions
  3. Network Analyst         — answers the network-focused question
  4. Threat Intel Analyst    — answers the threat intelligence question
  5. Lead Investigator (synthesis) — synthesises all findings into final verdict

Flow (sequential):
  Alert
    → Evidence Validator          (evidence_report)
    → Lead Investigator decompose (network_question, threat_intel_question)
    → Network Analyst             (network_finding)
    → Threat Intel Analyst        (threat_intel_finding)
    → Lead Investigator synthesise (verdict, confidence, rationale, mitigation)

The Evidence Validator result is passed to every subsequent agent so they can
calibrate their confidence based on evidence reliability.
"""

import json
import time

from harness.alert_loader import Alert
from harness.llm_client import BaseLLMClient
from strategies.base import Strategy, extract_json


# ─── System prompts ───────────────────────────────────────────────────────────

_EVIDENCE_VALIDATOR_SYSTEM = (
    "You are a forensic evidence quality analyst. Assess the raw evidence in the "
    "alert below for completeness, internal consistency, and reliability. Identify "
    "any gaps or red flags. "
    "Return JSON only — no prose before or after:\n"
    '{"quality": "low|medium|high", "gaps": ["..."], "reliable": true, "notes": "..."}'
)

_LEAD_DECOMPOSE_SYSTEM = (
    "You are a senior SOC analyst. Given the alert and evidence quality report below, "
    "generate exactly 2 investigation questions: one about network indicators, one about "
    "threat intelligence context. "
    "Return JSON only — no prose before or after:\n"
    '{"network_question": "...", "threat_intel_question": "..."}'
)

_NETWORK_ANALYST_SYSTEM = (
    "You are a network security analyst. Answer the investigation question below "
    "using the alert evidence provided. Be concise and factual (max 150 words). "
    "Note the evidence reliability rating from the evidence report when drawing conclusions."
)

_THREAT_INTEL_SYSTEM = (
    "You are a threat intelligence analyst. Answer the investigation question below "
    "using the alert evidence and threat intelligence context. "
    "Be concise and factual (max 150 words). "
    "Account for evidence quality when stating confidence."
)

_LEAD_SYNTHESISE_SYSTEM = (
    "You are a senior SOC analyst making a final determination. Synthesise all findings "
    "below into a verdict. Account for evidence quality when setting confidence — "
    "low-quality evidence should reduce confidence even if findings suggest malicious activity. "
    "Return JSON only — no prose before or after:\n"
    '{"verdict": "true_positive|false_positive", "confidence": 0.0, '
    '"rationale": "...", "mitigation_action": "..."}'
)


# ─── HierarchicalStrategy ─────────────────────────────────────────────────────

class HierarchicalStrategy(Strategy):
    """
    Hierarchical collaboration strategy.

    Receives an LLM client pre-configured for this alert and strategy.
    All five agent calls go through the same client instance.
    """

    def __init__(self, llm_client: BaseLLMClient) -> None:
        self._llm = llm_client

    # ── public interface ──────────────────────────────────────────────────────

    def investigate(self, alert: Alert) -> dict:
        """
        Run the five-agent hierarchical pipeline and return the combined result dict.

        Token counts and latency are summed across all five LLM calls.
        """
        t_start = time.perf_counter()
        total_input = 0
        total_output = 0

        alert_json = json.dumps(alert.to_prompt_dict(), indent=2)

        # ── Step 1: Evidence Validator ────────────────────────────────────────
        resp_ev = self._llm.invoke(
            system=_EVIDENCE_VALIDATOR_SYSTEM,
            user=f"Alert:\n{alert_json}\n\nAssess the evidence quality.",
        )
        total_input  += resp_ev.input_tokens
        total_output += resp_ev.output_tokens

        evidence_data   = _parse_evidence_report(resp_ev.text)
        evidence_report = resp_ev.text   # pass raw text to downstream agents

        # ── Step 2: Lead Investigator — decompose ─────────────────────────────
        resp_decompose = self._llm.invoke(
            system=_LEAD_DECOMPOSE_SYSTEM,
            user=(
                f"Alert:\n{alert_json}\n\n"
                f"Evidence quality report:\n{evidence_report}\n\n"
                "Generate the two investigation questions."
            ),
        )
        total_input  += resp_decompose.input_tokens
        total_output += resp_decompose.output_tokens

        questions = _parse_questions(resp_decompose.text)
        network_question     = questions.get("network_question", "Analyse network indicators.")
        threat_intel_question = questions.get("threat_intel_question", "Analyse threat intel context.")

        # ── Step 3: Network Analyst ───────────────────────────────────────────
        resp_network = self._llm.invoke(
            system=_NETWORK_ANALYST_SYSTEM,
            user=(
                f"Alert:\n{alert_json}\n\n"
                f"Evidence quality report:\n{evidence_report}\n\n"
                f"Investigation question: {network_question}"
            ),
        )
        network_finding = resp_network.text
        total_input  += resp_network.input_tokens
        total_output += resp_network.output_tokens

        # ── Step 4: Threat Intel Analyst ──────────────────────────────────────
        resp_threat = self._llm.invoke(
            system=_THREAT_INTEL_SYSTEM,
            user=(
                f"Alert:\n{alert_json}\n\n"
                f"Evidence quality report:\n{evidence_report}\n\n"
                f"Investigation question: {threat_intel_question}"
            ),
        )
        threat_intel_finding = resp_threat.text
        total_input  += resp_threat.input_tokens
        total_output += resp_threat.output_tokens

        # ── Step 5: Lead Investigator — synthesise ────────────────────────────
        resp_synthesis = self._llm.invoke(
            system=_LEAD_SYNTHESISE_SYSTEM,
            user=(
                f"Alert:\n{alert_json}\n\n"
                f"Evidence report:\n{evidence_report}\n\n"
                f"Network finding:\n{network_finding}\n\n"
                f"Threat intel finding:\n{threat_intel_finding}\n\n"
                "Produce the final verdict."
            ),
        )
        total_input  += resp_synthesis.input_tokens
        total_output += resp_synthesis.output_tokens

        synthesis_data = _parse_synthesis(resp_synthesis.text)

        latency_ms = (time.perf_counter() - t_start) * 1_000

        return {
            "verdict":            synthesis_data["verdict"],
            "confidence":         float(synthesis_data.get("confidence", 0.0)),
            "rationale":          synthesis_data.get("rationale", ""),
            "mitigation_action":  synthesis_data.get("mitigation_action", ""),
            "evidence_quality":   evidence_data.get("quality", "medium"),
            "total_input_tokens":  total_input,
            "total_output_tokens": total_output,
            "latency_ms":         latency_ms,
            # Strategy-specific detail
            "sub_findings": {
                "evidence_validation": evidence_report,
                "network":             network_finding,
                "threat_intel":        threat_intel_finding,
            },
        }


# ─── Parsing helpers ──────────────────────────────────────────────────────────

def _parse_evidence_report(text: str) -> dict:
    """Parse Evidence Validator JSON. Falls back to medium quality on error."""
    try:
        data = extract_json(text)
        quality = data.get("quality", "medium").lower()
        if quality not in {"low", "medium", "high"}:
            quality = "medium"
        data["quality"] = quality
        return data
    except (ValueError, KeyError):
        return {"quality": "medium", "gaps": [], "reliable": True, "notes": text[:200]}


def _parse_questions(text: str) -> dict:
    """Parse Lead Investigator decomposition JSON. Falls back to generic questions."""
    try:
        return extract_json(text)
    except (ValueError, KeyError):
        return {
            "network_question": "Analyse all network indicators in the evidence.",
            "threat_intel_question": "Identify threat actor TTPs relevant to this alert.",
        }


def _parse_synthesis(text: str) -> dict:
    """Parse Lead Investigator synthesis JSON. Falls back to conservative defaults."""
    try:
        data = extract_json(text)
        verdict = data.get("verdict", "").lower()
        if verdict not in {"true_positive", "false_positive"}:
            verdict = "false_positive"
        data["verdict"] = verdict
        return data
    except (ValueError, KeyError):
        return {
            "verdict": "false_positive",
            "confidence": 0.0,
            "rationale": f"[parse error] raw response: {text[:200]}",
            "mitigation_action": "Manual review required",
        }
