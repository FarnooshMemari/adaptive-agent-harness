"""
strategies/panel.py — Panel-based multi-perspective investigation strategy.

Four agents analyse the alert from independent professional viewpoints:

  1. Threat Analyst      — threat actor TTPs, attack patterns, intent
  2. Forensics Analyst   — artifact integrity, timeline, indicator authenticity
  3. Risk Critic         — challenges both analyses, rates evidence quality
  4. Consensus Agent     — synthesises all inputs into a final verdict

Flow (sequential):
  Alert → Threat Analyst → Forensics Analyst → Risk Critic → Consensus Agent

The Threat Analyst and Forensics Analyst receive only the alert.
The Risk Critic receives both assessments plus the alert.
The Consensus Agent receives all three outputs plus the alert.
"""

import json
import time

from harness.alert_loader import Alert
from harness.llm_client import BaseLLMClient
from strategies.base import Strategy, extract_json


# ─── System prompts ───────────────────────────────────────────────────────────

_THREAT_ANALYST_SYSTEM = (
    "You are a threat intelligence analyst. Analyze the alert below and assess "
    "whether it represents a genuine attack. Be concise (max 150 words). "
    "Identify specific TTPs or attack patterns from the evidence."
)

_FORENSICS_ANALYST_SYSTEM = (
    "You are a forensic analyst. Examine the artifacts, timeline, and indicators "
    "in the alert below. Assess whether the evidence is authentic and consistent "
    "with malicious activity. Be concise (max 150 words)."
)

_RISK_CRITIC_SYSTEM = (
    "You are a senior security reviewer. You have received two independent assessments "
    "of an alert. Your job is to challenge both: identify gaps, over-confident claims, "
    "and unresolved questions. Also rate the overall evidence quality as low, medium, "
    "or high. Be concise (max 150 words). "
    "Return JSON only — no prose before or after:\n"
    '{"critique": "...", "unresolved_questions": ["..."], "evidence_quality": "low|medium|high"}'
)

_CONSENSUS_SYSTEM = (
    "You are a SOC lead making a final call on an alert. You have three analyst inputs. "
    "Weigh them carefully and produce a final verdict. "
    "Return JSON only — no prose before or after:\n"
    '{"verdict": "true_positive|false_positive", "confidence": 0.0, '
    '"rationale": "...", "mitigation_action": "..."}'
)


# ─── PanelStrategy ────────────────────────────────────────────────────────────

class PanelStrategy(Strategy):
    """
    Panel-based collaboration strategy.

    Receives an LLM client pre-configured for this alert and strategy.
    All four agent calls go through the same client instance.
    """

    def __init__(self, llm_client: BaseLLMClient) -> None:
        self._llm = llm_client

    # ── public interface ──────────────────────────────────────────────────────

    def investigate(self, alert: Alert) -> dict:
        """
        Run the four-agent panel and return the combined result dict.

        Token counts and latency are summed across all four LLM calls.
        """
        t_start = time.perf_counter()
        total_input = 0
        total_output = 0

        alert_json = json.dumps(alert.to_prompt_dict(), indent=2)

        # ── Step 1: Threat Analyst ────────────────────────────────────────────
        resp_threat = self._llm.invoke(
            system=_THREAT_ANALYST_SYSTEM,
            user=f"Alert:\n{alert_json}\n\nProvide your threat assessment.",
        )
        threat_assessment = resp_threat.text
        total_input  += resp_threat.input_tokens
        total_output += resp_threat.output_tokens

        # ── Step 2: Forensics Analyst ─────────────────────────────────────────
        resp_forensics = self._llm.invoke(
            system=_FORENSICS_ANALYST_SYSTEM,
            user=f"Alert:\n{alert_json}\n\nProvide your forensics assessment.",
        )
        forensics_assessment = resp_forensics.text
        total_input  += resp_forensics.input_tokens
        total_output += resp_forensics.output_tokens

        # ── Step 3: Risk Critic ───────────────────────────────────────────────
        resp_critic = self._llm.invoke(
            system=_RISK_CRITIC_SYSTEM,
            user=(
                f"Alert:\n{alert_json}\n\n"
                f"Threat Analyst assessment:\n{threat_assessment}\n\n"
                f"Forensics Analyst assessment:\n{forensics_assessment}\n\n"
                "Provide your critique and evidence quality rating."
            ),
        )
        total_input  += resp_critic.input_tokens
        total_output += resp_critic.output_tokens

        critic_data = _parse_critic(resp_critic.text)

        # ── Step 4: Consensus Agent ───────────────────────────────────────────
        resp_consensus = self._llm.invoke(
            system=_CONSENSUS_SYSTEM,
            user=(
                f"Alert:\n{alert_json}\n\n"
                f"Threat Analyst:\n{threat_assessment}\n\n"
                f"Forensics Analyst:\n{forensics_assessment}\n\n"
                f"Risk Critic:\n{resp_critic.text}\n\n"
                "Produce the final verdict."
            ),
        )
        total_input  += resp_consensus.input_tokens
        total_output += resp_consensus.output_tokens

        consensus_data = _parse_consensus(resp_consensus.text)

        latency_ms = (time.perf_counter() - t_start) * 1_000

        return {
            "verdict":            consensus_data["verdict"],
            "confidence":         float(consensus_data.get("confidence", 0.0)),
            "rationale":          consensus_data.get("rationale", ""),
            "mitigation_action":  consensus_data.get("mitigation_action", ""),
            "evidence_quality":   critic_data.get("evidence_quality", "medium"),
            "total_input_tokens":  total_input,
            "total_output_tokens": total_output,
            "latency_ms":         latency_ms,
            # Strategy-specific detail
            "assessments": {
                "threat":    threat_assessment,
                "forensics": forensics_assessment,
                "critic":    resp_critic.text,
            },
        }


# ─── Parsing helpers ──────────────────────────────────────────────────────────

def _parse_critic(text: str) -> dict:
    """
    Parse Risk Critic JSON response.
    Falls back to safe defaults if parsing fails so the pipeline continues.
    """
    try:
        data = extract_json(text)
        # Normalise evidence_quality to the allowed set
        eq = data.get("evidence_quality", "medium").lower()
        if eq not in {"low", "medium", "high"}:
            eq = "medium"
        data["evidence_quality"] = eq
        return data
    except (ValueError, KeyError):
        return {
            "critique": text,
            "unresolved_questions": [],
            "evidence_quality": "medium",
        }


def _parse_consensus(text: str) -> dict:
    """
    Parse Consensus Agent JSON response.
    Falls back to conservative defaults if parsing fails.
    """
    try:
        data = extract_json(text)
        # Normalise verdict
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
