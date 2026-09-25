"""
harness/llm_client.py — LLM client abstraction.

Three classes:
  BaseLLMClient   — abstract interface; all strategy code depends only on this
  MockLLMClient   — deterministic alert-keyed responses loaded from mock_responses.json
  BedrockLLMClient — Amazon Bedrock (Claude Messages API) with retry on throttling

Factory:
  get_llm_client(alert_id, strategy) -> BaseLLMClient
      Returns the correct backend based on config.LLM_BACKEND.
      All strategy code calls this factory; no direct backend instantiation.
"""

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

import config

# ─── Logging setup ────────────────────────────────────────────────────────────

os.makedirs(config.LOGS_DIR, exist_ok=True)

_log = logging.getLogger("llm_client")
_log.setLevel(logging.DEBUG)

_file_handler = logging.FileHandler(
    os.path.join(config.LOGS_DIR, "llm_client.log"), encoding="utf-8"
)
_file_handler.setFormatter(
    logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s")
)
_log.addHandler(_file_handler)


# ─── LLMResponse ─────────────────────────────────────────────────────────────

@dataclass
class LLMResponse:
    """Normalised response returned by every backend."""
    text: str
    input_tokens: int
    output_tokens: int
    latency_ms: float


# ─── BaseLLMClient ────────────────────────────────────────────────────────────

class BaseLLMClient(ABC):
    """
    Abstract LLM client interface.

    Concrete implementations must override invoke().
    Strategy code must never reference MockLLMClient or BedrockLLMClient directly;
    it always receives a BaseLLMClient from get_llm_client().
    """

    @abstractmethod
    def invoke(self, system: str, user: str) -> LLMResponse:
        """
        Call the LLM with a system prompt and a user message.

        Args:
            system: System-role instruction string.
            user:   User-role message string.

        Returns:
            LLMResponse with text, token counts, and latency.
        """


# ─── MockLLMClient ────────────────────────────────────────────────────────────

# Agent-role keywords used to identify which canned response to return.
# Order matters: more specific phrases checked before generic ones.
_PANEL_ROLE_KEYWORDS = {
    "threat_assessment":     "threat intelligence analyst",
    "forensics_assessment":  "forensic analyst",       # more specific than "forensic"
    "critic_report":         "senior security reviewer",
    "consensus":             "soc lead",
}

_HIER_ROLE_KEYWORDS = {
    "evidence_validation":   "forensic evidence quality analyst",
    "decomposition":         "generate exactly 2 investigation questions",
    "network_finding":       "network",
    "threat_intel_finding":  "threat intelligence context",
    "synthesis":             "final determination",
}


class MockLLMClient(BaseLLMClient):
    """
    Deterministic mock LLM client for local development and pipeline validation.

    Responses are keyed by (alert_id, strategy, agent_role) and loaded from
    data/mock_responses.json at construction time.  The same alert always
    produces the same response regardless of call order.

    Token counts are estimated from prompt lengths so that cost and latency
    metrics are non-zero and vary across alerts.
    """

    def __init__(self, alert_id: str, strategy: str) -> None:
        """
        Args:
            alert_id: e.g. "ALT-001" — used to look up the correct mock entry.
            strategy: "panel_strategy" | "hierarchical_strategy"
        """
        self.alert_id = alert_id
        self.strategy = strategy
        self._responses: dict = self._load_responses(alert_id, strategy)

    # ── public interface ──────────────────────────────────────────────────────

    def invoke(self, system: str, user: str) -> LLMResponse:
        role = self._detect_role(system)
        text = self._responses.get(role, f"[mock] No response defined for role '{role}'")

        # Estimate tokens from character length (≈ 4 chars per token)
        input_tokens  = max(1, (len(system) + len(user)) // 4)
        output_tokens = max(1, len(text) // 4)

        _log.debug(
            "[MOCK] alert=%s strategy=%s role=%s | in=%d out=%d tokens",
            self.alert_id, self.strategy, role, input_tokens, output_tokens,
        )

        return LLMResponse(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=0.0,
        )

    # ── private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _load_responses(alert_id: str, strategy: str) -> dict:
        """Load and return the agent-role → response dict for this alert + strategy."""
        path = config.MOCK_RESPONSES_FILE
        with open(path, "r", encoding="utf-8") as fh:
            all_responses = json.load(fh)

        if alert_id not in all_responses:
            raise KeyError(
                f"MockLLMClient: no mock responses found for alert_id={alert_id!r} "
                f"in {path}"
            )
        strategy_responses = all_responses[alert_id].get(strategy)
        if strategy_responses is None:
            raise KeyError(
                f"MockLLMClient: no mock responses for strategy={strategy!r} "
                f"under alert_id={alert_id!r} in {path}"
            )
        return strategy_responses

    @staticmethod
    def _detect_role(system: str) -> str:
        """
        Identify the agent role from the system prompt text.
        Checks panel keywords first, then hierarchical keywords.
        Falls back to 'unknown' if no match found.
        """
        lower = system.lower()

        for role, keyword in _PANEL_ROLE_KEYWORDS.items():
            if keyword in lower:
                return role

        for role, keyword in _HIER_ROLE_KEYWORDS.items():
            if keyword in lower:
                return role

        _log.warning("MockLLMClient: could not detect role from system prompt: %s", system[:80])
        return "unknown"


# ─── BedrockLLMClient ─────────────────────────────────────────────────────────

class BedrockLLMClient(BaseLLMClient):
    """
    Amazon Bedrock LLM client using the Claude Messages API.

    Requires valid AWS credentials (env vars, ~/.aws/credentials, or IAM role)
    and config.BEDROCK_MODEL_ID to be set.

    Retries up to 3 times on ThrottlingException with exponential backoff.
    Logs every prompt and response to logs/llm_client.log.
    """

    _MAX_RETRIES = 3
    _BACKOFF_BASE = 2.0   # seconds; doubles on each retry

    def __init__(self) -> None:
        # Import boto3 lazily so the rest of the codebase works without it
        import boto3  # noqa: PLC0415
        self._client = boto3.client(
            "bedrock-runtime", region_name=config.AWS_REGION
        )

    # ── public interface ──────────────────────────────────────────────────────

    def invoke(self, system: str, user: str) -> LLMResponse:
        payload = self._build_payload(system, user)
        _log.debug("[BEDROCK] Sending request | model=%s", config.BEDROCK_MODEL_ID)
        _log.debug("[BEDROCK] system=%s", system[:200])
        _log.debug("[BEDROCK] user=%s", user[:200])

        for attempt in range(1, self._MAX_RETRIES + 1):
            try:
                t0 = time.perf_counter()
                raw = self._client.invoke_model(
                    modelId=config.BEDROCK_MODEL_ID,
                    body=json.dumps(payload),
                    contentType="application/json",
                    accept="application/json",
                )
                latency_ms = (time.perf_counter() - t0) * 1_000

                body = json.loads(raw["body"].read())
                text = body["content"][0]["text"]
                usage = body.get("usage", {})
                input_tokens  = usage.get("input_tokens", 0)
                output_tokens = usage.get("output_tokens", 0)

                _log.debug(
                    "[BEDROCK] Response | in=%d out=%d tokens | %.0fms",
                    input_tokens, output_tokens, latency_ms,
                )
                _log.debug("[BEDROCK] text=%s", text[:400])

                return LLMResponse(
                    text=text,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    latency_ms=latency_ms,
                )

            except Exception as exc:  # noqa: BLE001
                exc_name = type(exc).__name__
                if "ThrottlingException" in exc_name and attempt < self._MAX_RETRIES:
                    wait = self._BACKOFF_BASE ** attempt
                    _log.warning(
                        "[BEDROCK] ThrottlingException on attempt %d/%d — retrying in %.1fs",
                        attempt, self._MAX_RETRIES, wait,
                    )
                    time.sleep(wait)
                else:
                    _log.error("[BEDROCK] Fatal error on attempt %d: %s", attempt, exc)
                    raise

        # Should never reach here
        raise RuntimeError("BedrockLLMClient: exhausted retries")  # pragma: no cover

    # ── private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _build_payload(system: str, user: str) -> dict:
        """Format a Claude Messages API request payload."""
        return {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": config.MAX_TOKENS,
            "temperature": config.TEMPERATURE,
            "system": system,
            "messages": [
                {"role": "user", "content": user}
            ],
        }


# ─── Factory ──────────────────────────────────────────────────────────────────

def get_llm_client(
    alert_id: Optional[str] = None,
    strategy: Optional[str] = None,
) -> BaseLLMClient:
    """
    Return the appropriate LLM client based on config.LLM_BACKEND.

    Args:
        alert_id: Required when LLM_BACKEND == "mock".
        strategy: Required when LLM_BACKEND == "mock".
                  Must be "panel_strategy" or "hierarchical_strategy".

    Returns:
        BaseLLMClient instance ready to call .invoke().
    """
    if config.LLM_BACKEND == "bedrock":
        return BedrockLLMClient()

    # Default: mock
    if not alert_id or not strategy:
        raise ValueError(
            "get_llm_client() requires alert_id and strategy when LLM_BACKEND='mock'"
        )
    return MockLLMClient(alert_id=alert_id, strategy=strategy)
