# Agent Prompt and Role Design

## Guiding principle

Every agent prompt in this project encodes a **specific professional role** that constrains what the agent analyses and how it responds. Agents do not have general instructions like "analyse this alert" — they have a defined scope, a defined output format, and a defined word limit. This keeps token costs bounded and makes JSON parsing reliable.

## The two strategies and their agents

### Panel strategy (`strategies/panel.py`)

Sequential flow: Threat Analyst → Forensics Analyst → Risk Critic → Consensus Agent.

| Agent | System prompt keyword (used by MockLLMClient) | Role scope | Output format |
|---|---|---|---|
| Threat Analyst | `"threat intelligence analyst"` | TTPs, attack patterns, intent | Free prose, max 150 words |
| Forensics Analyst | `"forensic analyst"` | Artifact integrity, timeline, indicator authenticity | Free prose, max 150 words |
| Risk Critic | `"senior security reviewer"` | Challenge both analyses, rate evidence quality | JSON: `{"critique", "unresolved_questions", "evidence_quality"}` |
| Consensus Agent | `"soc lead"` | Synthesise into final verdict | JSON: `{"verdict", "confidence", "rationale", "mitigation_action"}` |

**The Risk Critic is the only agent that produces `evidence_quality`.** The Consensus Agent does not re-rate evidence — it uses the Critic's rating. Do not move evidence quality production to a different agent without updating `_parse_critic()` and the RunResult population in `run.py`.

### Hierarchical strategy (`strategies/hierarchical.py`)

Sequential flow: Evidence Validator → Lead Investigator (decompose) → Network Analyst → Threat Intel Analyst → Lead Investigator (synthesise).

| Agent | System prompt keyword (used by MockLLMClient) | Role scope | Output format |
|---|---|---|---|
| Evidence Validator | `"forensic evidence quality analyst"` | Evidence completeness, consistency, reliability | JSON: `{"quality", "gaps", "reliable", "notes"}` |
| Lead Investigator (decompose) | `"generate exactly 2 investigation questions"` | Decompose into network + threat intel questions | JSON: `{"network_question", "threat_intel_question"}` |
| Network Analyst | `"network"` | Answer the network-focused question | Free prose, max 150 words |
| Threat Intel Analyst | `"threat intelligence context"` | Answer the threat intel question | Free prose, max 150 words |
| Lead Investigator (synthesise) | `"final determination"` | Synthesise all findings into verdict | JSON: `{"verdict", "confidence", "rationale", "mitigation_action"}` |

**Evidence Validator runs first, always.** Its `reliable` flag and `quality` rating are passed to every downstream agent. Do not reorder this step.

## Prompt design rules

**1. Keep system prompts under 80 words.** Every system prompt currently fits comfortably. Longer prompts cost more tokens and dilute the role focus.

**2. JSON-only agents must say "Return JSON only — no prose before or after" explicitly.** This phrase is load-bearing — `extract_json()` in `strategies/base.py` handles extra prose gracefully, but it is slower and less reliable than a clean JSON response. Keep the instruction.

**3. Word limits belong in system prompts, not user prompts.** The `"Be concise (max 150 words)"` instruction is in the system prompt for prose agents. User prompt length grows with alert size; the word limit counterbalances that.

**4. Never include `ground_truth` in any prompt.** Agents must never see the expected verdict, expected mitigation, or `preferred_strategy` label. The `alert.to_prompt_dict()` method (in `harness/alert_loader.py`) explicitly excludes `ground_truth` — always use `to_prompt_dict()`, never `to_dict()`, when building prompts.

**5. Role keyword uniqueness.** `MockLLMClient._detect_role()` identifies which canned response to return by searching the system prompt for a keyword. Keywords must not be substrings of each other. The current distinction between `"forensic analyst"` (panel) and `"forensic evidence quality analyst"` (hierarchical) is intentional — do not shorten either.

## JSON output requirements

All JSON-producing agents must return a flat object (no nested arrays at the top level). Required keys per agent:

| Agent | Required JSON keys |
|---|---|
| Risk Critic | `critique`, `unresolved_questions` (array), `evidence_quality` |
| Evidence Validator | `quality`, `gaps` (array), `reliable` (bool), `notes` |
| Lead Investigator decompose | `network_question`, `threat_intel_question` |
| Consensus Agent | `verdict`, `confidence`, `rationale`, `mitigation_action` |
| Lead Investigator synthesise | `verdict`, `confidence`, `rationale`, `mitigation_action` |

`evidence_quality` and `quality` must be exactly `"low"`, `"medium"`, or `"high"` (lowercase). Both are normalised in the respective parsing helpers (`_parse_critic`, `_parse_evidence_report`) if the model returns a different casing — but the system prompt should still specify lowercase to minimise parsing failures.

## Changing prompts

If you modify a system prompt, check whether the keyword in `_PANEL_ROLE_KEYWORDS` or `_HIER_ROLE_KEYWORDS` in `harness/llm_client.py` still matches. A prompt change that removes the matching keyword will break `MockLLMClient._detect_role()` and silently return wrong mock responses. The test `test_prompts_never_contain_ground_truth` in `tests/test_benchmark.py` will catch ground-truth leakage but not keyword mismatches.
