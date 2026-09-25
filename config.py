"""
config.py — Central configuration for the Adaptive Agent Harness.

All tuneable constants live here. Values are read from environment variables
where appropriate; .env is loaded automatically via python-dotenv.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─── LLM Backend ─────────────────────────────────────────────────────────────
# "mock"    → alert-keyed deterministic responses (local dev, no credentials)
# "bedrock" → live Amazon Bedrock (requires AWS credentials)
LLM_BACKEND: str = os.getenv("LLM_BACKEND", "mock")

# ─── Amazon Bedrock ───────────────────────────────────────────────────────────
BEDROCK_MODEL_ID: str = os.getenv(
    "BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0"
)
AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")

# ─── LLM Generation Parameters ───────────────────────────────────────────────
MAX_TOKENS: int = 512
TEMPERATURE: float = 0.0

# ─── Pricing (Amazon Bedrock Claude 3 Haiku, per 1 000 tokens) ───────────────
HAIKU_INPUT_COST_PER_1K: float = 0.00025
HAIKU_OUTPUT_COST_PER_1K: float = 0.00125

# ─── Strategy Selector Thresholds ────────────────────────────────────────────
# complexity:           number of distinct indicator types found in raw_evidence
# ambiguity:            count of hedging keywords (capped at 3)
# evidence_availability: ratio of populated evidence fields (0.0 – 1.0)
COMPLEXITY_THRESHOLD: int = 3
AMBIGUITY_THRESHOLD: int = 2
EVIDENCE_AVAILABILITY_THRESHOLD: float = 0.5

# ─── Paths ────────────────────────────────────────────────────────────────────
RESULTS_FILE: str = "results.jsonl"
LOGS_DIR: str = "logs"
MOCK_RESPONSES_FILE: str = "data/mock_responses.json"
