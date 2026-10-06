# LLM Backend Configuration and Credential Handling

## Backend switch

The system supports two backends, controlled by the `LLM_BACKEND` environment variable in `.env`:

| Value | Behaviour | Credentials required |
|---|---|---|
| `mock` (default) | Deterministic alert-keyed responses from `data/mock_responses.json` | None |
| `bedrock` | Live Amazon Bedrock calls via `boto3` | Yes — see below |

Set `LLM_BACKEND=mock` during all local development, testing, and CI. The full pipeline — including all 13 tests — runs without any AWS credentials in mock mode.

## Entry point: `get_llm_client()`

All code that needs an LLM client must call the factory function in `harness/llm_client.py`:

```python
from harness.llm_client import get_llm_client
client = get_llm_client(alert_id="ALT-001", strategy="panel_strategy")
```

- In mock mode: returns `MockLLMClient(alert_id, strategy)`. Both arguments are required.
- In bedrock mode: returns `BedrockLLMClient()`. The `alert_id` and `strategy` arguments are ignored.

**Never instantiate `MockLLMClient` or `BedrockLLMClient` directly** outside of `tests/` and `scripts/check_bedrock.py`. Strategy code receives a `BaseLLMClient` and must not import concrete client classes.

## Credential handling rules

1. **Never commit credentials.** `.env` is in `.gitignore`. `.env.example` documents every required variable with placeholder values — it is safe to commit.

2. **Never read `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `AWS_SESSION_TOKEN` in code.** `boto3` reads these automatically from the environment. The only credential-related variable referenced in `config.py` is `AWS_REGION`, which is not a secret.

3. **Use `.env` for local overrides, never for secrets checked into the repo.** Copy `.env.example` to `.env` and fill in credentials locally. The `.env` file must never be staged or committed.

4. **Production use should rely on IAM roles, not static keys.** When running on AWS infrastructure (EC2, Lambda, ECS), attach an IAM role with the `bedrock:InvokeModel` permission. No credentials file is needed.

5. **Verify Bedrock access before switching backends.** Run `python scripts/check_bedrock.py` after setting `LLM_BACKEND=bedrock`. It sends a single minimal prompt and reports any credential or permission errors with actionable guidance.

## Switching to Bedrock: step-by-step

```bash
# 1. Copy the env template
cp .env.example .env

# 2. Edit .env — set LLM_BACKEND and AWS credentials
#    LLM_BACKEND=bedrock
#    AWS_REGION=us-east-1
#    BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0
#    AWS_ACCESS_KEY_ID=...
#    AWS_SECRET_ACCESS_KEY=...

# 3. Verify connectivity (exits 0 on success)
python scripts/check_bedrock.py

# 4. Run a single alert to confirm end-to-end
python run.py --alert data/sample_alerts.json --id ALT-001
```

## Bedrock model configuration

All Bedrock model parameters are set in `config.py`:

| Variable | Default | Notes |
|---|---|---|
| `BEDROCK_MODEL_ID` | `anthropic.claude-3-haiku-20240307-v1:0` | Change to Sonnet for higher quality at higher cost |
| `AWS_REGION` | `us-east-1` | Must match the region where the model is enabled |
| `MAX_TOKENS` | `512` | Per-call token budget. Agents target 150 words (~200 tokens); 512 leaves headroom for JSON formatting |
| `TEMPERATURE` | `0.0` | Deterministic outputs for reproducibility |

**To switch to Claude 3 Sonnet** for higher accuracy on production data, set `BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0` in `.env`. The pricing constants in `config.py` (`HAIKU_INPUT_COST_PER_1K`, `HAIKU_OUTPUT_COST_PER_1K`) should also be updated to Sonnet pricing.

The model must be enabled in your AWS account via the Bedrock console (Model access → Request access) before `invoke_model` calls will succeed.

## Retry and throttling behaviour

`BedrockLLMClient` retries up to 3 times on `ThrottlingException` with exponential backoff:
- Attempt 1 failure → wait 2.0s
- Attempt 2 failure → wait 4.0s
- Attempt 3 failure → raise

Constants `_MAX_RETRIES = 3` and `_BACKOFF_BASE = 2.0` are defined directly in `BedrockLLMClient`. If you need to adjust retry behaviour for a higher-throughput deployment, edit them there.

No other exception types trigger a retry. Network errors and access-denied errors surface immediately.

## Logging

All LLM calls are logged to `logs/llm_client.log` regardless of backend:

- Mock mode: logs `[MOCK] alert=... strategy=... role=... | in=N out=N tokens`
- Bedrock mode: logs full request (first 200 chars of system and user) and response (first 400 chars)

The `logs/` directory is created automatically on first run. Log files are excluded from git via `.gitignore`. Do not log credential values — only region and model ID appear in logs.

## Mock client internals

`MockLLMClient` loads all responses for an alert at construction time from `data/mock_responses.json`. The JSON structure is:

```
{
  "ALT-013": {
    "panel_strategy": {
      "threat_assessment": "...",        ← free prose
      "forensics_assessment": "...",     ← free prose
      "critic_report": "{...}",          ← JSON-encoded string
      "consensus": "{...}"               ← JSON-encoded string
    },
    "hierarchical_strategy": {
      "evidence_validation": "{...}",    ← JSON-encoded string
      "decomposition": "{...}",          ← JSON-encoded string
      "network_finding": "...",          ← free prose
      "threat_intel_finding": "...",     ← free prose
      "synthesis": "{...}"              ← JSON-encoded string
    }
  }
}
```

The correct response for each agent call is looked up by detecting a keyword in the system prompt (`_detect_role()`). When adding a new alert to `data/sample_alerts.json`, a corresponding entry with all 9 agent keys (4 for panel, 5 for hierarchical) **must** be added to `data/mock_responses.json`. The test `test_mock_responses_cover_every_alert` will fail if any entry is missing.
