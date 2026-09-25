"""
scripts/check_bedrock.py — One-shot AWS Bedrock connectivity check.

Run this before switching LLM_BACKEND=bedrock to confirm:
  - AWS credentials are configured (env vars, ~/.aws/credentials, or IAM role)
  - The target region and model ID are accessible
  - IAM permissions allow bedrock:InvokeModel

Usage:
    LLM_BACKEND=bedrock python scripts/check_bedrock.py

The script exits 0 on success, 1 on failure.
"""

import json
import os
import sys

# Allow running from the project root without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402 (must be after sys.path modification)


def main() -> int:
    print(f"Region : {config.AWS_REGION}")
    print(f"Model  : {config.BEDROCK_MODEL_ID}")
    print()

    try:
        import boto3
    except ImportError:
        print("ERROR: boto3 is not installed. Run: pip install boto3", file=sys.stderr)
        return 1

    try:
        client = boto3.client("bedrock-runtime", region_name=config.AWS_REGION)
    except Exception as exc:
        print(f"ERROR: could not create Bedrock client: {exc}", file=sys.stderr)
        return 1

    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 32,
        "temperature": 0.0,
        "system": "You are a helpful assistant.",
        "messages": [{"role": "user", "content": "Reply with the single word: connected"}],
    }

    print("Sending test prompt to Bedrock...")
    try:
        response = client.invoke_model(
            modelId=config.BEDROCK_MODEL_ID,
            body=json.dumps(payload),
            contentType="application/json",
            accept="application/json",
        )
        body  = json.loads(response["body"].read())
        text  = body["content"][0]["text"]
        usage = body.get("usage", {})
        print(f"Response      : {text.strip()!r}")
        print(f"Input tokens  : {usage.get('input_tokens', 'N/A')}")
        print(f"Output tokens : {usage.get('output_tokens', 'N/A')}")
        print()
        print("✓ Bedrock connectivity confirmed. Set LLM_BACKEND=bedrock to use live calls.")
        return 0

    except Exception as exc:
        print(f"ERROR: Bedrock call failed: {exc}", file=sys.stderr)
        print()
        print("Common causes:")
        print("  - AWS credentials not configured (set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)")
        print("  - Model not enabled in your account (enable in Bedrock console → Model access)")
        print(f"  - Wrong region (current: {config.AWS_REGION})")
        print("  - IAM policy missing bedrock:InvokeModel permission")
        return 1


if __name__ == "__main__":
    sys.exit(main())
