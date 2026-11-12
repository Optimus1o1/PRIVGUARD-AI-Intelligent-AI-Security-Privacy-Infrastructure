# PRIVGUARD Python SDK (`privguard-sdk`)

[![PyPI version](https://img.shields.io/badge/pypi-v0.1.0-blue.svg)](https://pypi.org/project/privguard-sdk/)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/privguard-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Security Standard](https://img.shields.io/badge/security-fail--closed-red.svg)](https://privguard.io)

> **Moon Sanctum Labs** — *Decode. Build. Evolve.*

The official Python client library for **PRIVGUARD AI** — the independent security and privacy enforcement layer positioned between AI applications, autonomous agents, untrusted context sources, external foundation models, and execution tools.

---

## Features

- **Dual Synchronous & Asynchronous Interfaces**: Consistent resource APIs across both `PrivGuardClient` and `AsyncPrivGuardClient` with context manager lifecycle support.
- **Fail-Closed Gateways**: OpenAI-compatible chat completion proxying with automated PII token substitution, secret interception, and Server-Sent Events (SSE) streaming.
- **Agent Security Broker**: Task session quotas, time-limited capability token requests, and brokered tool execution.
- **Human-in-the-Loop Approvals**: Query pending approval queues, evaluate cryptographic HMAC action hashes, and authorize/reject high-risk operations.
- **Personal AI Memory Vault**: AES-256-GCM envelope-encrypted memory proposals, consent gates, semantic search, and irreversible cryptographic erasure.
- **Tamper-Evident Audit Trails**: Query content-free security audit ledgers and threat detection events.
- **Compliance Evidence Engine**: Explore statutory frameworks (DPDP Act/Rules, EU AI Act, NIST AI, ISO 27001, SOC 2), discover 35 internal controls, trigger automated evidence collection, and generate cryptographically signed export snapshots.
- **Offline Cryptographic Verifier**: Standalone verification module to validate SHA-256 artifact digests and Ed25519 manifest signatures of exported compliance audit bundles without server access.
- **Idempotency-Aware Reliability**: Built-in HTTPX connection pooling with exponential backoff and jitter strictly bounded to idempotent reads (`GET`). Write operations are never blindly retried on network timeouts.
- **Type-Safe & Typed**: Fully typed with Pydantic V2 models, strict PEP 561 inline typing indicator (`py.typed`), and zero database ORM leakage.

---

## Installation

```bash
pip install privguard-sdk
```

### Supported Python Versions
- Python 3.10
- Python 3.11
- Python 3.12 (Recommended)
- Python 3.13

---

## Authentication & Configuration

The SDK connects to your PRIVGUARD AI instance using an API key and optional tenant routing headers.

```bash
export PRIVGUARD_BASE_URL="https://privguard.internal"
export PRIVGUARD_API_KEY="pg_live_your_api_key_here"
export PRIVGUARD_TENANT_ID="tenant_corp_alpha"
```

Credentials can also be passed explicitly:

```python
from privguard_sdk import PrivGuardClient

client = PrivGuardClient(
    base_url="https://privguard.internal",
    api_key="pg_live_your_api_key_here",
    tenant_id="tenant_corp_alpha",
    timeout=30.0,
    verify_ssl=True,
)
```

> [!NOTE]
> `repr(client)` and `repr(config)` mask your API key (`sk-***...`) to prevent accidental credential leakage in logs or stack traces.

---

## Quickstart

### 1. Synchronous Client

```python
from privguard_sdk import PrivGuardClient

with PrivGuardClient(api_key="your_api_key") as client:
    # 1. Health Probe
    liveness = client.health.check()
    print("Health Status:", liveness.status)

    # 2. Inspect text for sensitive data (Secrets & PII)
    inspection = client.privacy.inspect("Draft an email to ceo@acme.com with token sk-test-12345")
    print(f"Action: {inspection.action}, Category: {inspection.category}, Blocked: {inspection.is_blocked}")

    # 3. Format-preserving PII Redaction
    redacted = client.privacy.redact("Call Alice at +1-555-0199")
    print("Sanitized text:", redacted.sanitized_text)  # "Call Alice at <PHONE_1>"
```

### 2. Asynchronous Client & Streaming

```python
import asyncio
from privguard_sdk import AsyncPrivGuardClient


async def main():
    async with AsyncPrivGuardClient(api_key="your_api_key") as client:
        # Non-streaming completion
        response = await client.gateway.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Explain zero-trust agent governance."}],
        )
        print("Response:", response.choices[0].message["content"])

        # Secure SSE Streaming
        print("Stream: ", end="")
        async for chunk in client.gateway.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Count from 1 to 5."}],
        ):
            if chunk.choices and "delta" in chunk.choices[0]:
                print(chunk.choices[0]["delta"].get("content", ""), end="", flush=True)
        print()


asyncio.run(main())
```

---

## Agent Security & Capability Tokens

PRIVGUARD enforces zero-trust execution over autonomous agents via temporary, task-scoped capability tokens:

```python
from privguard_sdk import PrivGuardClient

with PrivGuardClient(api_key="your_api_key") as client:
    # 1. Register agent
    agent = client.agents.register(
        name="ResearchAgent-01",
        allowed_tools=["search_web", "read_file"],
    )

    # 2. Create task session with step budget
    task = client.tasks.create(
        agent_id=agent.id,
        description="Market research report",
        ttl_seconds=600,
        max_steps=50,
    )

    # 3. Request capability token for a single tool call
    cap = client.capabilities.request(
        agent_id=agent.id,
        task_id=task.id,
        tool_name="search_web",
        max_uses=1,
    )

    # 4. Invoke tool through the Security Broker
    result = client.tools.execute(
        tool_name="search_web",
        agent_id=agent.id,
        task_id=task.id,
        capability_token=cap.capability_token,
        parameters={"query": "AI Act statutory milestones"},
    )
    print("Execution output:", result.output)
```

---

## Personal AI Memory Vault

Encrypted personal memory with staged human consent proposals and cryptographic erasure:

```python
from privguard_sdk import PrivGuardClient

with PrivGuardClient(api_key="your_api_key", user_id="user_123") as client:
    # Propose long-term memory (requires consent)
    proposal = client.memory.propose(
        proposed_key="preferred_timezone",
        proposed_value="Asia/Kolkata (IST)",
        agent_id="agent_01",
        task_id="task_01",
    )
    print("Proposal ID:", proposal.id)

    # Human user consents to proposal -> encrypted into vault
    client.memory.consent_proposal(proposal.id)

    # Retrieve and decrypt
    item = client.memory.retrieve("preferred_timezone")
    print("Decrypted memory:", item.value)

    # Irreversible cryptographic erasure (destroys record DEK)
    client.memory.cryptographic_erasure(key="preferred_timezone")
```

---

## Compliance Evidence & Offline Verification

Query 35 standardized controls, trigger evidence collection, download signed audit snapshots, and verify them completely offline without server access:

```python
from privguard_sdk import PrivGuardClient, verify_export_package

# 1. Export compliance snapshot
with PrivGuardClient(api_key="your_api_key") as client:
    snapshot = client.compliance.create_export(format="ZIP", include_artifacts=True)
    zip_path = "privguard_audit_package.zip"
    client.compliance.download_export(snapshot.export_id, zip_path)

# 2. Offline verification (no network required)
# Auditors can pass an independently trusted public key PEM
report = verify_export_package(zip_path, allow_embedded_key=True)

print("Verification Valid:", report.is_valid)
print(f"Artifacts Verified: {report.artifacts_verified}/{report.total_artifacts}")
print("Signature Valid:", report.signature_valid)
```

---

## Error Handling

PRIVGUARD SDK provides a rich, status-coded exception hierarchy:

```python
from privguard_sdk import PrivGuardClient
from privguard_sdk.exceptions import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    PrivGuardError,
)

client = PrivGuardClient(api_key="invalid_key")

try:
    client.health.check()
except AuthenticationError as e:
    print(f"Authentication failed: {e.message} [Code: {e.error_code}]")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds.")
except PrivGuardError as e:
    print(f"PRIVGUARD Error (Status {e.status_code}): {e}")
```

---

## Security Invariants

1. **Client Library Invariant**: The SDK is an interface over PRIVGUARD's authenticated APIs. It does not replace server-side controls or enforce security policies on the client.
2. **Fail-Closed**: Incomplete streams or connection interruptions never result in silent fallback or permissive defaults.
3. **SSRF Prevention**: Redirects are strictly disabled (`follow_redirects=False`) across all transport clients.
4. **Idempotency Guardrail**: Automatic retries are strictly restricted to idempotent read methods (`GET`). Write operations (`POST`, `PATCH`, `DELETE`) are never automatically retried after uncertain network failures.
5. **No Credential Logging**: Passwords, API tokens, and decrypted memory vaults are never logged or exposed in `repr()`.

---

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
