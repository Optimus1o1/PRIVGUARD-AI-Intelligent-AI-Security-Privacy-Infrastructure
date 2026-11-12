"""PRIVGUARD AI - Stage 10.6 Synthetic Security Canary Tests.
Executes all 8 synthetic security canaries and verifies that security assertions fail closed.
"""

import pytest
from app.observability.canary.scenarios import (
    GatewayProtectionCanary,
    SecretBlockingCanary,
    AgentAuthorizationCanary,
    CapabilityRevocationCanary,
    PromptInjectionCanary,
    MemoryIsolationCanary,
    MCPSecurityCanary,
    KMSAvailabilityCanary,
)
from app.observability.canary.runner import CanaryRunner, get_canary_runner


@pytest.mark.asyncio
async def test_01_gateway_protection_canary():
    """Canary 1: Verifies PII detection and redaction using synthetic test data."""
    canary = GatewayProtectionCanary()
    res = await canary.execute()

    assert res.passed is True
    assert res.canary_name == "gateway_protection"
    assert res.severity == "critical"
    assert res.latency_ms > 0


@pytest.mark.asyncio
async def test_02_secret_blocking_canary():
    """Canary 2: Verifies that synthetic credential patterns fail closed."""
    canary = SecretBlockingCanary()
    res = await canary.execute()

    assert res.passed is True
    assert res.canary_name == "secret_blocking"
    assert res.severity == "critical"


@pytest.mark.asyncio
async def test_03_agent_authorization_canary():
    """Canary 3: Verifies that unauthorized tool calls are denied."""
    canary = AgentAuthorizationCanary()
    res = await canary.execute()

    assert res.passed is True
    assert res.canary_name == "agent_authorization"
    assert res.severity == "critical"


@pytest.mark.asyncio
async def test_04_capability_revocation_canary():
    """Canary 4: Verifies that revoked capability tokens are rejected."""
    canary = CapabilityRevocationCanary()
    res = await canary.execute()

    assert res.passed is True
    assert res.canary_name == "capability_revocation"
    assert res.severity == "critical"


@pytest.mark.asyncio
async def test_05_prompt_injection_canary():
    """Canary 5: Verifies that synthetic injection heuristics trigger threat signals."""
    canary = PromptInjectionCanary()
    res = await canary.execute()

    assert res.passed is True
    assert res.canary_name == "prompt_injection"
    assert res.severity == "high"


@pytest.mark.asyncio
async def test_06_memory_isolation_canary():
    """Canary 6: Verifies cross-user memory decryption or ciphertext tampering is rejected."""
    canary = MemoryIsolationCanary()
    res = await canary.execute()

    assert res.passed is True
    assert res.canary_name == "memory_isolation"
    assert res.severity == "critical"


@pytest.mark.asyncio
async def test_07_mcp_security_canary():
    """Canary 7: Verifies SSRF attacks against internal network endpoints are blocked."""
    canary = MCPSecurityCanary()
    res = await canary.execute()

    assert res.passed is True
    assert res.canary_name == "mcp_security"
    assert res.severity == "critical"


@pytest.mark.asyncio
async def test_08_kms_availability_canary():
    """Canary 8: Verifies active KMS encryption/decryption roundtrip validation."""
    canary = KMSAvailabilityCanary()
    res = await canary.execute()

    assert res.passed is True
    assert res.canary_name == "kms_availability"
    assert res.severity == "critical"


@pytest.mark.asyncio
async def test_09_canary_runner_executes_all_canaries():
    """Test 9: CanaryRunner executes all 8 canaries and produces clean summary."""
    runner = CanaryRunner()
    results = await runner.run_all()

    assert len(results) == 8
    assert all(r.passed for r in results)

    summary = runner.get_summary()
    assert summary["healthy"] is True
    assert summary["total_canaries"] == 8
    assert summary["passed"] == 8
    assert summary["failed"] == 0
    assert summary["last_run_timestamp"] is not None
