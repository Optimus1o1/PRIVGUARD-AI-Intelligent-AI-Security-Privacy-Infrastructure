"""Unit tests for synchronous client resources using httpx.MockTransport."""

import json

import httpx

from privguard_sdk.client import PrivGuardClient
from privguard_sdk.types import AgentStatus, MemoryCategory, SourceType


def mock_sync_handler(request: httpx.Request) -> httpx.Response:
    url_path = request.url.path
    method = request.method

    # 1. Health
    if url_path == "/health":
        return httpx.Response(
            200, json={"status": "healthy", "service": "privguard", "version": "0.1.0", "environment": "test"}
        )
    if url_path == "/ready":
        return httpx.Response(200, json={"status": "ready", "checks": {"database": "connected"}})

    # 2. Gateway
    if url_path == "/v1/chat/completions":
        body = json.loads(request.content)
        if body.get("stream"):
            chunk_data = json.dumps(
                {
                    "id": "c1",
                    "object": "chat.completion.chunk",
                    "created": 12345,
                    "model": "gpt-4o",
                    "choices": [{"index": 0, "delta": {"content": "Hello world!"}}],
                }
            )
            sse_content = f"data: {chunk_data}\n\ndata: [DONE]\n\n"
            return httpx.Response(200, text=sse_content, headers={"content-type": "text/event-stream"})
        return httpx.Response(
            200,
            json={
                "id": "chat-123",
                "object": "chat.completion",
                "created": 12345,
                "model": "gpt-4o",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello!"}}],
                "usage": {"total_tokens": 10},
                "privguard_meta": {"action": "ALLOW"},
            },
        )

    # 3. Privacy
    if url_path == "/v1/privacy/inspect":
        return httpx.Response(
            200,
            json={
                "category": "SAFE",
                "risk_level": "LOW",
                "action": "ALLOW",
                "is_blocked": False,
                "detected_secrets": [],
                "detected_pii": [],
                "entity_counts": {},
                "content_fingerprint": "abc123",
            },
        )
    if url_path == "/v1/privacy/redact":
        return httpx.Response(
            200,
            json={
                "sanitized_text": "Hello <EMAIL_1>",
                "mapping": {"<EMAIL_1>": "alice@test.com"},
                "entity_counts": {"EMAIL": 1},
            },
        )

    # 4. Threats
    if url_path == "/v1/threats/inspect":
        return httpx.Response(
            200,
            json={
                "assessment": {"injection_confidence": 0.0},
                "trust_level": "TRUSTED",
                "sanitized_content": "safe text",
                "is_quarantined": False,
            },
        )
    if url_path == "/v1/threats/events":
        return httpx.Response(
            200,
            json=[
                {
                    "id": "te1",
                    "application_id": "app1",
                    "threat_type": "PROMPT_INJECTION",
                    "severity": "HIGH",
                    "details": {},
                    "created_at": "2026-11-08T00:00:00Z",
                }
            ],
        )

    # 5. Agents
    if url_path == "/v1/agents/register":
        return httpx.Response(
            200,
            json={
                "id": "ag_1",
                "name": "TestAgent",
                "description": "test",
                "status": "ACTIVE",
                "allowed_tools": ["search_web"],
                "created_at": "2026-11-08T00:00:00Z",
                "last_activity_at": "2026-11-08T00:00:00Z",
            },
        )
    if url_path == "/v1/agents":
        return httpx.Response(
            200,
            json=[
                {
                    "id": "ag_1",
                    "name": "TestAgent",
                    "description": "test",
                    "status": "ACTIVE",
                    "allowed_tools": ["search_web"],
                    "created_at": "2026-11-08T00:00:00Z",
                    "last_activity_at": "2026-11-08T00:00:00Z",
                }
            ],
        )
    if url_path == "/v1/agents/ag_1":
        return httpx.Response(
            200,
            json={
                "id": "ag_1",
                "name": "TestAgent",
                "description": "test",
                "status": "ACTIVE",
                "allowed_tools": ["search_web"],
                "created_at": "2026-11-08T00:00:00Z",
                "last_activity_at": "2026-11-08T00:00:00Z",
            },
        )
    if url_path == "/v1/agents/ag_1/status":
        return httpx.Response(
            200,
            json={
                "id": "ag_1",
                "name": "TestAgent",
                "description": "test",
                "status": "PAUSED",
                "allowed_tools": ["search_web"],
                "created_at": "2026-11-08T00:00:00Z",
                "last_activity_at": "2026-11-08T00:00:00Z",
            },
        )

    # 6. Tasks
    if url_path == "/v1/tasks" and method == "POST":
        return httpx.Response(
            200,
            json={
                "id": "task_1",
                "agent_id": "ag_1",
                "status": "RUNNING",
                "description": "t",
                "created_at": "2026-11-08T00:00:00Z",
                "expires_at": "2026-11-08T01:00:00Z",
            },
        )
    if url_path == "/v1/tasks/task_1":
        return httpx.Response(
            200,
            json={
                "id": "task_1",
                "agent_id": "ag_1",
                "status": "RUNNING",
                "description": "t",
                "created_at": "2026-11-08T00:00:00Z",
                "expires_at": "2026-11-08T01:00:00Z",
            },
        )
    if url_path == "/v1/tasks" and method == "GET":
        return httpx.Response(
            200,
            json=[
                {
                    "id": "task_1",
                    "agent_id": "ag_1",
                    "status": "RUNNING",
                    "description": "t",
                    "created_at": "2026-11-08T00:00:00Z",
                    "expires_at": "2026-11-08T01:00:00Z",
                }
            ],
        )

    # 7. Capabilities
    if url_path == "/v1/capabilities/request":
        return httpx.Response(
            200,
            json={
                "id": "cap_1",
                "agent_id": "ag_1",
                "task_id": "task_1",
                "tool_name": "search_web",
                "permissions": ["execute"],
                "max_uses": 1,
                "uses_count": 0,
                "is_revoked": False,
                "expires_at": "2026-11-08T01:00:00Z",
                "capability_token": "secret_tok_1",
            },
        )
    if url_path == "/v1/capabilities/validate":
        return httpx.Response(200, json={"is_valid": True})
    if url_path == "/v1/capabilities/secret_tok_1/revoke":
        return httpx.Response(
            200,
            json={
                "id": "cap_1",
                "agent_id": "ag_1",
                "task_id": "task_1",
                "tool_name": "search_web",
                "permissions": [],
                "max_uses": 1,
                "uses_count": 0,
                "is_revoked": True,
                "expires_at": "2026-11-08T01:00:00Z",
            },
        )

    # 8. Approvals
    if url_path == "/v1/approvals/pending":
        return httpx.Response(
            200,
            json=[
                {
                    "id": "appr_1",
                    "task_id": "task_1",
                    "agent_id": "ag_1",
                    "tool_name": "send_email",
                    "action_parameters": {"recipient": "test@test.com"},
                    "action_hash": "hash_123",
                    "risk_level": "HIGH",
                    "status": "PENDING",
                    "created_at": "2026-11-08T00:00:00Z",
                    "expires_at": "2026-11-08T01:00:00Z",
                }
            ],
        )
    if url_path == "/v1/approvals/appr_1":
        return httpx.Response(
            200,
            json={
                "id": "appr_1",
                "task_id": "task_1",
                "agent_id": "ag_1",
                "tool_name": "send_email",
                "action_parameters": {},
                "action_hash": "hash_123",
                "risk_level": "HIGH",
                "status": "PENDING",
                "created_at": "2026-11-08T00:00:00Z",
                "expires_at": "2026-11-08T01:00:00Z",
            },
        )
    if url_path == "/v1/approvals/appr_1/approve":
        return httpx.Response(
            200,
            json={
                "id": "appr_1",
                "task_id": "task_1",
                "agent_id": "ag_1",
                "tool_name": "send_email",
                "action_parameters": {},
                "action_hash": "hash_123",
                "risk_level": "HIGH",
                "status": "APPROVED",
                "created_at": "2026-11-08T00:00:00Z",
                "expires_at": "2026-11-08T01:00:00Z",
            },
        )
    if url_path == "/v1/approvals/appr_1/reject":
        return httpx.Response(
            200,
            json={
                "id": "appr_1",
                "task_id": "task_1",
                "agent_id": "ag_1",
                "tool_name": "send_email",
                "action_parameters": {},
                "action_hash": "hash_123",
                "risk_level": "HIGH",
                "status": "REJECTED",
                "created_at": "2026-11-08T00:00:00Z",
                "expires_at": "2026-11-08T01:00:00Z",
            },
        )
    if url_path == "/v1/approvals/action-hash":
        return httpx.Response(200, json={"action_hash": "hmac_calculated_hash"})

    # 9. Tools
    if url_path == "/v1/tools":
        return httpx.Response(
            200,
            json=[
                {
                    "name": "search_web",
                    "description": "Searches the web",
                    "parameter_schema": {"type": "object"},
                    "is_active": True,
                }
            ],
        )
    if url_path == "/v1/tools/search_web/execute":
        return httpx.Response(
            200,
            json={
                "execution_id": "exec_1",
                "status": "SUCCESS",
                "tool": "search_web",
                "output": "Results: 42",
                "duration_ms": 15.2,
            },
        )

    # 10. Memory
    if url_path == "/v1/memory/proposals" and method == "POST":
        return httpx.Response(
            200,
            json={
                "id": "prop_1",
                "app_id": "app1",
                "owner_id": "u1",
                "proposed_key": "k",
                "proposed_value": "v",
                "category": "USER_PREFERENCES",
                "status": "PENDING",
                "threat_assessment": {},
                "risk_level": "LOW",
                "created_at": "2026-11-08T00:00:00Z",
            },
        )
    if url_path == "/v1/memory/proposals/pending":
        return httpx.Response(
            200,
            json=[
                {
                    "id": "prop_1",
                    "app_id": "app1",
                    "owner_id": "u1",
                    "proposed_key": "k",
                    "proposed_value": "v",
                    "category": "USER_PREFERENCES",
                    "status": "PENDING",
                    "threat_assessment": {},
                    "risk_level": "LOW",
                    "created_at": "2026-11-08T00:00:00Z",
                }
            ],
        )
    if url_path == "/v1/memory/proposals/prop_1/consent":
        return httpx.Response(
            200,
            json={
                "id": "prop_1",
                "app_id": "app1",
                "owner_id": "u1",
                "proposed_key": "k",
                "proposed_value": "v",
                "category": "USER_PREFERENCES",
                "status": "CONSENTED",
                "threat_assessment": {},
                "risk_level": "LOW",
                "created_at": "2026-11-08T00:00:00Z",
            },
        )
    if url_path == "/v1/memory/proposals/prop_1/reject":
        return httpx.Response(
            200,
            json={
                "id": "prop_1",
                "app_id": "app1",
                "owner_id": "u1",
                "proposed_key": "k",
                "proposed_value": "v",
                "category": "USER_PREFERENCES",
                "status": "REJECTED",
                "threat_assessment": {},
                "risk_level": "LOW",
                "created_at": "2026-11-08T00:00:00Z",
            },
        )
    if url_path == "/v1/memory/items" and method == "POST":
        return httpx.Response(
            200,
            json={
                "key": "k",
                "value": "v",
                "category": "USER_PREFERENCES",
                "version": 1,
                "created_at": "2026-11-08T00:00:00Z",
                "updated_at": "2026-11-08T00:00:00Z",
            },
        )
    if url_path == "/v1/memory/items/k" and method == "GET":
        return httpx.Response(
            200,
            json={
                "key": "k",
                "value": "v",
                "category": "USER_PREFERENCES",
                "version": 1,
                "created_at": "2026-11-08T00:00:00Z",
                "updated_at": "2026-11-08T00:00:00Z",
            },
        )
    if url_path == "/v1/memory/items" and method == "GET":
        return httpx.Response(
            200,
            json=[
                {
                    "key": "k",
                    "value": "v",
                    "category": "USER_PREFERENCES",
                    "version": 1,
                    "created_at": "2026-11-08T00:00:00Z",
                    "updated_at": "2026-11-08T00:00:00Z",
                }
            ],
        )
    if url_path == "/v1/memory/items/k" and method == "DELETE":
        return httpx.Response(200, json={"status": "deleted"})
    if url_path == "/v1/memory/search":
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "key": "k",
                        "value": "v",
                        "category": "USER_PREFERENCES",
                        "version": 1,
                        "created_at": "2026-11-08T00:00:00Z",
                        "updated_at": "2026-11-08T00:00:00Z",
                    }
                ],
                "count": 1,
            },
        )
    if url_path == "/v1/memory/erasure":
        return httpx.Response(200, json={"status": "success", "erased_count": 1, "message": "DEK destroyed"})

    # 11. Audit
    if url_path == "/v1/audit/events":
        return httpx.Response(
            200,
            json=[
                {
                    "id": "ev1",
                    "request_id": "r1",
                    "event_type": "AUDIT",
                    "action_taken": "ALLOW",
                    "risk_level": "LOW",
                    "entity_counts": {},
                    "status": "SUCCESS",
                    "timestamp": "2026-11-08T00:00:00Z",
                }
            ],
        )

    # 12. Compliance
    if url_path == "/v1/compliance/signing-keys/public":
        return httpx.Response(
            200,
            json={
                "kid": "k1",
                "purpose": "evidence_signing",
                "algorithm": "Ed25519",
                "public_key_hex": "abc",
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n",
                "is_active": True,
                "created_at": "2026-11-08T00:00:00Z",
            },
        )
    if url_path == "/v1/compliance/frameworks":
        return httpx.Response(
            200,
            json=[
                {
                    "id": "dpdp-2023",
                    "name": "DPDP",
                    "version": "2023",
                    "jurisdiction": "India",
                    "authority": "MeitY",
                    "status": "ACTIVE",
                    "total_requirements": 8,
                    "mapped_requirements": 8,
                    "coverage_percentage": 100.0,
                }
            ],
        )
    if url_path == "/v1/compliance/controls":
        return httpx.Response(
            200,
            json=[
                {
                    "id": "PG-CONTROL-001",
                    "domain": "Identity",
                    "title": "API Key",
                    "description": "desc",
                    "criticality": "CRITICAL",
                    "owner_role": "Engineer",
                    "active": True,
                }
            ],
        )
    if url_path == "/v1/compliance/evidence/collect":
        return httpx.Response(200, json={"status": "completed", "records_created": 6})
    if url_path == "/v1/compliance/evidence":
        return httpx.Response(
            200,
            json=[
                {
                    "id": "ev_1",
                    "control_id": "PG-CONTROL-001",
                    "evidence_type": "telemetry",
                    "collected_at": "2026-11-08T00:00:00Z",
                    "valid_until": "2026-11-09T00:00:00Z",
                    "assurance_level": "HIGH",
                    "freshness": "CURRENT",
                    "sha256_fingerprint": "abc12345",
                }
            ],
        )
    if url_path == "/v1/compliance/gaps":
        return httpx.Response(
            200,
            json={
                "framework_id": "dpdp-2023",
                "overall_coverage_percentage": 100.0,
                "total_requirements": 8,
                "gaps": [],
            },
        )
    if url_path == "/v1/compliance/exports":
        return httpx.Response(
            200,
            json={
                "export_id": "exp_1",
                "format": "ZIP",
                "status": "READY",
                "download_url": "/v1/compliance/exports/exp_1/download",
                "manifest": {},
                "expires_at": "2026-11-09T00:00:00Z",
            },
        )

    return httpx.Response(404, json={"detail": "Not found"})


def create_mock_client() -> PrivGuardClient:
    client = PrivGuardClient(base_url="http://mock.privguard.internal", api_key="sk-test")
    # Replace transport client with mock
    client._transport._client = httpx.Client(
        transport=httpx.MockTransport(mock_sync_handler),
        base_url="http://mock.privguard.internal",
        headers=client.config.build_headers(),
    )
    return client


def test_sync_health_resource():
    client = create_mock_client()
    live = client.health.check()
    assert live.status == "healthy"
    assert live.service == "privguard"

    ready = client.health.ready()
    assert ready.status == "ready"
    assert ready.checks["database"] == "connected"


def test_sync_gateway_resource():
    client = create_mock_client()
    res = client.gateway.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hi"}],
    )
    assert res.id == "chat-123"
    assert res.choices[0].message["content"] == "Hello!"

    # Streaming test
    chunks = list(
        client.gateway.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hi"}],
        )
    )
    assert len(chunks) == 1
    assert chunks[0].choices[0]["delta"]["content"] == "Hello world!"


def test_sync_privacy_and_threats_resource():
    client = create_mock_client()
    insp = client.privacy.inspect("text to check")
    assert insp.category == "SAFE"

    red = client.privacy.redact("email is alice@test.com")
    assert red.sanitized_text == "Hello <EMAIL_1>"

    threat = client.threats.inspect("some prompt", source_type=SourceType.USER_INPUT)
    assert threat.trust_level == "TRUSTED"
    assert threat.is_quarantined is False

    events = client.threats.list_events()
    assert len(events) == 1
    assert events[0].threat_type == "PROMPT_INJECTION"


def test_sync_agents_and_tasks_resource():
    client = create_mock_client()
    agent = client.agents.register(name="TestAgent")
    assert agent.id == "ag_1"
    assert agent.status == AgentStatus.ACTIVE

    agents = client.agents.list()
    assert len(agents) == 1

    updated = client.agents.update_status("ag_1", status="PAUSED")
    assert updated.status == AgentStatus.PAUSED

    task = client.tasks.create(agent_id="ag_1")
    assert task.id == "task_1"
    assert task.status == "RUNNING"


def test_sync_capabilities_and_approvals_and_tools():
    client = create_mock_client()
    cap = client.capabilities.request(agent_id="ag_1", task_id="task_1", tool_name="search_web")
    assert cap.capability_token == "secret_tok_1"

    val = client.capabilities.validate(capability_token="secret_tok_1", tool_name="search_web")
    assert val.is_valid is True

    rev = client.capabilities.revoke("secret_tok_1")
    assert rev.is_revoked is True

    pending = client.approvals.list_pending()
    assert len(pending) == 1
    assert pending[0].action_hash == "hash_123"

    approved = client.approvals.approve("appr_1")
    assert approved.status == "APPROVED"

    hash_res = client.approvals.compute_action_hash("search_web", target_resource="res")
    assert hash_res == "hmac_calculated_hash"

    tools = client.tools.list()
    assert len(tools) == 1
    assert tools[0].name == "search_web"

    exec_res = client.tools.execute(
        tool_name="search_web",
        agent_id="ag_1",
        task_id="task_1",
        capability_token="tok",
    )
    assert exec_res.status == "SUCCESS"


def test_sync_memory_audit_and_compliance():
    client = create_mock_client()
    # Memory
    prop = client.memory.propose(
        proposed_key="k",
        proposed_value="v",
        agent_id="ag_1",
        task_id="task_1",
        category=MemoryCategory.USER_PREFERENCES,
    )
    assert prop.id == "prop_1"

    stored = client.memory.store(key="k", value="v")
    assert stored.key == "k"

    retrieved = client.memory.retrieve(key="k")
    assert retrieved.value == "v"

    search = client.memory.search(query="test")
    assert search.count == 1

    erased = client.memory.cryptographic_erasure(key="k")
    assert erased.status == "success"

    # Audit
    audit_events = client.audit.list_events()
    assert len(audit_events) == 1

    # Compliance
    pk = client.compliance.get_public_signing_key()
    assert pk.algorithm == "Ed25519"

    fws = client.compliance.list_frameworks()
    assert len(fws) == 1
    assert fws[0].id == "dpdp-2023"

    ctrls = client.compliance.list_controls()
    assert len(ctrls) == 1

    col = client.compliance.collect_evidence()
    assert col["status"] == "completed"

    gaps = client.compliance.get_gap_analysis("dpdp-2023")
    assert gaps.total_requirements == 8
