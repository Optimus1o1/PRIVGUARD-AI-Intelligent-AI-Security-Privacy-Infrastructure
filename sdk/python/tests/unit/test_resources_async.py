"""Unit tests for asynchronous client resources using httpx.MockTransport."""

import httpx
import pytest

from privguard_sdk.async_client import AsyncPrivGuardClient
from tests.unit.test_resources_sync import mock_sync_handler


def create_mock_async_client() -> AsyncPrivGuardClient:
    client = AsyncPrivGuardClient(base_url="http://mock.privguard.internal", api_key="sk-test")
    client._transport._client = httpx.AsyncClient(
        transport=httpx.MockTransport(mock_sync_handler),
        base_url="http://mock.privguard.internal",
        headers=client.config.build_headers(),
    )
    return client


@pytest.mark.asyncio
async def test_async_health_resource():
    async with create_mock_async_client() as client:
        live = await client.health.check()
        assert live.status == "healthy"

        ready = await client.health.ready()
        assert ready.status == "ready"


@pytest.mark.asyncio
async def test_async_gateway_resource():
    async with create_mock_async_client() as client:
        res = await client.gateway.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hi"}],
        )
        assert res.id == "chat-123"

        # Stream
        chunks = []
        async for chunk in client.gateway.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hi"}],
        ):
            chunks.append(chunk)
        assert len(chunks) == 1
        assert chunks[0].choices[0]["delta"]["content"] == "Hello world!"


@pytest.mark.asyncio
async def test_async_privacy_and_threats():
    async with create_mock_async_client() as client:
        insp = await client.privacy.inspect("test text")
        assert insp.category == "SAFE"

        red = await client.privacy.redact("test text")
        assert "<EMAIL_1>" in red.sanitized_text

        threat = await client.threats.inspect("prompt text")
        assert threat.trust_level == "TRUSTED"


@pytest.mark.asyncio
async def test_async_agents_tasks_and_tools():
    async with create_mock_async_client() as client:
        agent = await client.agents.register(name="AsyncAgent")
        assert agent.id == "ag_1"

        task = await client.tasks.create(agent_id="ag_1")
        assert task.id == "task_1"

        cap = await client.capabilities.request(agent_id="ag_1", task_id="task_1", tool_name="search_web")
        assert cap.capability_token == "secret_tok_1"

        tools = await client.tools.list()
        assert len(tools) == 1

        exec_res = await client.tools.execute(
            tool_name="search_web",
            agent_id="ag_1",
            task_id="task_1",
            capability_token="secret_tok_1",
        )
        assert exec_res.status == "SUCCESS"


@pytest.mark.asyncio
async def test_async_memory_and_compliance():
    async with create_mock_async_client() as client:
        stored = await client.memory.store(key="k", value="v")
        assert stored.key == "k"

        retrieved = await client.memory.retrieve(key="k")
        assert retrieved.value == "v"

        fws = await client.compliance.list_frameworks()
        assert len(fws) == 1

        pk = await client.compliance.get_public_signing_key()
        assert pk.algorithm == "Ed25519"
