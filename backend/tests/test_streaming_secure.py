"""Tests for secure buffered streaming response handling."""

import json
import pytest
import httpx
from httpx import AsyncClient
from app.core.exceptions import ResponseSecurityViolationError
from app.database.models import Application
from app.gateway.streaming import secure_stream_handler
from app.providers.openai_compatible import OpenAICompatibleProvider
from app.providers.registry import provider_registry


@pytest.mark.asyncio
async def test_streaming_success_and_chunk_structure(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Streaming request returns valid OpenAI-compatible SSE events ending in [DONE]."""
    payload = {
        "model": "mock-model",
        "messages": [
            {"role": "user", "content": "Explain secure streaming in one sentence."}
        ],
        "stream": True,
    }

    res = await client.post("/v1/chat/completions", json=payload, headers=auth_headers)
    assert res.status_code == 200
    assert "text/event-stream" in res.headers["content-type"]

    lines = res.text.strip().split("\n")
    data_lines = [l for l in lines if l.startswith("data:")]
    assert len(data_lines) >= 3

    # Check last line is [DONE]
    assert data_lines[-1] == "data: [DONE]"

    # Verify JSON structure of intermediate chunks
    first_chunk = json.loads(data_lines[0].replace("data:", "").strip())
    assert first_chunk["object"] == "chat.completion.chunk"
    assert "choices" in first_chunk


@pytest.mark.asyncio
async def test_streaming_with_pii_restoration(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Streaming response properly restores PII placeholders across buffered chunks."""
    def mock_streaming_upstream(request: httpx.Request):
        chunks = [
            f"data: {json.dumps({'choices': [{'delta': {'content': 'Sending confidential update '}}]})}\n\n",
            f"data: {json.dumps({'choices': [{'delta': {'content': 'to <EMAIL_1>.'}}]})}\n\n",
            f"data: {json.dumps({'choices': [{'delta': {}, 'finish_reason': 'stop'}]})}\n\n",
            "data: [DONE]\n\n",
        ]
        return httpx.Response(
            200,
            content="".join(chunks),
            headers={"content-type": "text/event-stream"},
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_streaming_upstream))
    stream_provider = OpenAICompatibleProvider(
        base_url="https://mock-upstream.internal/v1",
        client=mock_client,
    )
    provider_registry.register("stream-pii-model", stream_provider)

    payload = {
        "model": "stream-pii-model",
        "messages": [
            {"role": "user", "content": "Email partner@enterprise.org immediately."}
        ],
        "stream": True,
    }

    res = await client.post("/v1/chat/completions", json=payload, headers=auth_headers)
    assert res.status_code == 200

    stream_text = res.text
    # Asserts that partner@enterprise.org was restored and delivered in the stream
    assert "partner@enterprise.org" in stream_text
    assert "<EMAIL_1>" not in stream_text


@pytest.mark.asyncio
async def test_split_chunk_secret_blocked_before_client_delivery():
    """
    CRITICAL SECURITY INVARIANT:
    If a secret is split across multiple streaming chunks,
    Buffer-Before-Stream ensures it is detected and blocked BEFORE
    any tokens reach the client.
    """
    # Secret split across 2 chunks: "sk-proj-" and "1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"
    async def mock_leaking_stream():
        yield f"data: {json.dumps({'choices': [{'delta': {'content': 'Here is the key: sk-proj-'}}]})}\n\n"
        yield f"data: {json.dumps({'choices': [{'delta': {'content': '1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef'}}]})}\n\n"
        yield "data: [DONE]\n\n"

    # When processed through secure_stream_handler, it MUST raise ResponseSecurityViolationError
    # during buffer assembly, BEFORE yielding a single byte to the client!
    with pytest.raises(ResponseSecurityViolationError) as exc_info:
        generator = secure_stream_handler.process_stream(
            upstream_stream=mock_leaking_stream(),
            request_mapping={},
            model="test-leak-model",
        )
        # Attempt to pull first chunk
        await anext(generator)

    err = exc_info.value
    assert err.error_code == "RESPONSE_SECURITY_VIOLATION"
    assert "OPENAI_API_KEY" in err.details["violation_type"]
