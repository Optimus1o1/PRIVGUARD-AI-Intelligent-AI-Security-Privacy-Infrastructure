"""OpenAI-compatible Gateway resource with streaming support."""

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

from privguard_sdk.models.gateway import (
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
)
from privguard_sdk.resources.base import AsyncResource, SyncResource


class GatewayResource(SyncResource):
    """Synchronous Gateway endpoints."""

    def create(
        self,
        model: str,
        messages: list[ChatMessage | dict[str, Any]],
        temperature: float | None = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: Any | None = None,
    ) -> ChatCompletionResponse:
        """Sends a chat completion request through PRIVGUARD AI."""
        msg_objs = [m if isinstance(m, ChatMessage) else ChatMessage.model_validate(m) for m in messages]
        req = ChatCompletionRequest(
            model=model,
            messages=msg_objs,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=False,
            tools=tools,
            tool_choice=tool_choice,
        )
        data = self._transport.request("POST", "/v1/chat/completions", json_data=req)
        return ChatCompletionResponse.model_validate(data)

    def stream(
        self,
        model: str,
        messages: list[ChatMessage | dict[str, Any]],
        temperature: float | None = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: Any | None = None,
    ) -> Iterator[ChatCompletionChunk]:
        """Streams chat completion deltas via Server-Sent Events (SSE)."""
        msg_objs = [m if isinstance(m, ChatMessage) else ChatMessage.model_validate(m) for m in messages]
        req = ChatCompletionRequest(
            model=model,
            messages=msg_objs,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            tools=tools,
            tool_choice=tool_choice,
        )
        for line in self._transport.stream("POST", "/v1/chat/completions", json_data=req):
            line_str = line.strip()
            if line_str.startswith("data: "):
                payload = line_str[6:].strip()
                if payload == "[DONE]":
                    break
                try:
                    chunk_dict = json.loads(payload)
                    yield ChatCompletionChunk.model_validate(chunk_dict)
                except Exception:
                    continue


class AsyncGatewayResource(AsyncResource):
    """Asynchronous Gateway endpoints."""

    async def create(
        self,
        model: str,
        messages: list[ChatMessage | dict[str, Any]],
        temperature: float | None = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: Any | None = None,
    ) -> ChatCompletionResponse:
        """Sends an asynchronous chat completion request through PRIVGUARD AI."""
        msg_objs = [m if isinstance(m, ChatMessage) else ChatMessage.model_validate(m) for m in messages]
        req = ChatCompletionRequest(
            model=model,
            messages=msg_objs,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=False,
            tools=tools,
            tool_choice=tool_choice,
        )
        data = await self._transport.request("POST", "/v1/chat/completions", json_data=req)
        return ChatCompletionResponse.model_validate(data)

    async def stream(
        self,
        model: str,
        messages: list[ChatMessage | dict[str, Any]],
        temperature: float | None = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: Any | None = None,
    ) -> AsyncIterator[ChatCompletionChunk]:
        """Streams chat completion deltas asynchronously via Server-Sent Events (SSE)."""
        msg_objs = [m if isinstance(m, ChatMessage) else ChatMessage.model_validate(m) for m in messages]
        req = ChatCompletionRequest(
            model=model,
            messages=msg_objs,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            tools=tools,
            tool_choice=tool_choice,
        )
        async for line in self._transport.stream("POST", "/v1/chat/completions", json_data=req):
            line_str = line.strip()
            if line_str.startswith("data: "):
                payload = line_str[6:].strip()
                if payload == "[DONE]":
                    break
                try:
                    chunk_dict = json.loads(payload)
                    yield ChatCompletionChunk.model_validate(chunk_dict)
                except Exception:
                    continue
