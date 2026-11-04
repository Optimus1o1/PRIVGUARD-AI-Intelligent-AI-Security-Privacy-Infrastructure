"""OpenAI-compatible HTTP and SSE streaming provider integration."""

import json
import uuid
from typing import Any, AsyncIterator, Dict, Optional
import httpx
from app.core.config import settings
from app.core.exceptions import (
    UpstreamAuthenticationError,
    UpstreamProviderError,
    UpstreamRateLimitError,
    UpstreamTimeoutError,
)
from app.providers.base import BaseProvider, ProviderResponse


class OpenAICompatibleProvider(BaseProvider):
    """Client for OpenAI-compatible Chat Completion endpoints."""

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds or settings.UPSTREAM_TIMEOUT_SECONDS
        self._custom_client = client

    def _get_client(self) -> httpx.AsyncClient:
        """Returns the custom client or creates a standard async client."""
        if self._custom_client:
            return self._custom_client
        return httpx.AsyncClient(timeout=self.timeout_seconds)

    def _build_headers(self) -> Dict[str, str]:
        """Constructs headers without exposing secrets."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def complete(self, request_payload: Dict[str, Any]) -> ProviderResponse:
        """Executes a non-streaming chat completion request against upstream provider."""
        endpoint = f"{self.base_url}/chat/completions"
        headers = self._build_headers()
        # Guarantee stream=False for non-streaming call
        payload = dict(request_payload)
        payload["stream"] = False

        client = self._get_client()
        should_close = client is not self._custom_client

        try:
            res = await client.post(endpoint, json=payload, headers=headers)

            if res.status_code == 401:
                raise UpstreamAuthenticationError()
            elif res.status_code == 429:
                retry_after = res.headers.get("retry-after")
                raise UpstreamRateLimitError(retry_after=retry_after)
            elif res.is_error:
                raise UpstreamProviderError(
                    message=f"Upstream provider error: HTTP {res.status_code}",
                    status_code=502,
                )

            data = res.json()
            choice = data["choices"][0]
            content = choice["message"].get("content", "")
            finish_reason = choice.get("finish_reason", "stop")
            usage = data.get("usage", {
                "prompt_tokens": 0,
                "completion_tokens": len(content.split()),
                "total_tokens": len(content.split()),
            })

            return ProviderResponse(
                id=data.get("id", f"gen_{uuid.uuid4().hex[:12]}"),
                model=data.get("model", payload.get("model", "unknown")),
                content=content,
                finish_reason=finish_reason,
                usage=usage,
                raw_response=data,
            )

        except httpx.TimeoutException:
            raise UpstreamTimeoutError(self.timeout_seconds)
        except (httpx.ConnectError, httpx.NetworkError):
            raise UpstreamProviderError(
                message="Failed to connect to upstream model provider.",
                status_code=502,
            )
        except (UpstreamAuthenticationError, UpstreamRateLimitError, UpstreamProviderError, UpstreamTimeoutError):
            raise
        except Exception as e:
            raise UpstreamProviderError(
                message=f"Unexpected error communicating with upstream: {str(e)}",
                status_code=502,
            )
        finally:
            if should_close:
                await client.aclose()

    async def stream(self, request_payload: Dict[str, Any]) -> AsyncIterator[str]:
        """Initiates an SSE streaming connection to the upstream model provider."""
        endpoint = f"{self.base_url}/chat/completions"
        headers = self._build_headers()
        payload = dict(request_payload)
        payload["stream"] = True

        client = self._get_client()
        should_close = client is not self._custom_client

        try:
            async with client.stream("POST", endpoint, json=payload, headers=headers) as response:
                if response.status_code == 401:
                    raise UpstreamAuthenticationError()
                elif response.status_code == 429:
                    raise UpstreamRateLimitError()
                elif response.is_error:
                    raise UpstreamProviderError(
                        message=f"Upstream provider stream error: HTTP {response.status_code}",
                        status_code=502,
                    )

                async for line in response.aiter_lines():
                    yield line

        except httpx.TimeoutException:
            raise UpstreamTimeoutError(self.timeout_seconds)
        except (httpx.ConnectError, httpx.NetworkError):
            raise UpstreamProviderError(
                message="Failed to connect to upstream stream provider.",
                status_code=502,
            )
        finally:
            if should_close:
                await client.aclose()

