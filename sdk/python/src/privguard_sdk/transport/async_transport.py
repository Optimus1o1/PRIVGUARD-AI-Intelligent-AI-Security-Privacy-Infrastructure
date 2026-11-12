"""Asynchronous HTTPX transport implementation for PRIVGUARD SDK.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from privguard_sdk.config import PrivGuardConfig
from privguard_sdk.exceptions import (
    ConnectionError,
    PrivGuardError,
    StreamingError,
    TimeoutError,
    exception_from_response,
)
from privguard_sdk.transport.base import BaseTransport
from privguard_sdk.transport.retries import RetryPolicy
from privguard_sdk.transport.serialization import serialize_payload


class AsyncTransport(BaseTransport):
    """Manages asynchronous HTTP requests, connection pooling, and resilient retries."""

    def __init__(self, config: PrivGuardConfig) -> None:
        super().__init__(config)
        self.retry_policy = RetryPolicy(
            max_retries=config.max_retries,
            base_delay=config.backoff_factor,
        )
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=config.timeout,
            verify=config.verify_ssl,
            headers=config.build_headers(),
            follow_redirects=False,  # Security invariant: prevent SSRF via unexpected redirect
        )

    async def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Executes an asynchronous HTTP request with idempotency-aware retries."""
        serialized_json = serialize_payload(json_data)
        attempt = 0

        while True:
            attempt += 1
            try:
                response = await self._client.request(
                    method=method,
                    url=path,
                    params=params,
                    json=serialized_json,
                    headers=headers,
                )

                if response.is_success:
                    if response.status_code == 204 or not response.content:
                        return {}
                    content_type = response.headers.get("content-type", "")
                    if "application/json" in content_type:
                        return response.json()
                    return response.content

                # Check if retryable
                retry_after_val: float | None = None
                raw_retry_after = response.headers.get("retry-after")
                if raw_retry_after:
                    try:
                        retry_after_val = float(raw_retry_after)
                    except ValueError:
                        pass

                if self.retry_policy.should_retry(
                    method=method,
                    attempt=attempt,
                    status_code=response.status_code,
                    is_network_error=False,
                ):
                    delay = self.retry_policy.compute_delay(attempt, retry_after=retry_after_val)
                    await asyncio.sleep(delay)
                    continue

                # Raise structured exception
                req_id = response.headers.get("x-request-id")
                try:
                    err_payload = response.json()
                except Exception:
                    err_payload = {"detail": response.text}

                raise exception_from_response(
                    status_code=response.status_code,
                    data=err_payload,
                    request_id=req_id,
                    retry_after=retry_after_val,
                )

            except (httpx.ConnectError, httpx.NetworkError) as exc:
                if self.retry_policy.should_retry(method=method, attempt=attempt, is_network_error=True):
                    delay = self.retry_policy.compute_delay(attempt)
                    await asyncio.sleep(delay)
                    continue
                raise ConnectionError(message=f"Network connection failed: {exc}") from exc

            except (httpx.TimeoutException, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                if self.retry_policy.should_retry(method=method, attempt=attempt, is_network_error=True):
                    delay = self.retry_policy.compute_delay(attempt)
                    await asyncio.sleep(delay)
                    continue
                raise TimeoutError(message=f"Request timed out: {exc}") from exc

            except PrivGuardError:
                raise

            except Exception as exc:
                raise PrivGuardError(message=f"Unexpected transport failure: {exc}") from exc

    async def stream(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> AsyncIterator[str]:
        """Streams Server-Sent Events (SSE) asynchronously from the gateway."""
        serialized_json = serialize_payload(json_data)
        try:
            async with self._client.stream(
                method=method,
                url=path,
                params=params,
                json=serialized_json,
                headers=headers,
            ) as response:
                if not response.is_success:
                    try:
                        content = await response.aread()
                        err_payload = json.loads(content)
                    except Exception:
                        err_payload = {"detail": "Streaming request failed"}
                    raise exception_from_response(
                        status_code=response.status_code,
                        data=err_payload,
                        request_id=response.headers.get("x-request-id"),
                    )

                async for line in response.aiter_lines():
                    if line:
                        yield line
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            raise ConnectionError(message=f"Streaming network failure: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise TimeoutError(message=f"Streaming timed out: {exc}") from exc
        except PrivGuardError:
            raise
        except Exception as exc:
            raise StreamingError(message=f"Stream processing interrupted: {exc}") from exc

    async def aclose(self) -> None:
        """Closes the underlying HTTPX async client."""
        await self._client.aclose()

    def close(self) -> None:
        """Synchronous wrapper for close if called outside async context."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.aclose())
            else:
                loop.run_until_complete(self.aclose())
        except Exception:
            pass
