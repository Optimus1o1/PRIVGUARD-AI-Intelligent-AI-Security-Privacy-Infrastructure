"""ASGI middleware for edge security, resource exhaustion protection, and request bounding.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

from typing import Optional
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse
from starlette.requests import ClientDisconnect
from starlette.exceptions import HTTPException as StarletteHTTPException
from app.core.config import settings
from app.core.exceptions import PrivGuardException


class PayloadTooLargeException(StarletteHTTPException, PrivGuardException):
    """Raised when streaming request body exceeds configured maximum size."""

    def __init__(self, max_bytes: int):
        StarletteHTTPException.__init__(
            self,
            status_code=413,
            detail=f"Request body exceeds maximum allowed size of {max_bytes} bytes.",
        )
        PrivGuardException.__init__(
            self,
            message=f"Request body exceeds maximum allowed size of {max_bytes} bytes.",
            status_code=413,
            error_code="PAYLOAD_TOO_LARGE",
            details={"max_allowed_bytes": max_bytes},
        )
        self.max_bytes = max_bytes


class RequestSizeLimitMiddleware:
    """
    ASGI middleware enforcing strict request payload size limits.
    Prevents memory exhaustion and Denial-of-Service (DoS) attacks from oversized payloads.
    Evaluates both Content-Length headers and active streaming byte counters.
    """

    def __init__(self, app: ASGIApp, max_bytes: Optional[int] = None):
        self.app = app
        self.max_bytes = max_bytes if max_bytes is not None else settings.MAX_REQUEST_SIZE_BYTES

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. Fast Content-Length header verification
        headers = dict(scope.get("headers", []))
        content_length_raw = headers.get(b"content-length")
        if content_length_raw:
            try:
                content_length = int(content_length_raw)
                if content_length > self.max_bytes:
                    response = JSONResponse(
                        status_code=413,
                        content={
                            "error": {
                                "code": "PAYLOAD_TOO_LARGE",
                                "message": f"Request body exceeds maximum allowed size of {self.max_bytes} bytes.",
                                "details": {
                                    "max_allowed_bytes": self.max_bytes,
                                    "content_length_bytes": content_length,
                                },
                            }
                        },
                    )
                    await response(scope, receive, send)
                    return
            except ValueError:
                pass

        # 2. Streaming byte count verification for chunked/streaming requests
        bytes_received = 0
        response_started = False

        async def tracking_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        async def limited_receive():
            nonlocal bytes_received
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                bytes_received += len(body)
                if bytes_received > self.max_bytes:
                    raise PayloadTooLargeException(self.max_bytes)
            return message

        try:
            await self.app(scope, limited_receive, tracking_send)
        except (PayloadTooLargeException, ClientDisconnect) as exc:
            if isinstance(exc, PayloadTooLargeException) or bytes_received > self.max_bytes:
                if not response_started:
                    response = JSONResponse(
                        status_code=413,
                        content={
                            "error": {
                                "code": "PAYLOAD_TOO_LARGE",
                                "message": f"Request body exceeds maximum allowed size of {self.max_bytes} bytes.",
                                "details": {"max_allowed_bytes": self.max_bytes},
                            }
                        },
                    )
                    await response(scope, receive, send)
                    return
            raise
