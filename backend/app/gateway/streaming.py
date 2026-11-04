"""Secure buffered streaming response processor.
Enforces Buffer-Before-Stream security invariant to prevent token leakage.
"""

import json
import time
from typing import Any, AsyncIterator, Dict, List, Optional
from app.core.exceptions import UpstreamProviderError
from app.gateway.response_inspector import response_inspector


class SecureStreamingHandler:
    """Buffers upstream SSE streams, verifies response security, and emits inspected SSE chunks."""

    def __init__(self):
        self.response_inspector = response_inspector

    async def process_stream(
        self,
        upstream_stream: AsyncIterator[str],
        request_mapping: Optional[Dict[str, str]] = None,
        model: str = "default",
        request_id: str = "req_stream",
        chunk_size: int = 12,
    ) -> AsyncIterator[str]:
        """
        Consumes the entire upstream stream into memory, performs security inspection,
        restores PII placeholders, and streams out approved SSE chunks.
        """
        accumulated_text = []
        finish_reason = "stop"
        created_ts = int(time.time())

        # Phase 1: Buffer the complete upstream stream into memory
        try:
            async for raw_line in upstream_stream:
                line = raw_line.strip() if isinstance(raw_line, str) else raw_line.decode("utf-8").strip()
                if not line or not line.startswith("data:"):
                    continue

                data_str = line[len("data:"):].strip()
                if data_str == "[DONE]":
                    break

                try:
                    chunk_json = json.loads(data_str)
                    choices = chunk_json.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        content_piece = delta.get("content")
                        if content_piece:
                            accumulated_text.append(content_piece)
                        if choices[0].get("finish_reason"):
                            finish_reason = choices[0]["finish_reason"]
                except json.JSONDecodeError:
                    # Ignore malformed non-JSON lines or heartbeats
                    continue

        except Exception as e:
            if not isinstance(e, UpstreamProviderError):
                raise UpstreamProviderError(f"Error reading upstream stream: {str(e)}")
            raise

        full_content = "".join(accumulated_text)

        # Phase 2: Security & Privacy Inspection (Buffer-Before-Stream Invariant)
        # If full_content contains secrets, inspect_and_restore raises ResponseSecurityViolationError!
        # Because we buffered, zero sensitive tokens have been transmitted to the client.
        inspected = self.response_inspector.inspect_and_restore(
            raw_model_content=full_content,
            request_mapping=request_mapping,
        )

        restored_content = inspected.restored_content

        # Phase 3: Emit inspected and restored SSE chunks to client
        # Initial role header chunk
        initial_chunk = {
            "id": request_id,
            "object": "chat.completion.chunk",
            "created": created_ts,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {"role": "assistant"},
                    "finish_reason": None,
                }
            ],
        }
        yield f"data: {json.dumps(initial_chunk)}\n\n"

        # Content chunks (emitted smoothly in word/character slices)
        words = restored_content.split(" ")
        for i, word in enumerate(words):
            piece = word if i == len(words) - 1 else f"{word} "
            chunk_payload = {
                "id": request_id,
                "object": "chat.completion.chunk",
                "created": created_ts,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": piece},
                        "finish_reason": None,
                    }
                ],
            }
            yield f"data: {json.dumps(chunk_payload)}\n\n"

        # Final termination chunk with finish_reason
        stop_chunk = {
            "id": request_id,
            "object": "chat.completion.chunk",
            "created": created_ts,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": finish_reason,
                }
            ],
        }
        yield f"data: {json.dumps(stop_chunk)}\n\n"

        # Final [DONE] indicator
        yield "data: [DONE]\n\n"


# Shared secure stream handler instance
secure_stream_handler = SecureStreamingHandler()
