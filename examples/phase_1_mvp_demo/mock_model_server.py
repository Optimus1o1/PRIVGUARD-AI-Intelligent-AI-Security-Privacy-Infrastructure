"""Deterministic Request-Capturing Mock Model Server for PRIVGUARD AI.

Moon Sanctum Labs - Decode. Build. Evolve.

Provides an OpenAI-compatible /v1/chat/completions mock endpoint that:
1. Records the exact raw payload received from the PRIVGUARD Security Gateway.
2. Emits valid OpenAI chat completion JSON responses.
3. Allows automated tests to inspect what content actually reached the model.
"""

import argparse
import json
import logging
import time
from typing import Any, Dict, List
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("privguard.mock_model")

app = FastAPI(title="PRIVGUARD Deterministic Mock Model Server")

# In-memory history of received payloads
captured_requests: List[Dict[str, Any]] = []


@app.post("/v1/chat/completions")
async def mock_chat_completions(request: Request):
    """Captures the forwarded payload and returns a synthetic completion."""
    body = await request.json()
    captured_requests.append(body)
    logger.info("MOCK MODEL RECEIVED REQUEST (%d messages)", len(body.get("messages", [])))

    # Extract user content for simulated response
    messages = body.get("messages", [])
    last_content = messages[-1].get("content", "") if messages else ""

    response_text = f"Simulated model completion acknowledging: {last_content[:60]}..."

    response_payload = {
        "id": f"chatcmpl-mock-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model", "mock-model"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response_text,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 15,
            "completion_tokens": 10,
            "total_tokens": 25,
        },
    }
    return JSONResponse(content=response_payload)


@app.get("/captured-requests")
async def get_captured_requests():
    """Endpoint for tests to query captured payloads."""
    return JSONResponse(content={"requests": captured_requests, "count": len(captured_requests)})


@app.post("/reset")
async def reset_captured():
    """Resets captured request history."""
    captured_requests.clear()
    return JSONResponse(content={"status": "RESET"})


def main():
    parser = argparse.ArgumentParser(description="PRIVGUARD Deterministic Mock Model Server")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface")
    parser.add_argument("--port", type=int, default=8001, help="Port to listen on")
    args = parser.parse_args()

    logger.info("Starting Deterministic Mock Model Server on %s:%d", args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

