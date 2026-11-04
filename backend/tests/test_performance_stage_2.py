"""Performance and latency benchmarks for Stage 2 pipeline."""

import time
import pytest
from app.gateway.response_inspector import response_inspector
from app.gateway.streaming import secure_stream_handler
from app.privacy.pipeline import inspection_pipeline


def test_request_and_response_inspection_latencies():
    """Measures request inspection and response inspection latencies."""
    request_text = "Please send a payment receipt to customer.care@acme.corp regarding invoice 12345678."
    response_text = "The payment of $500 has been confirmed for account <ACCOUNT_NUMBER_1> and sent to <EMAIL_1>."
    mapping = {"<EMAIL_1>": "customer.care@acme.corp", "<ACCOUNT_NUMBER_1>": "12345678"}

    req_latencies = []
    resp_latencies = []

    # Warmup
    for _ in range(5):
        inspection_pipeline.inspect_text(request_text)
        response_inspector.inspect_and_restore(response_text, mapping)

    # 100 runs
    for _ in range(100):
        t0 = time.perf_counter()
        inspection_pipeline.inspect_text(request_text)
        req_latencies.append((time.perf_counter() - t0) * 1000)

        t1 = time.perf_counter()
        response_inspector.inspect_and_restore(response_text, mapping)
        resp_latencies.append((time.perf_counter() - t1) * 1000)

    req_latencies.sort()
    resp_latencies.sort()

    req_p95 = req_latencies[95]
    resp_p95 = resp_latencies[95]

    print(f"\n[BENCHMARK] Request Inspection P95: {req_p95:.3f}ms | Response Inspection P95: {resp_p95:.3f}ms")

    assert req_p95 < 20.0
    assert resp_p95 < 20.0


@pytest.mark.asyncio
async def test_buffered_streaming_assembly_benchmark():
    """Measures overhead of buffer-before-stream reconstruction and re-emission."""
    import json

    async def mock_stream():
        for i in range(20):
            chunk = {"choices": [{"delta": {"content": f"word{i} "}}]}
            yield f"data: {json.dumps(chunk)}\n\n"
        yield "data: [DONE]\n\n"

    t0 = time.perf_counter()
    chunks = []
    async for chunk in secure_stream_handler.process_stream(
        upstream_stream=mock_stream(),
        request_mapping={},
        model="benchmark-model",
    ):
        chunks.append(chunk)

    elapsed_ms = (time.perf_counter() - t0) * 1000
    print(f"\n[BENCHMARK] Buffered Stream Processing Overhead: {elapsed_ms:.3f}ms for 20 chunks")

    # The buffering overhead for 20 chunks must be well below 50ms
    assert elapsed_ms < 50.0
    assert len(chunks) > 20
