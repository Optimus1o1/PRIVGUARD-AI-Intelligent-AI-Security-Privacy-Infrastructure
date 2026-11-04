"""Latency benchmarking for inspection pipeline."""

import time
import pytest
from app.privacy.pipeline import inspection_pipeline


def test_inspection_pipeline_latency_benchmark():
    """Verifies that inspection processing latency is well below 50ms for text payloads."""
    sample_text = (
        "Hello assistant, please draft an email to client.contact@acme-corp.com "
        "discussing the architecture update for account number 9876543210. "
        "Ensure the server at 192.168.1.100 is monitored properly."
    )

    latencies = []
    # Warmup
    for _ in range(5):
        inspection_pipeline.inspect_text(sample_text)

    # 100 iterations
    for _ in range(100):
        t0 = time.perf_counter()
        verdict = inspection_pipeline.inspect_text(sample_text)
        latencies.append((time.perf_counter() - t0) * 1000)

    latencies.sort()
    p50 = latencies[50]
    p95 = latencies[95]

    print(f"\n[BENCHMARK] P50 Latency: {p50:.3f}ms | P95 Latency: {p95:.3f}ms")

    # Invariant: P95 latency must be under 50ms (target was < 300ms)
    assert p95 < 50.0, f"P95 latency {p95}ms exceeded 50ms threshold!"
    assert verdict.action.value == "REDACT"

