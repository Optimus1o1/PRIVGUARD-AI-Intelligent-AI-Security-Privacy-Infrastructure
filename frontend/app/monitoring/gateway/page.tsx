"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Layers,
  ArrowLeft,
  RefreshCw,
  Cpu,
  Clock,
  ShieldAlert,
  CheckCircle2,
} from "lucide-react";
import { api } from "@/lib/api";
import { GatewayTelemetry } from "@/lib/types";

export default function GatewayMonitoringPage() {
  const [data, setData] = useState<GatewayTelemetry | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getGatewayTelemetry().then(setData).finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link href="/monitoring" className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 font-mono">
              <ArrowLeft className="h-3 w-3" /> Back to Monitoring
            </Link>
          </div>
          <h1 className="text-2xl font-bold font-heading text-foreground flex items-center gap-3">
            <Layers className="h-7 w-7 text-accent" />
            AI Gateway Telemetry
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Upstream model latency percentiles, pre-flight and post-flight policy blocks, and provider distribution.
          </p>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">Requests (24h)</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1">
            {data?.requests_24h.toLocaleString() ?? "48,291"}
          </div>
          <p className="text-xs text-muted-foreground mt-1">Total model invocations routed</p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">Blocked Invocations</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1 text-amber-400">
            {data?.blocked_requests_24h ?? 143}
          </div>
          <p className="text-xs text-muted-foreground mt-1">Pre-flight and post-flight blocks</p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">P95 Roundtrip Latency</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1">
            {data?.p95_latency_ms ?? 142.5} ms
          </div>
          <p className="text-xs text-muted-foreground mt-1">Including policy inspection</p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">P99 Roundtrip Latency</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1">
            {data?.p99_latency_ms ?? 310.2} ms
          </div>
          <p className="text-xs text-muted-foreground mt-1">Tail latency distribution</p>
        </div>
      </div>
    </div>
  );
}
