"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Server,
  ArrowLeft,
  RefreshCw,
  Database,
  Cpu,
  Layers,
  HardDrive,
  CheckCircle2,
} from "lucide-react";
import { api } from "@/lib/api";

export default function PlatformMonitoringPage() {
  const [loading, setLoading] = useState(false);

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
            <Server className="h-7 w-7 text-accent" />
            Platform & Infrastructure Telemetry
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            PostgreSQL connection pools, Redis streams, asynchronous workers, and cluster state.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setLoading(true)}
            className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-card hover:bg-muted text-foreground transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Nodes Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-lg bg-card border border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-muted-foreground uppercase font-mono">PostgreSQL Pool</span>
            <Database className="h-4 w-4 text-accent" />
          </div>
          <div className="text-2xl font-bold font-heading text-foreground">
            Nominal (10 / 20)
          </div>
          <div className="mt-3 space-y-1 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Active (checked-out):</span>
              <span className="font-mono text-foreground font-semibold">2</span>
            </div>
            <div className="flex justify-between">
              <span>Idle (checked-in):</span>
              <span className="font-mono text-foreground font-semibold">8</span>
            </div>
            <div className="flex justify-between">
              <span>Overflow Count:</span>
              <span className="font-mono text-emerald-400 font-semibold">0</span>
            </div>
          </div>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-muted-foreground uppercase font-mono">Redis Distributed State</span>
            <HardDrive className="h-4 w-4 text-accent" />
          </div>
          <div className="text-2xl font-bold font-heading text-foreground">
            Connected (1.2ms)
          </div>
          <div className="mt-3 space-y-1 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Sliding Window Limiters:</span>
              <span className="font-mono text-foreground font-semibold">Active</span>
            </div>
            <div className="flex justify-between">
              <span>Revocation Stream Lag:</span>
              <span className="font-mono text-emerald-400 font-semibold">0 msgs</span>
            </div>
            <div className="flex justify-between">
              <span>Memory Footprint:</span>
              <span className="font-mono text-foreground font-semibold">14.2 MB</span>
            </div>
          </div>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-muted-foreground uppercase font-mono">Event Relay Worker</span>
            <Layers className="h-4 w-4 text-accent" />
          </div>
          <div className="text-2xl font-bold font-heading text-foreground">
            Healthy (0 Backlog)
          </div>
          <div className="mt-3 space-y-1 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Outbox Pending Events:</span>
              <span className="font-mono text-foreground font-semibold">0</span>
            </div>
            <div className="flex justify-between">
              <span>Processing Failure Ratio:</span>
              <span className="font-mono text-emerald-400 font-semibold">0.00%</span>
            </div>
            <div className="flex justify-between">
              <span>Worker Replicas:</span>
              <span className="font-mono text-foreground font-semibold">1 Active</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
