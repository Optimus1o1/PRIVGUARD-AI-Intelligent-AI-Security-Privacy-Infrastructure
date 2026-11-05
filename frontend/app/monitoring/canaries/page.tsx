"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  RefreshCw,
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowLeft,
  Clock,
  Activity,
  Lock,
} from "lucide-react";
import { api } from "@/lib/api";
import { CanaryResponse, CanaryResult } from "@/lib/types";

export default function CanariesMonitoringPage() {
  const [data, setData] = useState<CanaryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadCanaries = async (autoRun: boolean = false) => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getCanaries(autoRun);
      setData(res);
    } catch (err: any) {
      setError(err.message || "Failed to load canary telemetry");
    } finally {
      setLoading(false);
    }
  };

  const handleRunAll = async () => {
    try {
      setRunning(true);
      setError(null);
      const res = await api.runCanaries();
      setData(res);
    } catch (err: any) {
      setError(err.message || "Failed to execute canaries");
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    loadCanaries(true);
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
            <ShieldCheck className="h-7 w-7 text-accent" />
            Synthetic Security Canaries
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Continuous active verification of privacy, threat mitigation, and authorization controls.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => loadCanaries(false)}
            disabled={loading || running}
            className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-card hover:bg-muted text-foreground transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={handleRunAll}
            disabled={running || loading}
            className="inline-flex items-center gap-2 px-4 py-1.5 text-xs font-semibold rounded-md bg-accent text-background hover:bg-accent/90 transition-colors shadow-sm disabled:opacity-50"
          >
            <Play className={`h-3.5 w-3.5 ${running ? "animate-spin" : ""}`} />
            {running ? "Executing Canaries..." : "Run All Canaries Now"}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Summary Scorecard */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">Canary Suite Status</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1 flex items-center gap-2">
            {data?.summary?.healthy ? (
              <span className="text-emerald-400 flex items-center gap-2">
                <CheckCircle2 className="h-6 w-6" /> 100% PASSING
              </span>
            ) : (
              <span className="text-red-400 flex items-center gap-2">
                <XCircle className="h-6 w-6" /> DEGRADED
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Last Executed: {data?.summary?.last_run_timestamp ? new Date(data.summary.last_run_timestamp).toLocaleTimeString() : "Never"}
          </p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">Scenarios Passing</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1">
            {data?.summary?.passed ?? 0} / {data?.summary?.total_canaries ?? 8}
          </div>
          <p className="text-xs text-emerald-400 mt-1">Active verification checks</p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">Failed Assertions</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1">
            {data?.summary?.failed ?? 0}
          </div>
          <p className="text-xs text-muted-foreground mt-1">Zero-tolerance fail-closed threshold</p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">Average Latency</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1">
            {data?.canaries && data.canaries.length > 0
              ? (data.canaries.reduce((acc, c) => acc + c.latency_ms, 0) / data.canaries.length).toFixed(1)
              : "0.0"}{" "}
            ms
          </div>
          <p className="text-xs text-muted-foreground mt-1">In-process security overhead</p>
        </div>
      </div>

      {/* Canary Scenarios Grid */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-base font-bold font-heading text-foreground flex items-center gap-2">
            <Activity className="h-4 w-4 text-accent" />
            Configured Security Canaries (8 Active)
          </h2>
          <span className="text-xs text-muted-foreground font-mono">Synthetic Payload Execution</span>
        </div>
        <div className="divide-y divide-border">
          {data?.canaries?.map((canary) => (
            <div key={canary.canary_name} className="p-4 hover:bg-muted/10 transition-colors">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  {canary.passed ? (
                    <div className="h-8 w-8 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
                      <CheckCircle2 className="h-4 w-4" />
                    </div>
                  ) : (
                    <div className="h-8 w-8 rounded-full bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400 shrink-0">
                      <XCircle className="h-4 w-4" />
                    </div>
                  )}
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-heading font-bold text-sm text-foreground">
                        {canary.canary_name}
                      </h3>
                      <span className={`px-2 py-0.2 rounded text-[10px] uppercase font-mono font-bold ${
                        canary.severity === "critical"
                          ? "bg-red-500/10 text-red-400 border border-red-500/20"
                          : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                      }`}>
                        {canary.severity}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {canary.message}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono text-muted-foreground shrink-0 sm:text-right">
                  <div className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    <span>{canary.latency_ms.toFixed(2)} ms</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                    canary.passed
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                      : "bg-red-500/10 text-red-400 border border-red-500/20"
                  }`}>
                    {canary.passed ? "VERIFIED" : "FAILED"}
                  </span>
                </div>
              </div>

              {canary.details && (
                <div className="mt-3 pl-11">
                  <pre className="text-[11px] font-mono bg-muted/40 p-2 rounded border border-border/50 text-muted-foreground overflow-x-auto">
                    {JSON.stringify(canary.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
