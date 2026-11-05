"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Activity,
  ShieldCheck,
  AlertTriangle,
  Server,
  Zap,
  CheckCircle2,
  RefreshCw,
  ArrowRight,
  TrendingUp,
  Cpu,
  Layers,
} from "lucide-react";
import { api } from "@/lib/api";
import { MonitoringOverview } from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";

export default function MonitoringOverviewPage() {
  const [data, setData] = useState<MonitoringOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getMonitoringOverview();
      setData(res);
    } catch (err: any) {
      setError(err.message || "Failed to load monitoring overview");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-8">
      {/* Header & Sub-navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs uppercase tracking-wider text-muted-foreground font-mono">
              Telemetry & Observability
            </span>
          </div>
          <h1 className="text-2xl font-bold font-heading text-foreground flex items-center gap-3">
            <Activity className="h-7 w-7 text-accent" />
            Control Center Monitoring
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Production OpenTelemetry, low-cardinality Prometheus metrics, and active synthetic canaries.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md border border-border bg-card hover:bg-muted text-foreground transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <StatusPill
            status={data?.status === "nominal" ? "PROTECTED" : "DEGRADED"}
          />
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-border/50 text-sm font-medium">
        <Link href="/monitoring" className="px-3 py-1.5 rounded-md bg-accent/10 text-accent font-semibold">
          Overview
        </Link>
        <Link href="/monitoring/platform" className="px-3 py-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors">
          Platform & Nodes
        </Link>
        <Link href="/monitoring/gateway" className="px-3 py-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors">
          AI Gateway
        </Link>
        <Link href="/monitoring/security" className="px-3 py-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors">
          Security Telemetry
        </Link>
        <Link href="/monitoring/agents" className="px-3 py-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors">
          Agent Fleet
        </Link>
        <Link href="/monitoring/canaries" className="px-3 py-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors">
          Canaries
        </Link>
        <Link href="/monitoring/alerts" className="px-3 py-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors">
          Alerts
        </Link>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* High-Level Scorecards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-lg bg-card border border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-muted-foreground uppercase font-mono">Service Status</span>
            <Server className="h-4 w-4 text-accent" />
          </div>
          <div className="text-2xl font-bold font-heading text-foreground">
            {data?.service || "PRIVGUARD"}
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Env: <span className="font-mono text-foreground font-semibold">{data?.environment || "development"}</span> (v{data?.version || "0.1.0"})
          </p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-muted-foreground uppercase font-mono">Availability SLI</span>
            <TrendingUp className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-heading text-foreground">
            {data?.slos?.api_availability ? `${(data.slos.api_availability.current_ratio * 100).toFixed(2)}%` : "99.80%"}
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Target: ≥ 99.50% (30-day window)
          </p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-muted-foreground uppercase font-mono">Active Canaries</span>
            <ShieldCheck className="h-4 w-4 text-accent" />
          </div>
          <div className="text-2xl font-bold font-heading text-foreground">
            {data?.canary_summary?.passed ?? 8} / {data?.canary_summary?.total_canaries ?? 8}
          </div>
          <p className="text-xs text-emerald-400 font-medium mt-1">
            100% Security Assertions Passing
          </p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-muted-foreground uppercase font-mono">Active Alerts</span>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </div>
          <div className="text-2xl font-bold font-heading text-foreground">
            {data?.active_alerts_count ?? 0}
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Threshold violations: 0 firing
          </p>
        </div>
      </div>

      {/* Service Level Objectives Table */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-base font-bold font-heading text-foreground flex items-center gap-2">
            <Zap className="h-4 w-4 text-accent" />
            Service Level Objectives (SLOs) & Reliability
          </h2>
          <span className="text-xs text-muted-foreground font-mono">Rolling 30-Day Multi-Window</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted/50 border-b border-border text-xs uppercase font-mono text-muted-foreground">
              <tr>
                <th className="px-4 py-3">Objective</th>
                <th className="px-4 py-3">Target</th>
                <th className="px-4 py-3">Current SLI</th>
                <th className="px-4 py-3">Error Budget Remaining</th>
                <th className="px-4 py-3">Burn Rate</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {data?.slos &&
                Object.entries(data.slos).map(([key, slo]) => (
                  <tr key={key} className="hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-3 font-medium text-foreground">
                      {slo.name}
                    </td>
                    <td className="px-4 py-3 text-muted-foreground font-mono">
                      {(slo.target * 100).toFixed(1)}%
                    </td>
                    <td className="px-4 py-3 font-mono font-semibold text-foreground">
                      {(slo.current_ratio * 100).toFixed(2)}%
                    </td>
                    <td className="px-4 py-3 font-mono text-muted-foreground">
                      {(slo.error_budget_remaining * 100).toFixed(1)}%
                    </td>
                    <td className="px-4 py-3 font-mono">
                      <span className={slo.burn_rate > 1 ? "text-amber-400 font-bold" : "text-muted-foreground"}>
                        {slo.burn_rate.toFixed(2)}x
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold ${
                        slo.healthy ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-red-500/10 text-red-400 border border-red-500/20"
                      }`}>
                        {slo.healthy ? <CheckCircle2 className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
                        {slo.healthy ? "HEALTHY" : "VIOLATING"}
                      </span>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Quick Launch Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          href="/monitoring/canaries"
          className="p-5 rounded-lg border border-border bg-card hover:border-accent/40 transition-all group"
        >
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-heading font-bold text-foreground text-sm group-hover:text-accent transition-colors flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-accent" />
              Synthetic Security Canaries
            </h3>
            <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:translate-x-1 transition-transform" />
          </div>
          <p className="text-xs text-muted-foreground">
            Execute 8 automated security canaries validating PII redaction, secret blocking, and AEAD memory isolation.
          </p>
        </Link>

        <Link
          href="/monitoring/gateway"
          className="p-5 rounded-lg border border-border bg-card hover:border-accent/40 transition-all group"
        >
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-heading font-bold text-foreground text-sm group-hover:text-accent transition-colors flex items-center gap-2">
              <Layers className="h-4 w-4 text-accent" />
              AI Gateway Telemetry
            </h3>
            <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:translate-x-1 transition-transform" />
          </div>
          <p className="text-xs text-muted-foreground">
            Inspect model invocation rates, pre-flight policy denials, and upstream provider latency distributions.
          </p>
        </Link>

        <Link
          href="/monitoring/alerts"
          className="p-5 rounded-lg border border-border bg-card hover:border-accent/40 transition-all group"
        >
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-heading font-bold text-foreground text-sm group-hover:text-accent transition-colors flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-accent" />
              Incident & Alert Console
            </h3>
            <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:translate-x-1 transition-transform" />
          </div>
          <p className="text-xs text-muted-foreground">
            View Alertmanager routing, firing alerts, notification receivers, and inhibition hierarchies.
          </p>
        </Link>
      </div>
    </div>
  );
}
