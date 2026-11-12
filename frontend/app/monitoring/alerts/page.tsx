"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  RefreshCw,
  BellRing,
  ShieldCheck,
  CheckCircle2,
  Inbox,
  Filter,
} from "lucide-react";
import { api } from "@/lib/api";
import { AlertsResponse } from "@/lib/types";

export default function AlertsMonitoringPage() {
  const [data, setData] = useState<AlertsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getActiveAlerts().then(setData).finally(() => setLoading(false));
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
            <BellRing className="h-7 w-7 text-accent" />
            Alerts & Incident Console
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Alertmanager rule evaluation, routing hierarchy, and active notifications.
          </p>
        </div>
      </div>

      {/* Alert Routing Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-lg bg-card border border-border">
          <span className="text-[10px] uppercase font-mono font-bold text-red-400">CRITICAL Route</span>
          <h3 className="font-heading font-bold text-foreground text-sm mt-1">Pager & Security Lead</h3>
          <p className="text-xs text-muted-foreground mt-0.5">Immediate paging + repeat every 1h</p>
        </div>

        <div className="p-4 rounded-lg bg-card border border-border">
          <span className="text-[10px] uppercase font-mono font-bold text-amber-400">HIGH Route</span>
          <h3 className="font-heading font-bold text-foreground text-sm mt-1">Operations Webhook</h3>
          <p className="text-xs text-muted-foreground mt-0.5">Ops notification + repeat every 2h</p>
        </div>

        <div className="p-4 rounded-lg bg-card border border-border">
          <span className="text-[10px] uppercase font-mono font-bold text-blue-400">MEDIUM Route</span>
          <h3 className="font-heading font-bold text-foreground text-sm mt-1">Engineering Channel</h3>
          <p className="text-xs text-muted-foreground mt-0.5">Slack/Discord ops notification</p>
        </div>

        <div className="p-4 rounded-lg bg-card border border-border">
          <span className="text-[10px] uppercase font-mono font-bold text-muted-foreground">LOW Route</span>
          <h3 className="font-heading font-bold text-foreground text-sm mt-1">Dashboard Only</h3>
          <p className="text-xs text-muted-foreground mt-0.5">Absorbed without outbound paging</p>
        </div>
      </div>

      {/* Active Alerts List */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-base font-bold font-heading text-foreground flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-accent" />
            Active Firing Alerts ({data?.total_firing ?? 0})
          </h2>
          <span className="text-xs text-muted-foreground font-mono">Prometheus Alert Rules</span>
        </div>

        {data?.firing_alerts && data.firing_alerts.length > 0 ? (
          <div className="divide-y divide-border">
            {data.firing_alerts.map((alert, idx) => (
              <div key={idx} className="p-4 hover:bg-muted/10 transition-colors flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-heading font-bold text-sm text-foreground">{alert.alertname}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/10 text-red-400 border border-red-500/20">
                      {alert.severity}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">{alert.description}</p>
                </div>
                <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-red-500/10 text-red-400 border border-red-500/20">
                  FIRING
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-12 text-center text-muted-foreground">
            <CheckCircle2 className="h-10 w-10 text-emerald-400 mx-auto mb-3" />
            <p className="text-sm font-medium text-foreground">Zero Firing Alerts</p>
            <p className="text-xs text-muted-foreground mt-1">
              All infrastructure, AI gateway, and security invariant alert rules are nominal.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
