"use client";

import React, { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  Layers,
  Lock,
  RefreshCw,
  Shield,
  ShieldAlert,
  Zap,
} from "lucide-react";
import { api } from "@/lib/api";
import { Agent, DashboardSummary, ThreatEvent, ThreatStatistics } from "@/lib/types";
import { ProtectionGauge } from "@/components/dashboard/ProtectionGauge";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { ThreatForecastChart } from "@/components/dashboard/ThreatForecastChart";
import { ActiveAgentsTable } from "@/components/dashboard/ActiveAgentsTable";
import { RecentThreatsFeed } from "@/components/dashboard/RecentThreatsFeed";

export default function OverviewPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [threatStats, setThreatStats] = useState<ThreatStatistics | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    try {
      setError(null);
      const [sumData, statsData, agentsData, threatsData] = await Promise.all([
        api.getSummary(),
        api.getThreatStatistics(),
        api.getAgents(),
        api.getThreatEvents({ limit: 5 }),
      ]);
      setSummary(sumData);
      setThreatStats(statsData);
      setAgents(agentsData);
      setThreats(threatsData);
    } catch (err: any) {
      setError(err.message || "Failed to load dashboard data from backend.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 8000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !summary) {
    return (
      <div className="h-[80vh] flex flex-col items-center justify-center space-y-3">
        <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
        <p className="text-xs text-slate font-mono">Connecting to PRIVGUARD Security Gateway...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner / Error */}
      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-xs flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={loadData}
            className="px-2 py-1 rounded bg-red-900/60 hover:bg-red-800 text-bone text-[11px] font-semibold"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Grid Row 1: Radial Protection Gauge + Primary Metric Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Semi-circular radial gauge (Inspired by user's demo layout) */}
        <div className="lg:col-span-1">
          <ProtectionGauge
            score={summary?.protection_score || 98}
            status={summary?.security_status || "PROTECTED"}
          />
        </div>

        {/* 4 Primary KPI cards */}
        <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-2 gap-4">
          <MetricCard
            label="Total AI Requests"
            value={summary?.total_requests || 0}
            icon={Zap}
            subtitle="Request inspection perimeter"
            badge="Fail-Closed"
            badgeColor="cyan"
          />
          <MetricCard
            label="Blocked Interceptions"
            value={summary?.blocked_requests || 0}
            icon={ShieldAlert}
            subtitle="Zero secrets leaked"
            badge={summary?.blocked_requests ? "Active Defense" : "Clean"}
            badgeColor={summary?.blocked_requests ? "red" : "emerald"}
          />
          <MetricCard
            label="PII Entities Redacted"
            value={summary?.pii_redactions || 0}
            icon={Lock}
            subtitle="Reversible token masking"
            badge="Luhn Verified"
            badgeColor="emerald"
          />
          <MetricCard
            label="Pending Approvals"
            value={summary?.pending_approvals || 0}
            icon={CheckCircle2}
            subtitle="Human authorization hold"
            badge={summary?.pending_approvals ? "Action Required" : "Queue Clean"}
            badgeColor={summary?.pending_approvals ? "amber" : "emerald"}
            urgent={(summary?.pending_approvals || 0) > 0}
          />
        </div>
      </div>

      {/* Grid Row 2: Secondary Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <MetricCard
          label="Active AI Agents"
          value={summary?.active_agents || 0}
          icon={Bot}
          subtitle="Least-privilege brokered"
        />
        <MetricCard
          label="Running Tasks"
          value={summary?.running_tasks || 0}
          icon={Layers}
          subtitle="Sliding window active"
        />
        <MetricCard
          label="Threats Intercepted"
          value={summary?.threats_detected || 0}
          icon={Shield}
          subtitle="Direct & indirect attacks"
        />
        <MetricCard
          label="Critical Threats"
          value={summary?.critical_threats || 0}
          icon={AlertTriangle}
          subtitle="Immediate task termination"
          badgeColor="red"
          urgent={(summary?.critical_threats || 0) > 0}
        />
      </div>

      {/* Grid Row 3: Threat Activity Chart & Live Threat Interceptions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ThreatForecastChart data={threatStats?.recent_timeline || []} />
        <RecentThreatsFeed threats={threats} />
      </div>

      {/* Grid Row 4: Connected Systems & Active Agents Table */}
      <div>
        <ActiveAgentsTable agents={agents} />
      </div>
    </div>
  );
}

