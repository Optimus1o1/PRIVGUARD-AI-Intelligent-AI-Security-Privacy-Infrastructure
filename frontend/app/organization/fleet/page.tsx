"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Radio,
  ArrowLeft,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Ban,
  Activity,
  Bot,
  Network,
  Cpu,
  ShieldAlert,
} from "lucide-react";
import { api } from "@/lib/api";

export default function FleetInventoryAndDrift() {
  const [fleet, setFleet] = useState<any[]>([]);
  const [syncStatus, setSyncStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [orgId, setOrgId] = useState("default_tenant");

  const fetchFleetData = async () => {
    setLoading(true);
    try {
      const orgs = await api.getOrganizations();
      const currentOrgId = orgs && orgs.length > 0 ? orgs[0].id : "default_tenant";
      setOrgId(currentOrgId);

      const [fleetData, syncData] = await Promise.all([
        api.getFleet(currentOrgId),
        api.getPolicySyncStatus(currentOrgId),
      ]);
      setFleet(fleetData);
      setSyncStatus(syncData);
    } catch {
      // Mock fallback
      setFleet([
        {
          id: "res_1",
          resource_id: "agent_code_assistant",
          resource_type: "AGENT",
          name: "Code Review & Refactor Agent",
          environment: "production",
          status: "ACTIVE",
          active_policy_version: 4,
          drift_status: "SYNCED",
          last_heartbeat_at: new Date(Date.now() - 30000).toISOString(),
          registered_at: new Date(Date.now() - 86400000).toISOString(),
        },
        {
          id: "res_2",
          resource_id: "mcps_github_gateway",
          resource_type: "MCP_SERVER",
          name: "GitHub Enterprise MCP Gateway",
          environment: "production",
          status: "ACTIVE",
          active_policy_version: 4,
          drift_status: "SYNCED",
          last_heartbeat_at: new Date(Date.now() - 45000).toISOString(),
          registered_at: new Date(Date.now() - 86400000).toISOString(),
        },
        {
          id: "res_3",
          resource_id: "agent_support_bot",
          resource_type: "AGENT",
          name: "Tier-1 Customer Help Agent",
          environment: "production",
          status: "ACTIVE",
          active_policy_version: 3,
          drift_status: "DRIFTED",
          last_heartbeat_at: new Date(Date.now() - 120000).toISOString(),
          registered_at: new Date(Date.now() - 86400000).toISOString(),
        },
      ]);
      setSyncStatus({
        total_resources: 3,
        synced_count: 2,
        drifted_count: 1,
        disconnected_count: 0,
        revoked_count: 0,
        compliance_percentage: 66.7,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFleetData();
  }, []);

  const handleRevoke = async (resourceId: string, name: string) => {
    if (!confirm(`Are you sure you want to centrally REVOKE '${name}'? All subsequent tool calls from this resource will be immediately rejected at the broker.`)) return;
    try {
      await api.revokeFleetResource(orgId, resourceId, "Administrative central killswitch triggered");
      fetchFleetData();
    } catch (err: any) {
      alert("Revocation failed: " + (err.message || "Unknown error"));
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/80 pb-5">
        <div className="flex items-center gap-3">
          <Link
            href="/organization"
            className="p-1.5 rounded-lg border border-border bg-card/60 hover:bg-card text-slate hover:text-bone transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-bone font-display">
              Fleet Inventory & Policy Drift Monitor
            </h1>
            <p className="text-xs text-slate mt-0.5">
              Live tracking of AI agents, MCP gateways, policy drift detection, and broker-side central revocation.
            </p>
          </div>
        </div>

        <button
          onClick={fetchFleetData}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border bg-card hover:bg-card/70 text-xs font-medium text-bone transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          Refresh Fleet
        </button>
      </div>

      {/* Sync Status Gauges */}
      {syncStatus && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="p-4 rounded-xl border border-border bg-card/40">
            <div className="text-[11px] font-mono text-slate">Total Fleet</div>
            <div className="text-2xl font-bold font-mono text-bone mt-1">
              {syncStatus.total_resources}
            </div>
          </div>
          <div className="p-4 rounded-xl border border-emerald-900/50 bg-emerald-950/20">
            <div className="text-[11px] font-mono text-emerald-400">Policy Synced</div>
            <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
              {syncStatus.synced_count}
            </div>
          </div>
          <div className="p-4 rounded-xl border border-amber-900/50 bg-amber-950/20">
            <div className="text-[11px] font-mono text-amber-400">Drift Detected</div>
            <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
              {syncStatus.drifted_count}
            </div>
          </div>
          <div className="p-4 rounded-xl border border-rose-900/50 bg-rose-950/20">
            <div className="text-[11px] font-mono text-rose-400">Disconnected</div>
            <div className="text-2xl font-bold font-mono text-rose-400 mt-1">
              {syncStatus.disconnected_count}
            </div>
          </div>
          <div className="p-4 rounded-xl border border-cyan-900/50 bg-cyan-950/20">
            <div className="text-[11px] font-mono text-cyan-400">Compliance Rate</div>
            <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
              {syncStatus.compliance_percentage}%
            </div>
          </div>
        </div>
      )}

      {/* Authoritative Revocation Banner */}
      <div className="p-4 rounded-xl border border-rose-900/50 bg-rose-950/20 flex items-start gap-3 text-xs text-slate leading-relaxed">
        <ShieldAlert className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
        <div>
          <span className="font-semibold text-rose-300">Centralized Broker Revocation:</span> When an administrator disables an agent or MCP server, PRIVGUARD immediately rejects all subsequent tool executions and memory reads at the security broker, even if the remote client is disconnected or offline.
        </div>
      </div>

      {/* Fleet Table */}
      <div className="rounded-xl border border-border bg-card/40 overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-border/80 bg-card/80 text-[11px] font-mono text-slate uppercase tracking-wider">
              <th className="py-3 px-4">Resource</th>
              <th className="py-3 px-4">Type</th>
              <th className="py-3 px-4">Environment</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Policy Sync</th>
              <th className="py-3 px-4">Last Heartbeat</th>
              <th className="py-3 px-4 text-right">Revocation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/50 text-xs">
            {fleet.map((item) => (
              <tr key={item.id || item.resource_id} className="hover:bg-card/60 transition-colors">
                <td className="py-3.5 px-4 font-medium text-bone">
                  <div className="flex items-center gap-2">
                    {item.resource_type === "AGENT" ? (
                      <Bot className="w-4 h-4 text-cyan-400" />
                    ) : (
                      <Network className="w-4 h-4 text-emerald-400" />
                    )}
                    <div>
                      <div>{item.name}</div>
                      <div className="text-[10px] font-mono text-slate">{item.resource_id}</div>
                    </div>
                  </div>
                </td>
                <td className="py-3.5 px-4 font-mono text-[11px] text-slate">
                  {item.resource_type}
                </td>
                <td className="py-3.5 px-4 font-mono text-[11px] text-slate">
                  {item.environment}
                </td>
                <td className="py-3.5 px-4">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                      item.status === "ACTIVE"
                        ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800/60"
                        : "bg-red-950/80 text-red-400 border border-red-800/60"
                    }`}
                  >
                    {item.status}
                  </span>
                </td>
                <td className="py-3.5 px-4">
                  {item.drift_status === "SYNCED" ? (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 inline-flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" /> v{item.active_policy_version} Synced
                    </span>
                  ) : item.drift_status === "DRIFTED" ? (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-amber-950/80 text-amber-400 border border-amber-800/60 inline-flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" /> v{item.active_policy_version} (Drift)
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-rose-950/80 text-rose-400 border border-rose-800/60 inline-flex items-center gap-1">
                      Disconnected
                    </span>
                  )}
                </td>
                <td className="py-3.5 px-4 font-mono text-slate text-[11px]">
                  {new Date(item.last_heartbeat_at).toLocaleTimeString()}
                </td>
                <td className="py-3.5 px-4 text-right">
                  {item.status === "ACTIVE" ? (
                    <button
                      onClick={() => handleRevoke(item.resource_id, item.name)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-rose-950/40 hover:bg-rose-950/80 border border-rose-800/50 text-[11px] text-rose-300 hover:text-rose-200 transition-colors"
                    >
                      <Ban className="w-3 h-3" />
                      Killswitch
                    </button>
                  ) : (
                    <span className="text-[11px] font-mono text-red-400">Revoked</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

