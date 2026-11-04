"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import {
  AlertTriangle,
  ArrowLeft,
  Bot,
  CheckCircle2,
  Clock,
  Database,
  Globe,
  Key,
  Mail,
  Shield,
  ShieldAlert,
  Terminal,
  Trash2,
  Wrench,
} from "lucide-react";
import { api } from "@/lib/api";
import { Agent } from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";
import { formatDate } from "@/lib/utils";

interface ToolNode {
  name: string;
  category: string;
  icon: any;
  risk: string;
  permission: "ALLOW" | "REQUIRE_APPROVAL" | "DENIED";
  scope: string;
}

const ALL_SYSTEM_TOOLS: ToolNode[] = [
  {
    name: "read_file",
    category: "Filesystem",
    icon: Wrench,
    risk: "LOW",
    permission: "ALLOW",
    scope: "./sandbox/* only",
  },
  {
    name: "search_web",
    category: "Web & Retrieval",
    icon: Globe,
    risk: "LOW",
    permission: "ALLOW",
    scope: "Public search queries",
  },
  {
    name: "send_email",
    category: "Communication",
    icon: Mail,
    risk: "HIGH",
    permission: "REQUIRE_APPROVAL",
    scope: "Outbound sink (Held in Escrow)",
  },
  {
    name: "http_request",
    category: "Network",
    icon: Globe,
    risk: "HIGH",
    permission: "REQUIRE_APPROVAL",
    scope: "Allowlist enforced (MITRE T1700)",
  },
  {
    name: "query_database",
    category: "Data Storage",
    icon: Database,
    risk: "HIGH",
    permission: "REQUIRE_APPROVAL",
    scope: "Tenant-bound schemas",
  },
  {
    name: "execute_bash",
    category: "OS Execution",
    icon: Terminal,
    risk: "CRITICAL",
    permission: "REQUIRE_APPROVAL",
    scope: "Isolated process sandbox",
  },
];

export default function AgentDetailsPage() {
  const params = useParams();
  const router = useRouter();
  const agentId = params.id as string;

  const [agent, setAgent] = useState<Agent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [processing, setProcessing] = useState(false);

  const loadAgent = async () => {
    try {
      setError(null);
      const data = await api.getAgent(agentId);
      setAgent(data);
    } catch (err: any) {
      setError(err.message || "Failed to load agent details.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAgent();
  }, [agentId]);

  const handleDisableAgent = async () => {
    if (!confirm("Are you sure you want to disable this agent? It will immediately block all tool executions.")) return;
    setProcessing(true);
    try {
      await api.disableAgent(agentId);
      setActionSuccess("Agent disabled successfully.");
      await loadAgent();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setProcessing(false);
    }
  };

  const handleRevokeAgent = async () => {
    if (!confirm("Are you sure you want to permanently revoke this agent identity? This action cannot be undone.")) return;
    setProcessing(true);
    try {
      await api.revokeAgent(agentId);
      setActionSuccess("Agent permanently revoked.");
      await loadAgent();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setProcessing(false);
    }
  };

  if (loading && !agent) {
    return (
      <div className="text-center py-20 text-slate text-xs font-mono">
        Loading agent details...
      </div>
    );
  }

  if (!agent) {
    return (
      <div className="text-center py-20 bg-card border border-border rounded-xl">
        <p className="text-xs text-red-400">Agent '{agentId}' not found.</p>
        <Link href="/agents" className="mt-3 text-cyan-400 text-xs inline-block hover:underline">
          Return to Agent Directory
        </Link>
      </div>
    );
  }

  const allowedSet = new Set(agent.allowed_tools || []);

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <Link
          href="/agents"
          className="flex items-center gap-1.5 text-xs text-slate hover:text-bone transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Agent Directory</span>
        </Link>

        <div className="flex items-center gap-3">
          {agent.status === "ACTIVE" && (
            <button
              onClick={handleDisableAgent}
              disabled={processing}
              className="px-3 py-1.5 rounded-lg border border-amber-800 text-amber-400 hover:bg-amber-950/40 text-xs font-semibold transition-colors"
            >
              Disable Agent
            </button>
          )}
          {agent.status !== "REVOKED" && (
            <button
              onClick={handleRevokeAgent}
              disabled={processing}
              className="px-3 py-1.5 rounded-lg border border-red-800 text-red-400 hover:bg-red-950/40 text-xs font-semibold transition-colors flex items-center gap-1.5"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Revoke Identity</span>
            </button>
          )}
        </div>
      </div>

      {actionSuccess && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800 text-emerald-300 text-xs">
          {actionSuccess}
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-xs">
          {error}
        </div>
      )}

      {/* Agent Header Card */}
      <div className="bg-card border border-border rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/60 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-surface border border-border flex items-center justify-center">
              <Bot className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-display font-bold text-bone text-base">{agent.name}</h2>
                <StatusPill status={agent.status} />
              </div>
              <p className="text-xs text-slate font-mono mt-0.5">{agent.id}</p>
            </div>
          </div>

          <div className="text-xs text-slate font-mono text-right">
            <div>Registered: {formatDate(agent.created_at)}</div>
            <div>Last Active: {formatDate(agent.last_activity_at)}</div>
          </div>
        </div>

        <p className="text-xs text-slate/90">
          {agent.description || "Autonomous AI agent registered under PRIVGUARD broker boundaries."}
        </p>
      </div>

      {/* Visual Agent Access Map (Feature 2 Prioritized) */}
      <div className="bg-card border border-border rounded-xl p-6 shadow-sm space-y-6">
        <div className="flex items-center justify-between border-b border-border/60 pb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <h3 className="font-display font-bold text-bone text-sm uppercase tracking-wide">
              Agent Access Map & Permission Topography
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate">
            Architecture: Least-Privilege Mediation
          </span>
        </div>

        {/* Tree Topology Flow */}
        <div className="flex flex-col items-center justify-center space-y-4 py-2">
          {/* Node 1: AI Agent */}
          <div className="px-5 py-2.5 rounded-xl bg-surface border border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.15)] flex items-center gap-2">
            <Bot className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-semibold text-bone">{agent.name}</span>
            <span className="text-[10px] font-mono text-slate">({agent.id})</span>
          </div>

          <div className="h-6 w-px bg-border relative">
            <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 -translate-x-[2px] absolute top-1/2" />
          </div>

          {/* Node 2: PRIVGUARD Security Broker */}
          <div className="px-6 py-2.5 rounded-xl bg-surface border border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.15)] flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span className="text-xs font-semibold text-bone">PRIVGUARD Security Broker</span>
            <span className="text-[10px] font-mono text-emerald-400">Enforcing Least-Privilege</span>
          </div>

          <div className="h-6 w-px bg-border relative">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 -translate-x-[2px] absolute top-1/2" />
          </div>

          {/* Node 3: Tools Matrix Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 w-full pt-2">
            {ALL_SYSTEM_TOOLS.map((tool) => {
              const isAllowlisted = allowedSet.has(tool.name);
              const ToolIcon = tool.icon;

              return (
                <div
                  key={tool.name}
                  className={`bg-surface border rounded-xl p-4 flex flex-col justify-between transition-all ${
                    isAllowlisted
                      ? tool.permission === "REQUIRE_APPROVAL"
                        ? "border-amber-500/40 bg-amber-950/5 shadow-[0_0_10px_rgba(245,158,11,0.08)]"
                        : "border-emerald-500/40 bg-emerald-950/5"
                      : "border-border/60 opacity-60 bg-surface/40"
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <ToolIcon className="w-4 h-4 text-slate" />
                      <span className="text-xs font-semibold font-mono text-bone">
                        {tool.name}
                      </span>
                    </div>
                    {isAllowlisted ? (
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                          tool.permission === "REQUIRE_APPROVAL"
                            ? "bg-amber-950/60 text-amber-400 border-amber-800"
                            : "bg-emerald-950/60 text-emerald-400 border-emerald-800"
                        }`}
                      >
                        {tool.permission.replace(/_/g, " ")}
                      </span>
                    ) : (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-900 text-zinc-500 border border-zinc-800 uppercase">
                        DENIED
                      </span>
                    )}
                  </div>

                  <div className="text-[11px] text-slate/80 space-y-1 font-mono mt-2">
                    <div>Category: {tool.category}</div>
                    <div>Risk Floor: {tool.risk}</div>
                    <div className="text-[10px] text-slate/60">Scope: {tool.scope}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
