"use client";

import { useEffect, useState } from "react";
import {
  Network,
  Server,
  Wrench,
  Shield,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Plus,
  Trash2,
  Power,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Play,
  FileCode,
  Lock,
  Search,
  SlidersHorizontal,
  ExternalLink,
  Cpu,
  Terminal,
  Clock,
} from "lucide-react";
import { api } from "@/lib/api";
import {
  MCPServer,
  MCPToolDefinition,
  MCPAuditEvent,
  CatalogSyncResult,
} from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";

export default function MCPGatewayPage() {
  const [activeTab, setActiveTab] = useState<"overview" | "servers" | "tools" | "activity">("overview");
  const [loading, setLoading] = useState(true);

  // Data states
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [tools, setTools] = useState<MCPToolDefinition[]>([]);
  const [activity, setActivity] = useState<MCPAuditEvent[]>([]);

  // Filter states
  const [toolSearch, setToolSearch] = useState("");
  const [toolRiskFilter, setToolRiskFilter] = useState("ALL");
  const [toolServerFilter, setToolServerFilter] = useState("ALL");

  // Registration Modal State
  const [registerModalOpen, setRegisterModalOpen] = useState(false);
  const [newServerName, setNewServerName] = useState("");
  const [newServerDesc, setNewServerDesc] = useState("");
  const [newTransportType, setNewTransportType] = useState<"streamable_http" | "stdio">("streamable_http");
  const [newEndpointUrl, setNewEndpointUrl] = useState("");
  const [newCommand, setNewCommand] = useState("");
  const [newArgs, setNewArgs] = useState("");
  const [newAuthType, setNewAuthType] = useState("NONE");
  const [newAuthCredRef, setNewAuthCredRef] = useState("");
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [registering, setRegistering] = useState(false);

  // Sync / Action State
  const [syncingServerId, setSyncingServerId] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Schema Inspection Modal State
  const [schemaModal, setSchemaModal] = useState<{ open: boolean; tool?: MCPToolDefinition }>({ open: false });

  // Tool Call Test Modal State
  const [callModal, setCallModal] = useState<{
    open: boolean;
    tool?: MCPToolDefinition;
    paramsText: string;
    agentId: string;
    capabilityToken: string;
    loading: boolean;
    result?: any;
    error?: string;
  }>({
    open: false,
    paramsText: "{}",
    agentId: "agent-preview",
    capabilityToken: "",
    loading: false,
  });

  const loadData = async () => {
    try {
      setLoading(true);
      const [srvList, toolList, actList] = await Promise.all([
        api.getMCPServers(),
        api.getMCPTools(),
        api.getMCPActivity({ limit: 50 }),
      ]);
      setServers(srvList || []);
      setTools(toolList || []);
      setActivity(actList || []);
    } catch (err: any) {
      console.error("Failed to load MCP Gateway data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRegisterServer = async (e: React.FormEvent) => {
    e.preventDefault();
    setRegisterError(null);
    setRegistering(true);

    try {
      const parsedArgs = newArgs
        .split(" ")
        .map((a) => a.trim())
        .filter(Boolean);

      await api.registerMCPServer({
        name: newServerName.trim(),
        description: newServerDesc.trim() || undefined,
        transport_type: newTransportType,
        endpoint_url: newTransportType === "streamable_http" ? newEndpointUrl.trim() : undefined,
        command: newTransportType === "stdio" ? newCommand.trim() : undefined,
        args: newTransportType === "stdio" ? parsedArgs : undefined,
        auth_type: newAuthType,
        auth_credential_ref: newAuthCredRef.trim() || undefined,
      });

      setRegisterModalOpen(false);
      setNewServerName("");
      setNewServerDesc("");
      setNewEndpointUrl("");
      setNewCommand("");
      setNewArgs("");
      setNewAuthType("NONE");
      setNewAuthCredRef("");
      setActionMessage({ type: "success", text: "MCP Server registered successfully. Ready to sync catalog." });
      await loadData();
    } catch (err: any) {
      setRegisterError(err.message || "Failed to register server.");
    } finally {
      setRegistering(false);
    }
  };

  const handleSyncServer = async (serverId: string) => {
    try {
      setSyncingServerId(serverId);
      setActionMessage(null);
      const res: CatalogSyncResult = await api.syncMCPCatalog(serverId);
      if (res.drift_detected) {
        setActionMessage({
          type: "error",
          text: `Catalog drift detected! ${res.new_tools} new tools, ${res.updated_tools} modified. Server flagged as REQUIRES_REAPPROVAL.`,
        });
      } else {
        setActionMessage({
          type: "success",
          text: `Catalog sync completed. ${res.new_tools} new, ${res.updated_tools} updated tools verified.`,
        });
      }
      await loadData();
    } catch (err: any) {
      setActionMessage({ type: "error", text: err.message || "Failed to sync catalog." });
    } finally {
      setSyncingServerId(null);
    }
  };

  const handleApproveServer = async (serverId: string) => {
    try {
      setActionMessage(null);
      const res = await api.approveMCPCatalog(serverId);
      setActionMessage({
        type: "success",
        text: `Server catalog approved. ${res.approved_tools_count} tools now active and authorized.`,
      });
      await loadData();
    } catch (err: any) {
      setActionMessage({ type: "error", text: err.message || "Failed to approve server catalog." });
    }
  };

  const handleDisableServer = async (serverId: string) => {
    try {
      setActionMessage(null);
      await api.disableMCPServer(serverId);
      setActionMessage({ type: "success", text: "MCP server disabled." });
      await loadData();
    } catch (err: any) {
      setActionMessage({ type: "error", text: err.message || "Failed to disable server." });
    }
  };

  const handleDeleteServer = async (serverId: string) => {
    if (!confirm("Are you sure you want to remove this MCP server and its tool registry?")) return;
    try {
      setActionMessage(null);
      await api.deleteMCPServer(serverId);
      setActionMessage({ type: "success", text: "MCP server removed." });
      await loadData();
    } catch (err: any) {
      setActionMessage({ type: "error", text: err.message || "Failed to delete server." });
    }
  };

  const handleExecuteToolTest = async () => {
    if (!callModal.tool) return;
    setCallModal((prev) => ({ ...prev, loading: true, result: undefined, error: undefined }));

    try {
      let parsedParams = {};
      try {
        parsedParams = JSON.parse(callModal.paramsText);
      } catch {
        throw new Error("Invalid JSON parameters format.");
      }

      const res = await api.callMCPTool(callModal.tool.server_id, callModal.tool.name, {
        parameters: parsedParams,
        agent_id: callModal.agentId || undefined,
        capability_token: callModal.capabilityToken || undefined,
      });

      setCallModal((prev) => ({ ...prev, loading: false, result: res }));
      // Refresh audit logs
      const act = await api.getMCPActivity({ limit: 50 });
      setActivity(act || []);
    } catch (err: any) {
      setCallModal((prev) => ({ ...prev, loading: false, error: err.message || "Execution failed." }));
    }
  };

  // Filter tools
  const filteredTools = tools.filter((t) => {
    const matchSearch =
      t.name.toLowerCase().includes(toolSearch.toLowerCase()) ||
      (t.description && t.description.toLowerCase().includes(toolSearch.toLowerCase()));
    const matchRisk = toolRiskFilter === "ALL" || t.risk_level === toolRiskFilter;
    const matchServer = toolServerFilter === "ALL" || t.server_id === toolServerFilter;
    return matchSearch && matchRisk && matchServer;
  });

  const activeServersCount = servers.filter((s) => s.status === "ACTIVE").length;
  const driftServersCount = servers.filter((s) => s.status === "REQUIRES_REAPPROVAL" || s.status === "QUARANTINED").length;
  const highCriticalToolsCount = tools.filter((t) => t.risk_level === "HIGH" || t.risk_level === "CRITICAL").length;

  return (
    <div className="space-y-6">
      {/* Top Banner / Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-border/40">
        <div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center justify-center p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Network className="w-5 h-5" />
            </span>
            <h1 className="text-2xl font-bold tracking-tight text-bone font-space">MCP Security Gateway</h1>
            <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-surface-muted text-copper border border-copper/30">
              2026-07-28 SPEC
            </span>
          </div>
          <p className="text-sm text-slate mt-1">
            Zero-trust mediation layer for Model Context Protocol tools, upstream servers, and agent capabilities.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border/60 hover:bg-surface-muted text-sm text-slate hover:text-bone transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setRegisterModalOpen(true)}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-ink font-semibold text-sm shadow-sm transition-all"
          >
            <Plus className="w-4 h-4" />
            Connect MCP Server
          </button>
        </div>
      </div>

      {/* Global Action / Error Alert */}
      {actionMessage && (
        <div
          className={`p-3.5 rounded-lg text-sm flex items-start gap-2.5 border ${
            actionMessage.type === "success"
              ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
              : "bg-rose-500/10 border-rose-500/30 text-rose-300"
          }`}
        >
          {actionMessage.type === "success" ? (
            <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400 mt-0.5" />
          ) : (
            <AlertTriangle className="w-5 h-5 shrink-0 text-rose-400 mt-0.5" />
          )}
          <div className="flex-1">{actionMessage.text}</div>
          <button
            onClick={() => setActionMessage(null)}
            className="text-xs hover:underline opacity-80"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex items-center gap-1 p-1 bg-surface-muted/60 border border-border/40 rounded-xl w-fit">
        <button
          onClick={() => setActiveTab("overview")}
          className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg transition-colors ${
            activeTab === "overview"
              ? "bg-surface-elevated text-cyan-400 shadow-sm border border-cyan-500/20"
              : "text-slate hover:text-bone"
          }`}
        >
          <Shield className="w-4 h-4" />
          Overview
        </button>
        <button
          onClick={() => setActiveTab("servers")}
          className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg transition-colors ${
            activeTab === "servers"
              ? "bg-surface-elevated text-cyan-400 shadow-sm border border-cyan-500/20"
              : "text-slate hover:text-bone"
          }`}
        >
          <Server className="w-4 h-4" />
          Upstream Servers ({servers.length})
        </button>
        <button
          onClick={() => setActiveTab("tools")}
          className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg transition-colors ${
            activeTab === "tools"
              ? "bg-surface-elevated text-cyan-400 shadow-sm border border-cyan-500/20"
              : "text-slate hover:text-bone"
          }`}
        >
          <Wrench className="w-4 h-4" />
          Tool Catalog ({tools.length})
        </button>
        <button
          onClick={() => setActiveTab("activity")}
          className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg transition-colors ${
            activeTab === "activity"
              ? "bg-surface-elevated text-cyan-400 shadow-sm border border-cyan-500/20"
              : "text-slate hover:text-bone"
          }`}
        >
          <Clock className="w-4 h-4" />
          Audit & Security Activity ({activity.length})
        </button>
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {/* Key Metric Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-surface-elevated border border-border/50">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider text-slate font-medium">Connected Servers</span>
                <Server className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold text-bone font-mono">{activeServersCount}</span>
                <span className="text-xs text-slate font-normal">of {servers.length} total</span>
              </div>
              <div className="mt-2 text-xs text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Streamable HTTP & stdio
              </div>
            </div>

            <div className="p-4 rounded-xl bg-surface-elevated border border-border/50">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider text-slate font-medium">Registered Tools</span>
                <Wrench className="w-4 h-4 text-copper" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold text-bone font-mono">{tools.length}</span>
                <span className="text-xs text-slate font-normal">inspected schemas</span>
              </div>
              <div className="mt-2 text-xs text-slate flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                Zero unverified tools
              </div>
            </div>

            <div className="p-4 rounded-xl bg-surface-elevated border border-border/50">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider text-slate font-medium">High / Critical Tools</span>
                <ShieldAlert className="w-4 h-4 text-amber-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold text-amber-400 font-mono">{highCriticalToolsCount}</span>
                <span className="text-xs text-slate font-normal">require approval</span>
              </div>
              <div className="mt-2 text-xs text-amber-400/90 flex items-center gap-1">
                <Lock className="w-3.5 h-3.5" />
                Protected by broker
              </div>
            </div>

            <div className="p-4 rounded-xl bg-surface-elevated border border-border/50">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider text-slate font-medium">Catalog Drift / Quarantine</span>
                <AlertTriangle className="w-4 h-4 text-rose-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className={`text-2xl font-bold font-mono ${driftServersCount > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                  {driftServersCount}
                </span>
                <span className="text-xs text-slate font-normal">servers affected</span>
              </div>
              <div className="mt-2 text-xs text-slate flex items-center gap-1">
                {driftServersCount === 0 ? "Catalog signatures match" : "Requires reapproval"}
              </div>
            </div>
          </div>

          {/* Architecture & Protocol Enforcement Card */}
          <div className="p-6 rounded-xl bg-surface-elevated border border-border/50 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-semibold text-bone font-space">
                  MCP 2026-07-28 Security Architecture & Enforcements
                </h3>
              </div>
              <span className="text-xs px-2.5 py-1 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Active Policy: Strict
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="p-3.5 rounded-lg bg-surface-muted/50 border border-border/40 space-y-1.5">
                <div className="text-xs font-semibold text-bone flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-copper" />
                  Header-Based Streamable Routing
                </div>
                <p className="text-xs text-slate leading-relaxed">
                  Strict enforcement of <code className="text-cyan-300">mcp-version: 2026-07-28</code>,{" "}
                  <code className="text-cyan-300">mcp-method</code>, and <code className="text-cyan-300">mcp-name</code>.
                  Requests with header/body mismatch are rejected before execution.
                </p>
              </div>

              <div className="p-3.5 rounded-lg bg-surface-muted/50 border border-border/40 space-y-1.5">
                <div className="text-xs font-semibold text-bone flex items-center gap-1.5">
                  <Lock className="w-4 h-4 text-emerald-400" />
                  No-Token-Passthrough Invariant
                </div>
                <p className="text-xs text-slate leading-relaxed">
                  Inbound agent access tokens are strictly verified for PRIVGUARD audience and never leaked upstream.
                  Upstream servers authenticate using isolated server-side credentials.
                </p>
              </div>

              <div className="p-3.5 rounded-lg bg-surface-muted/50 border border-border/40 space-y-1.5">
                <div className="text-xs font-semibold text-bone flex items-center gap-1.5">
                  <Cpu className="w-4 h-4 text-amber-400" />
                  SSRF & Sandboxed stdio
                </div>
                <p className="text-xs text-slate leading-relaxed">
                  Localhost, private IPv4/IPv6, and cloud metadata (169.254.169.254) are blocked. Stdio processes run in
                  an isolated environment with zero shell metacharacter execution.
                </p>
              </div>
            </div>
          </div>

          {/* Quick Server Status List */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-bone uppercase tracking-wider font-space">
                Registered MCP Gateways
              </h3>
              <button
                onClick={() => setActiveTab("servers")}
                className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                View all servers &rarr;
              </button>
            </div>

            {servers.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-surface-elevated border border-dashed border-border/60">
                <Server className="w-8 h-8 text-slate mx-auto mb-2 opacity-50" />
                <p className="text-sm text-slate">No MCP servers registered yet.</p>
                <button
                  onClick={() => setRegisterModalOpen(true)}
                  className="mt-3 px-3 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 text-xs font-medium transition-colors"
                >
                  Connect your first MCP server
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {servers.slice(0, 4).map((server) => (
                  <div
                    key={server.id}
                    className="p-4 rounded-xl bg-surface-elevated border border-border/50 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="font-semibold text-bone flex items-center gap-2">
                            {server.name}
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-muted text-slate border border-border/50 uppercase">
                              {server.transport_type}
                            </span>
                          </div>
                          <p className="text-xs text-slate mt-0.5 line-clamp-1">
                            {server.description || "No description provided"}
                          </p>
                        </div>
                        <StatusPill status={server.status} />
                      </div>

                      <div className="mt-3 text-xs font-mono text-slate/80 truncate">
                        {server.transport_type === "streamable_http" ? (
                          <span className="text-cyan-300">{server.endpoint_url}</span>
                        ) : (
                          <span>
                            {server.command} {(server.args || []).join(" ")}
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-border/30 flex items-center justify-between text-xs">
                      <span className="text-slate">
                        Catalog:{" "}
                        <span className="font-mono text-bone">
                          {server.catalog_fingerprint ? `${server.catalog_fingerprint.slice(0, 12)}...` : "Unsynced"}
                        </span>
                      </span>
                      <button
                        onClick={() => handleSyncServer(server.id)}
                        disabled={syncingServerId === server.id}
                        className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
                      >
                        <RefreshCw className={`w-3 h-3 ${syncingServerId === server.id ? "animate-spin" : ""}`} />
                        Sync
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: SERVERS */}
      {activeTab === "servers" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-bone font-space">Upstream MCP Server Management</h2>
              <p className="text-xs text-slate">
                Register, sync, and govern connections to MCP servers via Streamable HTTP or sandboxed stdio.
              </p>
            </div>
            <button
              onClick={() => setRegisterModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-ink font-semibold text-xs transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              Add Server
            </button>
          </div>

          {servers.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-surface-elevated border border-dashed border-border/60">
              <Server className="w-8 h-8 text-slate mx-auto mb-2 opacity-50" />
              <p className="text-sm text-slate">No MCP servers registered.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {servers.map((server) => {
                const serverTools = tools.filter((t) => t.server_id === server.id);
                return (
                  <div
                    key={server.id}
                    className="p-5 rounded-xl bg-surface-elevated border border-border/50 space-y-3"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-base font-semibold text-bone">{server.name}</h3>
                          <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-surface-muted text-cyan-300 border border-cyan-500/20">
                            {server.transport_type}
                          </span>
                          <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-surface-muted text-slate border border-border/50">
                            Trust: {server.trust_level}
                          </span>
                        </div>
                        <p className="text-xs text-slate mt-1">{server.description || "No description provided."}</p>
                      </div>

                      <div className="flex items-center gap-2 self-start sm:self-center">
                        <StatusPill status={server.status} />
                        {server.status === "REQUIRES_REAPPROVAL" && (
                          <button
                            onClick={() => handleApproveServer(server.id)}
                            className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-xs font-medium border border-amber-500/30 transition-colors"
                          >
                            Approve Catalog Changes
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Details Bar */}
                    <div className="p-3 rounded-lg bg-surface-muted/40 border border-border/30 grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                      <div>
                        <span className="text-slate">Target: </span>
                        <span className="text-bone">
                          {server.transport_type === "streamable_http"
                            ? server.endpoint_url
                            : `${server.command} ${(server.args || []).join(" ")}`}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate">Fingerprint: </span>
                        <span className="text-cyan-300">
                          {server.catalog_fingerprint || "None (Run sync to compute)"}
                        </span>
                      </div>
                    </div>

                    {/* Action Bar */}
                    <div className="flex items-center justify-between pt-2 border-t border-border/30 text-xs">
                      <div className="text-slate">
                        Active Tools: <span className="font-semibold text-bone">{serverTools.length}</span>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleSyncServer(server.id)}
                          disabled={syncingServerId === server.id}
                          className="flex items-center gap-1 px-2.5 py-1 rounded border border-border/60 hover:bg-surface-muted text-slate hover:text-bone transition-colors"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${syncingServerId === server.id ? "animate-spin" : ""}`} />
                          Sync Catalog
                        </button>
                        <button
                          onClick={() => handleDisableServer(server.id)}
                          className="flex items-center gap-1 px-2.5 py-1 rounded border border-border/60 hover:bg-surface-muted text-slate hover:text-amber-400 transition-colors"
                        >
                          <Power className="w-3.5 h-3.5" />
                          Toggle Status
                        </button>
                        <button
                          onClick={() => handleDeleteServer(server.id)}
                          className="flex items-center gap-1 px-2.5 py-1 rounded border border-rose-500/30 hover:bg-rose-500/10 text-rose-400 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          Remove
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: TOOLS */}
      {activeTab === "tools" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold text-bone font-space">Protected MCP Tool Registry</h2>
              <p className="text-xs text-slate">
                All registered tools are scanned for prompt injection, sensitive instruction smuggling, and risk levels.
              </p>
            </div>

            {/* Filter controls */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate" />
                <input
                  type="text"
                  placeholder="Search tools..."
                  value={toolSearch}
                  onChange={(e) => setToolSearch(e.target.value)}
                  className="pl-8 pr-3 py-1.5 rounded-lg bg-surface-muted border border-border/60 text-bone placeholder-slate/50 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>

              <select
                value={toolRiskFilter}
                onChange={(e) => setToolRiskFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-surface-muted border border-border/60 text-bone text-xs focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Risk Levels</option>
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>

              <select
                value={toolServerFilter}
                onChange={(e) => setToolServerFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-surface-muted border border-border/60 text-bone text-xs focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Servers</option>
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {filteredTools.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-surface-elevated border border-dashed border-border/60">
              <Wrench className="w-8 h-8 text-slate mx-auto mb-2 opacity-50" />
              <p className="text-sm text-slate">No tools match your criteria.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredTools.map((tool) => {
                const srv = servers.find((s) => s.id === tool.server_id);
                return (
                  <div
                    key={tool.id}
                    className="p-4 rounded-xl bg-surface-elevated border border-border/50 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="font-semibold text-bone font-mono text-sm">{tool.name}</div>
                          <span className="text-[10px] text-slate font-medium">Server: {srv?.name || tool.server_id}</span>
                        </div>
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                            tool.risk_level === "CRITICAL"
                              ? "bg-rose-500/20 text-rose-300 border-rose-500/30"
                              : tool.risk_level === "HIGH"
                              ? "bg-amber-500/20 text-amber-300 border-amber-500/30"
                              : tool.risk_level === "MEDIUM"
                              ? "bg-yellow-500/20 text-yellow-300 border-yellow-500/30"
                              : "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                          }`}
                        >
                          {tool.risk_level}
                        </span>
                      </div>

                      <p className="text-xs text-slate mt-2 line-clamp-2 leading-relaxed">
                        {tool.description || "No tool description available."}
                      </p>

                      <div className="mt-3 flex flex-wrap gap-2 text-[10px] font-mono text-slate">
                        <span className="px-1.5 py-0.5 rounded bg-surface-muted border border-border/40">
                          v{tool.version}
                        </span>
                        {tool.requires_approval && (
                          <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 flex items-center gap-1">
                            <Lock className="w-2.5 h-2.5" />
                            Approval Required
                          </span>
                        )}
                        <span
                          className={`px-1.5 py-0.5 rounded border ${
                            tool.is_approved
                              ? "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"
                              : "bg-rose-500/10 text-rose-300 border-rose-500/30"
                          }`}
                        >
                          {tool.is_approved ? "Approved" : "Requires Approval"}
                        </span>
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-border/30 flex items-center justify-between text-xs">
                      <button
                        onClick={() => setSchemaModal({ open: true, tool })}
                        className="text-slate hover:text-bone flex items-center gap-1 transition-colors"
                      >
                        <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                        Schema
                      </button>

                      <button
                        onClick={() =>
                          setCallModal({
                            open: true,
                            tool,
                            paramsText: "{}",
                            agentId: "agent-preview",
                            capabilityToken: "",
                            loading: false,
                          })
                        }
                        className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 font-medium flex items-center gap-1 border border-cyan-500/20 transition-colors"
                      >
                        <Play className="w-3 h-3" />
                        Test Call
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: ACTIVITY & SECURITY */}
      {activeTab === "activity" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-bone font-space">MCP Security & Audit Trail</h2>
              <p className="text-xs text-slate">
                Content-free audit logging preserving metadata hashes without persisting sensitive parameters.
              </p>
            </div>
            <button
              onClick={loadData}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-border/60 hover:bg-surface-muted text-xs text-slate hover:text-bone transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>

          {activity.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-surface-elevated border border-dashed border-border/60">
              <Clock className="w-8 h-8 text-slate mx-auto mb-2 opacity-50" />
              <p className="text-sm text-slate">No MCP activity events logged yet.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {activity.map((evt) => (
                <div
                  key={evt.id}
                  className="p-3.5 rounded-xl bg-surface-elevated border border-border/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-bone">{evt.action}</span>
                      {evt.tool_name && (
                        <span className="font-mono text-cyan-300 bg-surface-muted px-1.5 py-0.5 rounded border border-border/40">
                          {evt.tool_name}
                        </span>
                      )}
                      <StatusPill status={evt.status} />
                    </div>
                    <div className="text-slate font-mono text-[11px] truncate max-w-xl">
                      {JSON.stringify(evt.details)}
                    </div>
                  </div>

                  <div className="text-slate font-mono text-[11px] shrink-0 text-right">
                    {new Date(evt.timestamp).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* MODAL 1: Connect MCP Server */}
      {registerModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/80 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl bg-surface-elevated border border-border/60 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-cyan-400" />
                <h3 className="text-lg font-bold text-bone font-space">Connect Upstream MCP Server</h3>
              </div>
              <button
                onClick={() => setRegisterModalOpen(false)}
                className="text-slate hover:text-bone text-sm"
              >
                ✕
              </button>
            </div>

            {registerError && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                {registerError}
              </div>
            )}

            <form onSubmit={handleRegisterServer} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-slate font-medium mb-1">Server Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. GitHub MCP Server, Filesystem Tools"
                  value={newServerName}
                  onChange={(e) => setNewServerName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-surface-muted border border-border/60 text-bone placeholder-slate/50 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate font-medium mb-1">Description</label>
                <input
                  type="text"
                  placeholder="e.g. Provides code search and repository tools"
                  value={newServerDesc}
                  onChange={(e) => setNewServerDesc(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-surface-muted border border-border/60 text-bone placeholder-slate/50 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate font-medium mb-1">Transport Type *</label>
                <select
                  value={newTransportType}
                  onChange={(e) => setNewTransportType(e.target.value as any)}
                  className="w-full px-3 py-2 rounded-lg bg-surface-muted border border-border/60 text-bone focus:outline-none focus:border-cyan-500"
                >
                  <option value="streamable_http">Streamable HTTP (2026-07-28 Spec - Recommended)</option>
                  <option value="stdio">stdio (Local Subprocess Sandbox)</option>
                </select>
              </div>

              {newTransportType === "streamable_http" ? (
                <div>
                  <label className="block text-slate font-medium mb-1">
                    Endpoint URL * (SSRF Protection Enforced)
                  </label>
                  <input
                    type="url"
                    required
                    placeholder="https://mcp.external-service.com/mcp"
                    value={newEndpointUrl}
                    onChange={(e) => setNewEndpointUrl(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-surface-muted border border-border/60 text-bone placeholder-slate/50 font-mono focus:outline-none focus:border-cyan-500"
                  />
                  <span className="text-[11px] text-slate mt-1 block">
                    Localhost (127.0.0.1) and private IPs are blocked by default.
                  </span>
                </div>
              ) : (
                <div className="space-y-3">
                  <div>
                    <label className="block text-slate font-medium mb-1">
                      Allowed Executable * (node, npx, python, python3, uvx)
                    </label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. npx"
                      value={newCommand}
                      onChange={(e) => setNewCommand(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-surface-muted border border-border/60 text-bone placeholder-slate/50 font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                  <div>
                    <label className="block text-slate font-medium mb-1">Arguments (space separated)</label>
                    <input
                      type="text"
                      placeholder="-y @modelcontextprotocol/server-filesystem /tmp"
                      value={newArgs}
                      onChange={(e) => setNewArgs(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-surface-muted border border-border/60 text-bone placeholder-slate/50 font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate font-medium mb-1">Auth Type</label>
                  <select
                    value={newAuthType}
                    onChange={(e) => setNewAuthType(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-surface-muted border border-border/60 text-bone focus:outline-none focus:border-cyan-500"
                  >
                    <option value="NONE">None</option>
                    <option value="BEARER_TOKEN">Bearer Token</option>
                    <option value="API_KEY">API Key</option>
                    <option value="OAUTH2">OAuth2</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate font-medium mb-1">Credential Secret Reference</label>
                  <input
                    type="text"
                    placeholder="e.g. env:GITHUB_MCP_TOKEN"
                    value={newAuthCredRef}
                    onChange={(e) => setNewAuthCredRef(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-surface-muted border border-border/60 text-bone placeholder-slate/50 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-border/40">
                <button
                  type="button"
                  onClick={() => setRegisterModalOpen(false)}
                  className="px-3.5 py-1.5 rounded-lg border border-border/60 text-slate hover:text-bone transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={registering}
                  className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-ink font-semibold transition-colors"
                >
                  {registering ? "Validating Destination..." : "Register Server"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: Tool Schema View */}
      {schemaModal.open && schemaModal.tool && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/80 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl bg-surface-elevated border border-border/60 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-bone font-mono">{schemaModal.tool.name}</h3>
                <span className="text-xs text-slate">Definition Hash: {schemaModal.tool.definition_hash.slice(0, 16)}...</span>
              </div>
              <button
                onClick={() => setSchemaModal({ open: false })}
                className="text-slate hover:text-bone text-sm"
              >
                ✕
              </button>
            </div>

            <div>
              <label className="block text-xs text-slate font-medium mb-1.5">JSON Input Schema</label>
              <pre className="p-3 rounded-lg bg-surface-muted border border-border/60 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-72">
                {JSON.stringify(schemaModal.tool.input_schema, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2 border-t border-border/40">
              <button
                onClick={() => setSchemaModal({ open: false })}
                className="px-3.5 py-1.5 rounded-lg bg-surface-muted hover:bg-border/60 text-xs text-bone transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 3: Tool Execution Test */}
      {callModal.open && callModal.tool && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/80 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-2xl bg-surface-elevated border border-border/60 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-bone font-mono flex items-center gap-2">
                  <Play className="w-4 h-4 text-cyan-400" />
                  Execute Protected Tool: {callModal.tool.name}
                </h3>
                <span className="text-xs text-slate">Mediated through PRIVGUARD Agent Security Broker</span>
              </div>
              <button
                onClick={() => setCallModal((prev) => ({ ...prev, open: false }))}
                className="text-slate hover:text-bone text-sm"
              >
                ✕
              </button>
            </div>

            {callModal.error && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
                {callModal.error}
              </div>
            )}

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate font-medium mb-1">Agent ID</label>
                  <input
                    type="text"
                    value={callModal.agentId}
                    onChange={(e) => setCallModal((prev) => ({ ...prev, agentId: e.target.value }))}
                    className="w-full px-3 py-1.5 rounded-lg bg-surface-muted border border-border/60 text-bone text-xs font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-slate font-medium mb-1">Capability Token (Optional)</label>
                  <input
                    type="text"
                    placeholder="token-..."
                    value={callModal.capabilityToken}
                    onChange={(e) => setCallModal((prev) => ({ ...prev, capabilityToken: e.target.value }))}
                    className="w-full px-3 py-1.5 rounded-lg bg-surface-muted border border-border/60 text-bone text-xs font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate font-medium mb-1">Parameters (JSON)</label>
                <textarea
                  rows={4}
                  value={callModal.paramsText}
                  onChange={(e) => setCallModal((prev) => ({ ...prev, paramsText: e.target.value }))}
                  className="w-full p-2.5 rounded-lg bg-surface-muted border border-border/60 text-bone text-xs font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              {callModal.result && (
                <div>
                  <label className="block text-emerald-400 font-medium mb-1">Execution Response</label>
                  <pre className="p-3 rounded-lg bg-surface-muted border border-emerald-500/30 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-48">
                    {JSON.stringify(callModal.result, null, 2)}
                  </pre>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-border/40">
                <button
                  type="button"
                  onClick={() => setCallModal((prev) => ({ ...prev, open: false }))}
                  className="px-3.5 py-1.5 rounded-lg border border-border/60 text-slate hover:text-bone transition-colors"
                >
                  Close
                </button>
                <button
                  type="button"
                  disabled={callModal.loading}
                  onClick={handleExecuteToolTest}
                  className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-ink font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <Play className={`w-3.5 h-3.5 ${callModal.loading ? "animate-spin" : ""}`} />
                  {callModal.loading ? "Mediating..." : "Execute Call"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
