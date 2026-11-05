"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Briefcase,
  Plus,
  ArrowLeft,
  RefreshCw,
  FolderGit2,
  Lock,
  Bot,
  Users,
} from "lucide-react";
import { api } from "@/lib/api";

export default function WorkspacesManagement() {
  const [workspaces, setWorkspaces] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [orgId, setOrgId] = useState("default_tenant");

  const fetchWorkspaces = async () => {
    setLoading(true);
    try {
      const orgs = await api.getOrganizations();
      const currentOrgId = orgs && orgs.length > 0 ? orgs[0].id : "default_tenant";
      setOrgId(currentOrgId);
      const data = await api.getWorkspaces(currentOrgId);
      setWorkspaces(data);
    } catch {
      // Mock fallback
      setWorkspaces([
        {
          id: "ws_eng",
          name: "Engineering & Core Systems",
          slug: "engineering",
          description: "Autonomous code generation and GitHub MCP integrations.",
          is_default: true,
          created_at: new Date().toISOString(),
        },
        {
          id: "ws_sec",
          name: "Security Operations (SecOps)",
          slug: "secops",
          description: "Vulnerability analysis, threat containment, and red-teaming agents.",
          is_default: false,
          created_at: new Date().toISOString(),
        },
        {
          id: "ws_res",
          name: "AI Research & RAG Labs",
          slug: "research",
          description: "High-dimensional memory retrieval and external knowledge search.",
          is_default: false,
          created_at: new Date().toISOString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchWorkspaces();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name) return;
    setSubmitting(true);
    try {
      await api.createWorkspace(orgId, { name, description });
      setShowCreateModal(false);
      setName("");
      setDescription("");
      fetchWorkspaces();
    } catch (err: any) {
      alert("Failed to create workspace: " + (err.message || "Unknown error"));
    } finally {
      setSubmitting(false);
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
              Departmental Workspaces
            </h1>
            <p className="text-xs text-slate mt-0.5">
              Strict compartmental isolation between departments, AI agents, and external integrations.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white shadow-sm transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            New Workspace
          </button>
          <button
            onClick={fetchWorkspaces}
            disabled={loading}
            className="p-2 rounded-lg border border-border bg-card hover:bg-card/70 text-slate hover:text-bone transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Cross-workspace notice */}
      <div className="p-4 rounded-xl border border-border/80 bg-card/40 flex items-start gap-3 text-xs text-slate leading-relaxed">
        <Lock className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
        <div>
          <span className="font-semibold text-bone">Workspace Boundary Enforcement:</span> Agents and memory vaults registered in one workspace cannot automatically access resources in another. All cross-workspace requests are blocked at the broker unless explicitly authorized.
        </div>
      </div>

      {/* Workspaces Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {workspaces.map((ws) => (
          <div
            key={ws.id}
            className="p-5 rounded-xl border border-border bg-card/50 hover:bg-card/80 transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="w-9 h-9 rounded-lg bg-emerald-950/50 border border-emerald-800/50 flex items-center justify-center text-emerald-400">
                  <FolderGit2 className="w-5 h-5" />
                </div>
                {ws.is_default && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
                    Default
                  </span>
                )}
              </div>

              <h3 className="text-sm font-bold text-bone">{ws.name}</h3>
              <div className="text-[11px] font-mono text-cyan-400/90 mt-0.5">
                slug: {ws.slug}
              </div>
              <p className="text-xs text-slate mt-2 leading-relaxed">
                {ws.description || "No description provided."}
              </p>
            </div>

            <div className="pt-4 mt-4 border-t border-border/50 flex items-center justify-between text-[11px] text-slate font-mono">
              <span>ID: {ws.id}</span>
              <span className="text-emerald-400">Isolated</span>
            </div>
          </div>
        ))}
      </div>

      {/* Create Workspace Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="rounded-xl border border-border bg-card w-full max-w-md p-6 space-y-4 shadow-xl">
            <h2 className="text-base font-bold text-bone">Create Departmental Workspace</h2>
            <p className="text-xs text-slate">
              Establish a new tenant compartment for isolated agents and tools.
            </p>

            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-[11px] font-mono text-slate mb-1">Workspace Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Financial Modeling Lab"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-background border border-border text-xs text-bone focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate mb-1">Description</label>
                <textarea
                  rows={3}
                  placeholder="Department purpose and security classification..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-background border border-border text-xs text-bone focus:outline-none focus:border-emerald-500 font-mono"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-border bg-card hover:bg-card/80 text-xs text-slate hover:text-bone"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white disabled:opacity-50"
                >
                  {submitting ? "Creating..." : "Create Workspace"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

