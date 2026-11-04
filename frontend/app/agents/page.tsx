"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Bot, ChevronRight, Plus, ShieldCheck, Wrench, X } from "lucide-react";
import { api } from "@/lib/api";
import { Agent } from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";
import { formatDate } from "@/lib/utils";

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isRegisterOpen, setIsRegisterOpen] = useState(false);
  const [newAgentName, setNewAgentName] = useState("");
  const [newAgentDesc, setNewAgentDesc] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const loadAgents = async () => {
    try {
      setError(null);
      const data = await api.getAgents();
      setAgents(data);
    } catch (err: any) {
      setError(err.message || "Failed to load agents.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAgents();
  }, []);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAgentName.trim()) return;
    setSubmitting(true);
    try {
      const res = await fetch("/api/backend/agents/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: newAgentName.trim(),
          description: newAgentDesc.trim() || undefined,
          allowed_tools: ["read_file", "search_web"],
        }),
      });
      if (!res.ok) throw new Error("Registration failed");
      setIsRegisterOpen(false);
      setNewAgentName("");
      setNewAgentDesc("");
      await loadAgents();
    } catch (err: any) {
      setError(err.message || "Failed to register agent.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-card border border-border rounded-xl p-5 shadow-sm">
        <div>
          <h2 className="font-display font-bold text-bone text-base tracking-wide flex items-center gap-2">
            <Bot className="w-5 h-5 text-cyan-400" />
            AI Agent Management Center
          </h2>
          <p className="text-xs text-slate mt-1">
            Registered autonomous agents operate under verifiable identities and least-privilege capability broker boundaries.
          </p>
        </div>
        <button
          onClick={() => setIsRegisterOpen(true)}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-bone text-xs font-semibold shadow-md transition-colors self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" />
          <span>Register New Agent</span>
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-xs">
          {error}
        </div>
      )}

      {/* Agents Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {loading ? (
          <div className="col-span-full text-center py-12 text-slate text-xs font-mono">
            Loading registered agents...
          </div>
        ) : agents.length === 0 ? (
          <div className="col-span-full text-center py-16 bg-card border border-border rounded-xl">
            <Bot className="w-10 h-10 text-slate mx-auto mb-3 opacity-60" />
            <h3 className="font-display font-medium text-bone text-sm">No Agents Registered</h3>
            <p className="text-xs text-slate mt-1">Click Register New Agent to initialize an agent identity.</p>
          </div>
        ) : (
          agents.map((agent) => (
            <div
              key={agent.id}
              className="bg-card border border-border hover:border-cyan-500/40 rounded-xl p-5 flex flex-col justify-between transition-all shadow-sm space-y-4 group"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
                    <h3 className="font-display font-semibold text-bone text-sm group-hover:text-cyan-300 transition-colors">
                      {agent.name}
                    </h3>
                  </div>
                  <StatusPill status={agent.status} />
                </div>
                <p className="text-xs text-slate/80 line-clamp-2">
                  {agent.description || "Autonomous AI agent registered under PRIVGUARD broker boundaries."}
                </p>
              </div>

              {/* Permissions & Tool Count */}
              <div className="space-y-2 pt-3 border-t border-border/60 text-xs">
                <div className="flex items-center justify-between text-slate font-mono text-[11px]">
                  <span>Agent ID:</span>
                  <span className="text-bone">{agent.id}</span>
                </div>
                <div className="flex items-center justify-between text-slate font-mono text-[11px]">
                  <span>Permitted Tools:</span>
                  <span className="text-cyan-400">{agent.allowed_tools?.length || 0} tools allowlisted</span>
                </div>
                <div className="flex items-center justify-between text-slate font-mono text-[11px]">
                  <span>Registered:</span>
                  <span>{formatDate(agent.created_at)}</span>
                </div>
              </div>

              {/* Action Button */}
              <Link
                href={`/agents/${agent.id}`}
                className="w-full flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-surface hover:bg-surface/80 border border-border text-xs text-bone font-medium transition-colors"
              >
                <span>View Access Map & Capabilities</span>
                <ChevronRight className="w-3.5 h-3.5 text-cyan-400" />
              </Link>
            </div>
          ))
        )}
      </div>

      {/* Register Modal */}
      {isRegisterOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
          <div className="bg-surface border border-border rounded-xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h3 className="font-display font-bold text-bone text-base">Register AI Agent</h3>
              <button
                onClick={() => setIsRegisterOpen(false)}
                className="text-slate hover:text-bone p-1 rounded-lg hover:bg-card/80"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleRegister} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate font-medium mb-1">Agent Name *</label>
                <input
                  type="text"
                  required
                  value={newAgentName}
                  onChange={(e) => setNewAgentName(e.target.value)}
                  placeholder="e.g. ResearchAssistant"
                  className="w-full bg-card border border-border rounded-lg p-2.5 text-bone focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate font-medium mb-1">Description</label>
                <textarea
                  rows={2}
                  value={newAgentDesc}
                  onChange={(e) => setNewAgentDesc(e.target.value)}
                  placeholder="Optional operational purpose"
                  className="w-full bg-card border border-border rounded-lg p-2.5 text-bone focus:outline-none focus:border-cyan-500 resize-none"
                />
              </div>

              <div className="p-3 bg-card border border-border rounded-lg text-[11px] text-slate/80 font-mono">
                Initial Default Tools: <span className="text-cyan-400">read_file, search_web</span> (Can be customized in Agent Access Map).
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsRegisterOpen(false)}
                  className="px-3 py-1.5 rounded-lg border border-border text-slate hover:text-bone"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting || !newAgentName.trim()}
                  className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-bone font-semibold"
                >
                  {submitting ? "Registering..." : "Register Identity"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
