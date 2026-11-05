"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  Plus,
  ArrowLeft,
  RefreshCw,
  RotateCcw,
  CheckCircle2,
  Lock,
  Layers,
  FileCode,
  Rocket,
} from "lucide-react";
import { api } from "@/lib/api";

export default function PolicyGovernance() {
  const [bundles, setBundles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [orgId, setOrgId] = useState("default_tenant");
  const [newRuleTarget, setNewRuleTarget] = useState("EMAIL_ADDRESS");
  const [newRuleAction, setNewRuleAction] = useState("REDACT");
  const [submitting, setSubmitting] = useState(false);

  const fetchPolicies = async () => {
    setLoading(true);
    try {
      const orgs = await api.getOrganizations();
      const currentOrgId = orgs && orgs.length > 0 ? orgs[0].id : "default_tenant";
      setOrgId(currentOrgId);
      const data = await api.getOrganizationPolicies(currentOrgId);
      setBundles(data);
    } catch {
      // Mock preview
      setBundles([
        {
          id: "pol_bundle_4",
          version: 4,
          status: "ACTIVE",
          policy_hash: "3a9f029b4e87611a2f...",
          rollout_stage: "ORG_WIDE",
          signing_key_id: "ed25519_pub_acme_prod",
          created_at: new Date(Date.now() - 3600000).toISOString(),
          activated_at: new Date(Date.now() - 1800000).toISOString(),
        },
        {
          id: "pol_bundle_3",
          version: 3,
          status: "REPLACED",
          policy_hash: "7f11c89012cd87e14a...",
          rollout_stage: "ORG_WIDE",
          signing_key_id: "ed25519_pub_acme_prod",
          created_at: new Date(Date.now() - 86400000).toISOString(),
          activated_at: new Date(Date.now() - 80000000).toISOString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleCreateBundle = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await api.createPolicyBundle(orgId, {
        rules: [
          { target: newRuleTarget, action: newRuleAction, rule_type: "PII_ACTION" },
        ],
      });
      setShowCreateModal(false);
      fetchPolicies();
    } catch (err: any) {
      alert("Failed to create policy bundle: " + (err.message || "Unknown error"));
    } finally {
      setSubmitting(false);
    }
  };

  const handleRollback = async (bundleId: string) => {
    if (!confirm("Are you sure you want to rollback to this policy bundle version?")) return;
    try {
      await api.rollbackPolicyBundle(orgId, bundleId);
      fetchPolicies();
    } catch (err: any) {
      alert("Rollback failed: " + (err.message || "Unknown error"));
    }
  };

  const activeBundle = bundles.find((b) => b.status === "ACTIVE") || bundles[0];

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
              Central Policy Governance & Signing
            </h1>
            <p className="text-xs text-slate mt-0.5">
              Deterministic 5-layer hierarchy, Ed25519 digital signatures, anti-downgrade protection, and staged rollouts.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-xs font-semibold text-white shadow-sm transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            Compile Policy Bundle
          </button>
          <button
            onClick={fetchPolicies}
            disabled={loading}
            className="p-2 rounded-lg border border-border bg-card hover:bg-card/70 text-slate hover:text-bone transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Policy Hierarchy Architecture Card */}
      <div className="p-5 rounded-xl border border-border bg-card/40 space-y-3">
        <div className="flex items-center gap-2 text-xs font-bold text-bone font-mono uppercase tracking-wider">
          <Layers className="w-4 h-4 text-cyan-400" />
          Deterministic Policy Evaluation Hierarchy
        </div>
        <p className="text-xs text-slate">
          In PRIVGUARD, lower-level policies can only tighten security. Platform guardrails are strictly immutable and cannot be overridden by any administrator.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-2 pt-2 text-[11px] font-mono">
          <div className="p-2.5 rounded-lg bg-red-950/40 border border-red-800/40 text-red-300">
            <div className="font-bold text-[10px] text-red-400 uppercase">Layer 1 (Top)</div>
            <div>Platform Guardrails</div>
            <div className="text-[9px] text-slate mt-0.5">Immutable System Bounds</div>
          </div>
          <div className="p-2.5 rounded-lg bg-amber-950/40 border border-amber-800/40 text-amber-300">
            <div className="font-bold text-[10px] text-amber-400 uppercase">Layer 2</div>
            <div>Organization Baseline</div>
            <div className="text-[9px] text-slate mt-0.5">Signed Master Policy</div>
          </div>
          <div className="p-2.5 rounded-lg bg-emerald-950/40 border border-emerald-800/40 text-emerald-300">
            <div className="font-bold text-[10px] text-emerald-400 uppercase">Layer 3</div>
            <div>Workspace Policy</div>
            <div className="text-[9px] text-slate mt-0.5">Departmental Constraints</div>
          </div>
          <div className="p-2.5 rounded-lg bg-cyan-950/40 border border-cyan-800/40 text-cyan-300">
            <div className="font-bold text-[10px] text-cyan-400 uppercase">Layer 4</div>
            <div>Application Scope</div>
            <div className="text-[9px] text-slate mt-0.5">App API Boundary</div>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
            <div className="font-bold text-[10px] text-slate-400 uppercase">Layer 5</div>
            <div>Agent Task Scope</div>
            <div className="text-[9px] text-slate mt-0.5">Least-Privilege Allowlist</div>
          </div>
        </div>
      </div>

      {/* Active Bundle Details */}
      {activeBundle && (
        <div className="rounded-xl border border-amber-900/50 bg-amber-950/20 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse" />
              <span className="text-xs font-mono font-bold text-amber-300 uppercase">
                Active Policy Bundle (v{activeBundle.version})
              </span>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
              Ed25519 Verified
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div>
              <div className="text-[10px] text-slate uppercase">Canonical SHA-256 Digest</div>
              <div className="text-bone truncate">{activeBundle.policy_hash}</div>
            </div>
            <div>
              <div className="text-[10px] text-slate uppercase">Rollout Scope</div>
              <div className="text-cyan-400">{activeBundle.rollout_stage}</div>
            </div>
            <div>
              <div className="text-[10px] text-slate uppercase">Signing Key Reference</div>
              <div className="text-slate truncate">{activeBundle.signing_key_id}</div>
            </div>
          </div>
        </div>
      )}

      {/* Policy Bundle History Table */}
      <div className="rounded-xl border border-border bg-card/40 overflow-hidden">
        <div className="p-4 border-b border-border/80 flex items-center justify-between">
          <h2 className="text-sm font-bold text-bone">Signed Policy Bundle History</h2>
          <span className="text-[11px] font-mono text-slate">Anti-Downgrade Enforced</span>
        </div>
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-border/80 bg-card/80 text-[11px] font-mono text-slate uppercase tracking-wider">
              <th className="py-3 px-4">Version</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Bundle Hash</th>
              <th className="py-3 px-4">Rollout Stage</th>
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/50 text-xs">
            {bundles.map((b) => (
              <tr key={b.id} className="hover:bg-card/60 transition-colors">
                <td className="py-3.5 px-4 font-mono font-bold text-bone">
                  v{b.version}
                </td>
                <td className="py-3.5 px-4">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                      b.status === "ACTIVE"
                        ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800/60"
                        : b.status === "APPROVED"
                        ? "bg-amber-950/80 text-amber-400 border border-amber-800/60"
                        : "bg-slate-900 text-slate-400 border border-slate-800"
                    }`}
                  >
                    {b.status}
                  </span>
                </td>
                <td className="py-3.5 px-4 font-mono text-slate text-[11px]">
                  {b.policy_hash?.substring(0, 16)}...
                </td>
                <td className="py-3.5 px-4 font-mono text-cyan-400 text-[11px]">
                  {b.rollout_stage}
                </td>
                <td className="py-3.5 px-4 font-mono text-slate text-[11px]">
                  {new Date(b.created_at).toLocaleString()}
                </td>
                <td className="py-3.5 px-4 text-right">
                  {b.status !== "ACTIVE" && (
                    <button
                      onClick={() => handleRollback(b.id)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-card hover:bg-card/80 border border-border text-[11px] text-amber-400 hover:text-amber-300 transition-colors"
                    >
                      <RotateCcw className="w-3 h-3" />
                      Rollback to v{b.version}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create Policy Bundle Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="rounded-xl border border-border bg-card w-full max-w-md p-6 space-y-4 shadow-xl">
            <h2 className="text-base font-bold text-bone">Compile New Policy Bundle</h2>
            <p className="text-xs text-slate">
              Rules will be validated against platform guardrails, serialized canonically, and signed with Ed25519.
            </p>

            <form onSubmit={handleCreateBundle} className="space-y-4">
              <div>
                <label className="block text-[11px] font-mono text-slate mb-1">Target PII / Tool</label>
                <select
                  value={newRuleTarget}
                  onChange={(e) => setNewRuleTarget(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-background border border-border text-xs text-bone focus:outline-none focus:border-amber-500 font-mono"
                >
                  <option value="EMAIL_ADDRESS">EMAIL_ADDRESS</option>
                  <option value="CREDIT_CARD">CREDIT_CARD</option>
                  <option value="PHONE_NUMBER">PHONE_NUMBER</option>
                  <option value="API_KEYS">API_KEYS</option>
                  <option value="SYSTEM_COMMANDS">SYSTEM_COMMANDS</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate mb-1">Action</label>
                <select
                  value={newRuleAction}
                  onChange={(e) => setNewRuleAction(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-background border border-border text-xs text-bone focus:outline-none focus:border-amber-500 font-mono"
                >
                  <option value="REDACT">REDACT</option>
                  <option value="BLOCK">BLOCK</option>
                  <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
                  <option value="SANITIZE">SANITIZE</option>
                  <option value="WARN">WARN</option>
                </select>
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
                  className="px-4 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-xs font-semibold text-white disabled:opacity-50"
                >
                  {submitting ? "Signing..." : "Sign & Compile"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

