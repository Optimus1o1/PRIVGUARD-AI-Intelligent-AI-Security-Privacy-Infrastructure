"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Users,
  UserPlus,
  Shield,
  ArrowLeft,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Key,
  Trash2,
} from "lucide-react";
import { api } from "@/lib/api";

const ROLES = [
  "ORGANIZATION_OWNER",
  "SECURITY_ADMIN",
  "POLICY_ADMIN",
  "FLEET_ADMIN",
  "DEVELOPER",
  "AGENT_OPERATOR",
  "AUDITOR",
  "VIEWER",
];

export default function MembersAndRBAC() {
  const [members, setMembers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("DEVELOPER");
  const [submitting, setSubmitting] = useState(false);
  const [orgId, setOrgId] = useState("default_tenant");

  const fetchMembers = async () => {
    setLoading(true);
    try {
      const orgs = await api.getOrganizations();
      const currentOrgId = orgs && orgs.length > 0 ? orgs[0].id : "default_tenant";
      setOrgId(currentOrgId);
      const data = await api.getOrganizationMembers(currentOrgId);
      setMembers(data);
    } catch {
      // Mock preview
      setMembers([
        {
          id: "mem_1",
          user_id: "usr_alice",
          email: "alice@acmecosystems.com",
          role: "ORGANIZATION_OWNER",
          status: "ACTIVE",
          mfa_enabled: true,
          created_at: new Date().toISOString(),
        },
        {
          id: "mem_2",
          user_id: "usr_bob",
          email: "bob@acmecosystems.com",
          role: "SECURITY_ADMIN",
          status: "ACTIVE",
          mfa_enabled: true,
          created_at: new Date().toISOString(),
        },
        {
          id: "mem_3",
          user_id: "usr_carol",
          email: "carol@acmecosystems.com",
          role: "POLICY_ADMIN",
          status: "ACTIVE",
          mfa_enabled: false,
          created_at: new Date().toISOString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMembers();
  }, []);

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail) return;
    setSubmitting(true);
    try {
      await api.inviteMember(orgId, { email: inviteEmail, role: inviteRole });
      setShowInviteModal(false);
      setInviteEmail("");
      fetchMembers();
    } catch (err: any) {
      alert("Failed to send invitation: " + (err.message || "Unknown error"));
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
              Enterprise Members & RBAC
            </h1>
            <p className="text-xs text-slate mt-0.5">
              8 built-in roles, separation of duties, and SCIM 2.0 automated deprovisioning.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowInviteModal(true)}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white shadow-sm transition-colors"
          >
            <UserPlus className="w-3.5 h-3.5" />
            Invite Member
          </button>
          <button
            onClick={fetchMembers}
            disabled={loading}
            className="p-2 rounded-lg border border-border bg-card hover:bg-card/70 text-slate hover:text-bone transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Members Table */}
      <div className="rounded-xl border border-border bg-card/40 overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-border/80 bg-card/80 text-[11px] font-mono text-slate uppercase tracking-wider">
              <th className="py-3 px-4">Member Email</th>
              <th className="py-3 px-4">User ID</th>
              <th className="py-3 px-4">Enterprise Role</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">MFA</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/50 text-xs">
            {members.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate">
                  No members found in this organization.
                </td>
              </tr>
            ) : (
              members.map((m) => (
                <tr key={m.id || m.user_id} className="hover:bg-card/60 transition-colors">
                  <td className="py-3.5 px-4 font-medium text-bone flex items-center gap-2">
                    <div className="w-7 h-7 rounded-full bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400 text-xs">
                      {m.email[0].toUpperCase()}
                    </div>
                    <span>{m.email}</span>
                  </td>
                  <td className="py-3.5 px-4 font-mono text-slate text-[11px]">
                    {m.user_id}
                  </td>
                  <td className="py-3.5 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950/70 text-cyan-300 border border-cyan-800/50">
                      {m.role}
                    </span>
                  </td>
                  <td className="py-3.5 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                        m.status === "ACTIVE"
                          ? "bg-emerald-950/80 text-emerald-400 border border-emerald-800/60"
                          : "bg-red-950/80 text-red-400 border border-red-800/60"
                      }`}
                    >
                      {m.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 font-mono text-slate text-[11px]">
                    {m.mfa_enabled ? (
                      <span className="text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> Enforced
                      </span>
                    ) : (
                      <span className="text-amber-400/80">Optional</span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={() => alert(`Managing role for ${m.email}`)}
                      className="px-2 py-1 rounded bg-card hover:bg-card/80 border border-border text-[11px] text-slate hover:text-bone transition-colors"
                    >
                      Edit Role
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Invite Modal */}
      {showInviteModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="rounded-xl border border-border bg-card w-full max-w-md p-6 space-y-4 shadow-xl">
            <h2 className="text-base font-bold text-bone">Invite Enterprise Member</h2>
            <p className="text-xs text-slate">
              Send an invitation link with pre-assigned RBAC permissions.
            </p>

            <form onSubmit={handleInvite} className="space-y-4">
              <div>
                <label className="block text-[11px] font-mono text-slate mb-1">Email Address</label>
                <input
                  type="email"
                  required
                  placeholder="developer@company.com"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-background border border-border text-xs text-bone focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate mb-1">Assigned Role</label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-background border border-border text-xs text-bone focus:outline-none focus:border-cyan-500 font-mono"
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowInviteModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-border bg-card hover:bg-card/80 text-xs text-slate hover:text-bone"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white disabled:opacity-50"
                >
                  {submitting ? "Inviting..." : "Send Invitation"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

