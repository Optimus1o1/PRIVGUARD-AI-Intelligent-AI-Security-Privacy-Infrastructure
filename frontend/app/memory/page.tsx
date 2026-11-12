"use client";

import { useEffect, useState } from "react";
import {
  Database,
  Lock,
  Plus,
  Trash2,
  Edit2,
  RefreshCw,
  Eye,
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  KeyRound,
  FileText,
  AlertTriangle,
  Clock,
  ExternalLink,
  Search,
  Filter,
} from "lucide-react";
import { api } from "@/lib/api";
import {
  MemoryAuditEvent,
  MemoryPermission,
  MemoryProposal,
  MemoryRecord,
  MemoryRetentionSummary,
} from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";

const CATEGORIES = [
  { id: "ALL", label: "All Categories" },
  { id: "USER_PREFERENCES", label: "User Preferences" },
  { id: "LEARNING_PREFERENCES", label: "Learning Preferences" },
  { id: "PROJECT_CONTEXT", label: "Project Context" },
  { id: "WORK_CONTEXT", label: "Work Context" },
  { id: "PERSONAL_PREFERENCES", label: "Personal Preferences" },
  { id: "TASK_CONTEXT", label: "Task Context" },
];

export default function MemoryVaultPage() {
  const [activeTab, setActiveTab] = useState<"memories" | "proposals" | "permissions" | "security">("memories");
  const [loading, setLoading] = useState(true);

  // Stored Memories
  const [memories, setMemories] = useState<MemoryRecord[]>([]);
  const [selectedCategory, setSelectedCategory] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [retentionSummary, setRetentionSummary] = useState<MemoryRetentionSummary | null>(null);

  // Proposals
  const [proposals, setProposals] = useState<MemoryProposal[]>([]);

  // Permissions
  const [permissions, setPermissions] = useState<MemoryPermission[]>([]);

  // Modals & Action States
  const [viewDetailModal, setViewDetailModal] = useState<{ open: boolean; memory?: MemoryRecord; loading?: boolean }>({ open: false });
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");
  const [newCategory, setNewCategory] = useState("USER_PREFERENCES");
  const [newRetentionDays, setNewRetentionDays] = useState<number | undefined>(undefined);
  const [createError, setCreateError] = useState<string | null>(null);

  const [editModalOpen, setEditModalOpen] = useState(false);
  const [editingMemory, setEditingMemory] = useState<MemoryRecord | null>(null);
  const [editValue, setEditValue] = useState("");
  const [editError, setEditError] = useState<string | null>(null);

  const [grantPermModalOpen, setGrantPermModalOpen] = useState(false);
  const [permAgentId, setPermAgentId] = useState("");
  const [permOperation, setPermOperation] = useState("memory.read");
  const [permCategory, setPermCategory] = useState("");
  const [permError, setPermError] = useState<string | null>(null);

  const [purgeConfirmOpen, setPurgeConfirmOpen] = useState(false);
  const [purgeInput, setPurgeInput] = useState("");
  const [rotatingKey, setRotatingKey] = useState(false);
  const [keyRotatedMsg, setKeyRotatedMsg] = useState<string | null>(null);

  // Load Data
  const loadAll = async () => {
    try {
      setLoading(true);
      const [mems, props, perms, ret] = await Promise.all([
        api.getMemoryRecords({ category: selectedCategory === "ALL" ? undefined : selectedCategory }),
        api.getMemoryProposals("PROPOSED"),
        api.getMemoryPermissions(),
        api.getMemoryRetention(),
      ]);
      setMemories(mems || []);
      setProposals(props || []);
      setPermissions(perms || []);
      setRetentionSummary(ret || null);
    } catch (err) {
      console.error("Failed to load memory vault data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, [selectedCategory]);

  // Actions: Decrypt & View
  const handleViewDetail = async (m: MemoryRecord) => {
    setViewDetailModal({ open: true, memory: m, loading: true });
    try {
      const detail = await api.getMemoryDetail(m.id);
      setViewDetailModal({ open: true, memory: detail, loading: false });
    } catch (err: any) {
      alert(`Failed to decrypt memory: ${err.message}`);
      setViewDetailModal({ open: false });
    }
  };

  // Actions: Create Direct Memory
  const handleCreateMemory = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);
    try {
      await api.createMemory(newKey, newValue, newCategory, newRetentionDays);
      setCreateModalOpen(false);
      setNewKey("");
      setNewValue("");
      loadAll();
    } catch (err: any) {
      setCreateError(err.message || "Failed to create memory");
    }
  };

  // Actions: Update CAS
  const handleUpdateMemory = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingMemory) return;
    setEditError(null);
    try {
      await api.updateMemory(editingMemory.id, editValue, editingMemory.version);
      setEditModalOpen(false);
      setEditingMemory(null);
      setEditValue("");
      loadAll();
    } catch (err: any) {
      setEditError(err.message || "Failed to update memory");
    }
  };

  // Actions: Delete (Cryptographic Erasure)
  const handleDeleteMemory = async (id: string) => {
    if (!confirm("Are you sure? This permanently destroys the encryption key and ciphertext. Plaintext will be permanently unrecoverable.")) {
      return;
    }
    try {
      await api.deleteMemory(id);
      loadAll();
    } catch (err: any) {
      alert(`Failed to delete: ${err.message}`);
    }
  };

  // Actions: Revoke
  const handleRevokeMemory = async (id: string) => {
    try {
      await api.revokeMemory(id);
      loadAll();
    } catch (err: any) {
      alert(`Failed to revoke: ${err.message}`);
    }
  };

  // Actions: Proposals
  const handleApproveProposal = async (id: string) => {
    try {
      await api.approveMemoryProposal(id);
      loadAll();
    } catch (err: any) {
      alert(`Failed to approve proposal: ${err.message}`);
    }
  };

  const handleRejectProposal = async (id: string) => {
    const reason = prompt("Optional rejection reason:", "Rejected by user");
    if (reason === null) return;
    try {
      await api.rejectMemoryProposal(id, reason);
      loadAll();
    } catch (err: any) {
      alert(`Failed to reject proposal: ${err.message}`);
    }
  };

  // Actions: Permissions
  const handleGrantPerm = async (e: React.FormEvent) => {
    e.preventDefault();
    setPermError(null);
    try {
      await api.grantMemoryPermission({
        agent_id: permAgentId,
        operation: permOperation,
        category: permCategory || undefined,
      });
      setGrantPermModalOpen(false);
      setPermAgentId("");
      loadAll();
    } catch (err: any) {
      setPermError(err.message || "Failed to grant permission");
    }
  };

  const handleRevokePerm = async (id: string) => {
    try {
      await api.revokeMemoryPermission(id);
      loadAll();
    } catch (err: any) {
      alert(`Failed to revoke permission: ${err.message}`);
    }
  };

  // Actions: Key Rotation
  const handleRotateKey = async () => {
    if (!confirm("Rotate your personal Key Encryption Key (KEK)? All active data encryption keys will be re-wrapped under the new key version.")) {
      return;
    }
    setRotatingKey(true);
    setKeyRotatedMsg(null);
    try {
      const res = await api.rotateMemoryKey();
      setKeyRotatedMsg(`Successfully rotated to key version ${res.new_key_version} (${res.records_rotated} records re-wrapped).`);
      loadAll();
    } catch (err: any) {
      alert(`Key rotation failed: ${err.message}`);
    } finally {
      setRotatingKey(false);
    }
  };

  // Actions: Purge Vault
  const handlePurgeVault = async () => {
    if (purgeInput !== "DELETE ALL MEMORIES") {
      alert("Please type 'DELETE ALL MEMORIES' exactly to confirm.");
      return;
    }
    try {
      await api.purgeMemoryVault();
      setPurgeConfirmOpen(false);
      setPurgeInput("");
      alert("Personal AI Memory Vault has been cryptographically purged.");
      loadAll();
    } catch (err: any) {
      alert(`Vault purge failed: ${err.message}`);
    }
  };

  // Filter memories by search
  const filteredMemories = memories.filter((m) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      m.id.toLowerCase().includes(q) ||
      m.category.toLowerCase().includes(q) ||
      (m.summary && m.summary.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-bone font-display flex items-center gap-2.5">
              <Database className="w-6 h-6 text-cyan-400" />
              Secure Personal AI Memory Vault
            </h1>
            <span className="px-2 py-0.5 text-[10px] font-mono tracking-wider font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              AES-256-GCM ENVELOPE
            </span>
          </div>
          <p className="text-sm text-slate mt-1">
            Encrypted, user-controlled memory infrastructure allowing AI applications to remember what you permit, access what they need, and forget what you revoke.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadAll}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg border border-border text-sm text-slate hover:text-bone hover:border-slate/50 transition-colors flex items-center gap-2 bg-card"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setCreateModalOpen(true)}
            className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-sm transition-colors flex items-center gap-2 shadow-sm"
          >
            <Plus className="w-4 h-4" />
            Store Memory
          </button>
        </div>
      </div>

      {/* Metrics Banner */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-card border border-border rounded-xl p-4">
          <div className="text-xs text-slate font-medium uppercase tracking-wider">Active Memories</div>
          <div className="text-2xl font-bold text-bone font-mono mt-1">
            {retentionSummary ? retentionSummary.active_count : "—"}
          </div>
          <div className="text-xs text-emerald-400 mt-1 flex items-center gap-1">
            <Lock className="w-3.5 h-3.5" /> Envelope Encrypted
          </div>
        </div>

        <div className="bg-card border border-border rounded-xl p-4">
          <div className="text-xs text-slate font-medium uppercase tracking-wider">Pending Consent Proposals</div>
          <div className="text-2xl font-bold text-amber-400 font-mono mt-1">
            {retentionSummary ? retentionSummary.pending_proposals : proposals.length}
          </div>
          <div className="text-xs text-slate mt-1">Awaiting user authorization</div>
        </div>

        <div className="bg-card border border-border rounded-xl p-4">
          <div className="text-xs text-slate font-medium uppercase tracking-wider">Active Agent Permissions</div>
          <div className="text-2xl font-bold text-cyan-400 font-mono mt-1">
            {permissions.filter((p) => p.is_granted).length}
          </div>
          <div className="text-xs text-slate mt-1">Default-deny enforcement</div>
        </div>

        <div className="bg-card border border-border rounded-xl p-4">
          <div className="text-xs text-slate font-medium uppercase tracking-wider">Expired / Revoked</div>
          <div className="text-2xl font-bold text-slate font-mono mt-1">
            {retentionSummary ? retentionSummary.expired_count + retentionSummary.revoked_count : 0}
          </div>
          <div className="text-xs text-slate mt-1">Lifecycle policy enforced</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border gap-6">
        <button
          onClick={() => setActiveTab("memories")}
          className={`pb-3 text-sm font-medium transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "memories"
              ? "border-cyan-400 text-cyan-400 font-semibold"
              : "border-transparent text-slate hover:text-bone"
          }`}
        >
          <Database className="w-4 h-4" />
          Stored Memories ({memories.length})
        </button>

        <button
          onClick={() => setActiveTab("proposals")}
          className={`pb-3 text-sm font-medium transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "proposals"
              ? "border-amber-400 text-amber-400 font-semibold"
              : "border-transparent text-slate hover:text-bone"
          }`}
        >
          <Clock className="w-4 h-4" />
          Pending Proposals
          {proposals.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-amber-500/20 text-amber-400 border border-amber-500/30">
              {proposals.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab("permissions")}
          className={`pb-3 text-sm font-medium transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "permissions"
              ? "border-cyan-400 text-cyan-400 font-semibold"
              : "border-transparent text-slate hover:text-bone"
          }`}
        >
          <Shield className="w-4 h-4" />
          Agent Permissions ({permissions.length})
        </button>

        <button
          onClick={() => setActiveTab("security")}
          className={`pb-3 text-sm font-medium transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === "security"
              ? "border-cyan-400 text-cyan-400 font-semibold"
              : "border-transparent text-slate hover:text-bone"
          }`}
        >
          <KeyRound className="w-4 h-4" />
          Security & Key Rotation
        </button>
      </div>

      {/* TAB 1: STORED MEMORIES */}
      {activeTab === "memories" && (
        <div className="space-y-4">
          {/* Controls Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-card p-3 rounded-lg border border-border">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-slate absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search memory summaries..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-surface border border-border rounded-md text-sm text-bone placeholder:text-slate focus:outline-none focus:border-cyan-500/50"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <Filter className="w-4 h-4 text-slate" />
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="bg-surface border border-border rounded-md text-xs text-bone px-3 py-1.5 focus:outline-none focus:border-cyan-500/50"
              >
                {CATEGORIES.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Table */}
          <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-surface/50 border-b border-border text-xs text-slate uppercase font-medium">
                  <tr>
                    <th className="py-3 px-4">Memory ID & Category</th>
                    <th className="py-3 px-4">Summary / Key</th>
                    <th className="py-3 px-4">Provenance</th>
                    <th className="py-3 px-4">Version</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Fingerprint</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {filteredMemories.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-12 text-center text-slate">
                        <Database className="w-8 h-8 text-slate/40 mx-auto mb-2" />
                        No memory records found in this category.
                      </td>
                    </tr>
                  ) : (
                    filteredMemories.map((m) => (
                      <tr key={m.id} className="hover:bg-surface/30 transition-colors">
                        <td className="py-3 px-4">
                          <div className="font-mono text-xs text-bone font-medium">{m.id}</div>
                          <span className="text-[11px] text-cyan-400 font-mono">{m.category}</span>
                        </td>
                        <td className="py-3 px-4 max-w-xs truncate text-bone text-xs">
                          {m.summary || "—"}
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-[10px] px-2 py-0.5 rounded bg-surface border border-border font-mono text-slate">
                            {m.provenance}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-xs font-mono text-slate">v{m.version}</td>
                        <td className="py-3 px-4">
                          <StatusPill status={m.status} />
                        </td>
                        <td className="py-3 px-4">
                          <span className="font-mono text-[10px] text-slate/70">
                            {m.content_fingerprint ? m.content_fingerprint.slice(0, 10) + "..." : "—"}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => handleViewDetail(m)}
                              title="Decrypt & View"
                              className="p-1 rounded text-slate hover:text-cyan-400 hover:bg-surface transition-colors"
                            >
                              <Eye className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => {
                                setEditingMemory(m);
                                setEditValue("");
                                setEditModalOpen(true);
                              }}
                              title="Update Value"
                              className="p-1 rounded text-slate hover:text-amber-400 hover:bg-surface transition-colors"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleRevokeMemory(m.id)}
                              title="Revoke Access"
                              className="p-1 rounded text-slate hover:text-amber-400 hover:bg-surface transition-colors"
                            >
                              <XCircle className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleDeleteMemory(m.id)}
                              title="Cryptographic Erasure"
                              className="p-1 rounded text-slate hover:text-rose-400 hover:bg-surface transition-colors"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: PENDING PROPOSALS */}
      {activeTab === "proposals" && (
        <div className="space-y-4">
          <div className="bg-card border border-border rounded-xl p-4 flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-bone font-display">Candidate AI Memory Proposals</h2>
              <p className="text-xs text-slate mt-0.5">
                Autonomous AI agents propose candidate knowledge. Memories are NEVER committed to vault until explicitly authorized.
              </p>
            </div>
            <span className="px-2.5 py-1 rounded-full text-xs font-mono bg-amber-500/10 text-amber-400 border border-amber-500/20">
              {proposals.length} Pending
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {proposals.length === 0 ? (
              <div className="bg-card border border-border rounded-xl p-12 text-center text-slate">
                <CheckCircle2 className="w-10 h-10 text-emerald-400/50 mx-auto mb-2" />
                No pending memory proposals. All AI-suggested context is resolved.
              </div>
            ) : (
              proposals.map((p) => (
                <div key={p.id} className="bg-card border border-border rounded-xl p-5 space-y-4 hover:border-border/80 transition-colors">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-cyan-400 font-semibold">{p.category}</span>
                        <span className="text-xs text-slate">• Agent: <code className="text-bone">{p.agent_id || "unknown"}</code></span>
                        <span className="text-xs text-slate">• Task: <code className="text-bone">{p.task_id || "none"}</code></span>
                      </div>
                      <h3 className="text-sm font-bold text-bone mt-1">{p.proposed_key}</h3>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
                      Risk: {p.risk_level}
                    </span>
                  </div>

                  <div className="bg-surface/70 border border-border/80 rounded-lg p-3">
                    <div className="text-[11px] uppercase tracking-wider text-slate font-medium mb-1">Proposed Value</div>
                    <div className="text-xs text-bone font-mono whitespace-pre-wrap">{p.proposed_value}</div>
                  </div>

                  {p.threat_assessment && Object.keys(p.threat_assessment).length > 0 && (
                    <div className="text-[11px] text-slate font-mono bg-surface/30 p-2.5 rounded border border-border/50">
                      Security Assessment: Passed Poisoning & Secret checks ({JSON.stringify(p.threat_assessment)})
                    </div>
                  )}

                  <div className="flex items-center justify-end gap-3 pt-2 border-t border-border/60">
                    <button
                      onClick={() => handleRejectProposal(p.id)}
                      className="px-3 py-1.5 rounded-lg border border-border text-xs text-rose-400 hover:bg-rose-500/10 hover:border-rose-500/30 transition-colors flex items-center gap-1.5"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      Reject Proposal
                    </button>
                    <button
                      onClick={() => handleApproveProposal(p.id)}
                      className="px-4 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-medium text-xs transition-colors flex items-center gap-1.5 shadow-sm"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Approve & Encrypt into Vault
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 3: AGENT PERMISSIONS */}
      {activeTab === "permissions" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between bg-card p-4 rounded-xl border border-border">
            <div>
              <h2 className="text-base font-bold text-bone font-display">Granular Agent Memory Permissions</h2>
              <p className="text-xs text-slate mt-0.5">
                PRIVGUARD implements default-deny. Autonomous agents have ZERO memory access unless explicitly granted.
              </p>
            </div>
            <button
              onClick={() => setGrantPermModalOpen(true)}
              className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs transition-colors flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" />
              Grant Permission
            </button>
          </div>

          <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface/50 border-b border-border text-xs text-slate uppercase font-medium">
                <tr>
                  <th className="py-3 px-4">Agent ID</th>
                  <th className="py-3 px-4">Operation</th>
                  <th className="py-3 px-4">Scope / Category</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Expires</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {permissions.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate">
                      <Shield className="w-8 h-8 text-slate/40 mx-auto mb-2" />
                      No active agent permissions configured. (Default-deny active)
                    </td>
                  </tr>
                ) : (
                  permissions.map((p) => (
                    <tr key={p.id} className="hover:bg-surface/30 transition-colors">
                      <td className="py-3 px-4 font-mono text-xs text-bone">{p.agent_id}</td>
                      <td className="py-3 px-4">
                        <span className="font-mono text-xs px-2 py-0.5 rounded bg-surface border border-border text-cyan-400">
                          {p.operation}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-xs text-slate font-mono">
                        {p.category || p.memory_id || "ALL_VAULT"}
                      </td>
                      <td className="py-3 px-4">
                        {p.is_granted ? (
                          <span className="text-xs text-emerald-400 font-mono flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" /> GRANTED
                          </span>
                        ) : (
                          <span className="text-xs text-rose-400 font-mono flex items-center gap-1">
                            <XCircle className="w-3.5 h-3.5" /> REVOKED
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-xs text-slate font-mono">
                        {p.expires_at ? new Date(p.expires_at).toLocaleDateString() : "Permanent"}
                      </td>
                      <td className="py-3 px-4 text-right">
                        {p.is_granted && (
                          <button
                            onClick={() => handleRevokePerm(p.id)}
                            className="px-2 py-1 rounded text-xs text-rose-400 hover:bg-rose-500/10 transition-colors"
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: SECURITY & RETENTION */}
      {activeTab === "security" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Cryptographic Key Architecture */}
            <div className="bg-card border border-border rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-base font-bold text-bone font-display flex items-center gap-2">
                  <KeyRound className="w-5 h-5 text-cyan-400" />
                  Key Encryption Key (KEK) Rotation
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  HKDF-SHA256
                </span>
              </div>
              <p className="text-xs text-slate">
                User personal memory is envelope-encrypted. Rotating your KEK re-wraps all active DEKs with fresh nonces in O(1) time without re-encrypting large ciphertexts.
              </p>

              {keyRotatedMsg && (
                <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono">
                  {keyRotatedMsg}
                </div>
              )}

              <button
                onClick={handleRotateKey}
                disabled={rotatingKey}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs transition-colors flex items-center gap-2"
              >
                <RefreshCw className={`w-4 h-4 ${rotatingKey ? "animate-spin" : ""}`} />
                Rotate KEK & Re-wrap DEKs Now
              </button>
            </div>

            {/* Privacy Invariants */}
            <div className="bg-card border border-border rounded-xl p-5 space-y-3">
              <h3 className="text-base font-bold text-bone font-display flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                Guaranteed Privacy Invariants
              </h3>
              <ul className="space-y-2 text-xs text-slate">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span><strong>Zero Plaintext on Disk:</strong> Database stores only AES-256-GCM ciphertexts, random nonces, and wrapped DEKs.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span><strong>No AI Training:</strong> Personal memory is exclusively for authorized, real-time context retrieval.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span><strong>Content-Free Audit:</strong> Audit trails record actions and entity fingerprints; zero memory values are ever logged.</span>
                </li>
              </ul>
            </div>
          </div>

          {/* Danger Zone: Vault Purge */}
          <div className="bg-card border border-rose-500/30 rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2 text-rose-400">
              <AlertTriangle className="w-5 h-5" />
              <h3 className="text-base font-bold font-display">Cryptographic Vault Purge (Right to be Forgotten)</h3>
            </div>
            <p className="text-xs text-slate">
              Cryptographically destroy all active and archived personal memories for this account. Encryption keys and ciphertexts are permanently overwritten, making past data mathematically impossible to recover.
            </p>
            <button
              onClick={() => setPurgeConfirmOpen(true)}
              className="px-4 py-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 hover:bg-rose-500 hover:text-white font-medium text-xs transition-colors flex items-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Initiate Permanent Account Purge
            </button>
          </div>
        </div>
      )}

      {/* MODAL: VIEW / DECRYPT MEMORY */}
      {viewDetailModal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-card border border-border rounded-xl max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <Lock className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-bone font-display">Decrypted Memory Entry</h3>
              </div>
              <button
                onClick={() => setViewDetailModal({ open: false })}
                className="text-slate hover:text-bone text-lg"
              >
                ✕
              </button>
            </div>

            {viewDetailModal.loading ? (
              <div className="py-8 text-center text-slate text-sm">
                <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-400" />
                Unwrapping DEK & Decrypting AES-256-GCM ciphertext...
              </div>
            ) : (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-slate">ID:</span> <code className="text-bone">{viewDetailModal.memory?.id}</code>
                  </div>
                  <div>
                    <span className="text-slate">Category:</span> <code className="text-cyan-400">{viewDetailModal.memory?.category}</code>
                  </div>
                  <div>
                    <span className="text-slate">Provenance:</span> <span className="text-bone">{viewDetailModal.memory?.provenance}</span>
                  </div>
                  <div>
                    <span className="text-slate">Version:</span> <span className="text-bone">v{viewDetailModal.memory?.version}</span>
                  </div>
                </div>

                <div>
                  <div className="text-xs text-slate font-medium mb-1">Summary</div>
                  <div className="text-xs text-bone bg-surface p-2.5 rounded border border-border">
                    {viewDetailModal.memory?.summary || "—"}
                  </div>
                </div>

                <div>
                  <div className="text-xs text-slate font-medium mb-1">Decrypted Plaintext Value</div>
                  <div className="text-xs text-bone font-mono bg-surface p-3 rounded border border-border whitespace-pre-wrap max-h-48 overflow-y-auto">
                    {viewDetailModal.memory?.value || "(No value returned)"}
                  </div>
                </div>

                <div className="text-[10px] text-slate font-mono">
                  SHA-256 Fingerprint: {viewDetailModal.memory?.content_fingerprint}
                </div>
              </div>
            )}

            <div className="flex justify-end pt-3 border-t border-border">
              <button
                onClick={() => setViewDetailModal({ open: false })}
                className="px-4 py-1.5 rounded-lg bg-surface border border-border text-xs text-bone hover:bg-surface/80"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: CREATE MEMORY */}
      {createModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <form onSubmit={handleCreateMemory} className="bg-card border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <Database className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-bone font-display">Store Direct Personal Memory</h3>
              </div>
              <button type="button" onClick={() => setCreateModalOpen(false)} className="text-slate hover:text-bone">✕</button>
            </div>

            {createError && (
              <div className="p-2.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs">
                {createError}
              </div>
            )}

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate font-medium block mb-1">Key / Summary</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Preferred programming language"
                  value={newKey}
                  onChange={(e) => setNewKey(e.target.value)}
                  className="w-full bg-surface border border-border rounded-md px-3 py-1.5 text-xs text-bone focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div>
                <label className="text-xs text-slate font-medium block mb-1">Category</label>
                <select
                  value={newCategory}
                  onChange={(e) => setNewCategory(e.target.value)}
                  className="w-full bg-surface border border-border rounded-md px-3 py-1.5 text-xs text-bone focus:outline-none focus:border-cyan-500/50"
                >
                  {CATEGORIES.filter((c) => c.id !== "ALL").map((c) => (
                    <option key={c.id} value={c.id}>{c.label}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs text-slate font-medium block mb-1">Plaintext Value (Will be Encrypted)</label>
                <textarea
                  required
                  rows={4}
                  placeholder="e.g. Always use TypeScript and strict linting for frontend modules."
                  value={newValue}
                  onChange={(e) => setNewValue(e.target.value)}
                  className="w-full bg-surface border border-border rounded-md p-3 text-xs text-bone font-mono focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div>
                <label className="text-xs text-slate font-medium block mb-1">Retention Days (Optional)</label>
                <input
                  type="number"
                  min={1}
                  max={3650}
                  placeholder="e.g. 90 (blank for indefinite)"
                  value={newRetentionDays || ""}
                  onChange={(e) => setNewRetentionDays(e.target.value ? parseInt(e.target.value) : undefined)}
                  className="w-full bg-surface border border-border rounded-md px-3 py-1.5 text-xs text-bone focus:outline-none focus:border-cyan-500/50"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border">
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-border text-xs text-slate hover:text-bone"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs transition-colors"
              >
                Encrypt & Store
              </button>
            </div>
          </form>
        </div>
      )}

      {/* MODAL: UPDATE MEMORY */}
      {editModalOpen && editingMemory && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <form onSubmit={handleUpdateMemory} className="bg-card border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <Edit2 className="w-5 h-5 text-amber-400" />
                <h3 className="font-bold text-bone font-display">Update Memory (v{editingMemory.version})</h3>
              </div>
              <button type="button" onClick={() => setEditModalOpen(false)} className="text-slate hover:text-bone">✕</button>
            </div>

            {editError && (
              <div className="p-2.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs">
                {editError}
              </div>
            )}

            <div className="space-y-3">
              <div className="text-xs text-slate">
                Updating <code className="text-bone">{editingMemory.summary}</code>. Optimistic CAS prevents concurrent write races; previous version is archived.
              </div>

              <div>
                <label className="text-xs text-slate font-medium block mb-1">New Value</label>
                <textarea
                  required
                  rows={4}
                  value={editValue}
                  onChange={(e) => setEditValue(e.target.value)}
                  placeholder="Enter updated memory content..."
                  className="w-full bg-surface border border-border rounded-md p-3 text-xs text-bone font-mono focus:outline-none focus:border-amber-500/50"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border">
              <button
                type="button"
                onClick={() => setEditModalOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-border text-xs text-slate hover:text-bone"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-medium text-xs transition-colors"
              >
                Save New Version
              </button>
            </div>
          </form>
        </div>
      )}

      {/* MODAL: GRANT PERMISSION */}
      {grantPermModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <form onSubmit={handleGrantPerm} className="bg-card border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-bone font-display">Grant Agent Memory Permission</h3>
              </div>
              <button type="button" onClick={() => setGrantPermModalOpen(false)} className="text-slate hover:text-bone">✕</button>
            </div>

            {permError && (
              <div className="p-2.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs">
                {permError}
              </div>
            )}

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate font-medium block mb-1">Agent ID</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. ag_research_v1"
                  value={permAgentId}
                  onChange={(e) => setPermAgentId(e.target.value)}
                  className="w-full bg-surface border border-border rounded-md px-3 py-1.5 text-xs text-bone focus:outline-none focus:border-cyan-500/50"
                />
              </div>

              <div>
                <label className="text-xs text-slate font-medium block mb-1">Operation</label>
                <select
                  value={permOperation}
                  onChange={(e) => setPermOperation(e.target.value)}
                  className="w-full bg-surface border border-border rounded-md px-3 py-1.5 text-xs text-bone focus:outline-none focus:border-cyan-500/50"
                >
                  <option value="memory.read">memory.read (Retrieve authorized memories)</option>
                  <option value="memory.propose_write">memory.propose_write (Submit proposals)</option>
                  <option value="memory.update">memory.update (Update existing memory)</option>
                  <option value="memory.delete">memory.delete (Delete memory)</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate font-medium block mb-1">Category Restriction (Optional)</label>
                <select
                  value={permCategory}
                  onChange={(e) => setPermCategory(e.target.value)}
                  className="w-full bg-surface border border-border rounded-md px-3 py-1.5 text-xs text-bone focus:outline-none focus:border-cyan-500/50"
                >
                  <option value="">All Categories</option>
                  {CATEGORIES.filter((c) => c.id !== "ALL").map((c) => (
                    <option key={c.id} value={c.id}>{c.label}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border">
              <button
                type="button"
                onClick={() => setGrantPermModalOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-border text-xs text-slate hover:text-bone"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs transition-colors"
              >
                Grant Permission
              </button>
            </div>
          </form>
        </div>
      )}

      {/* MODAL: PURGE CONFIRM */}
      {purgeConfirmOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4">
          <div className="bg-card border border-rose-500/50 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-2 text-rose-400 border-b border-rose-500/30 pb-3">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="font-bold font-display text-base">Permanent Cryptographic Erasure</h3>
            </div>

            <p className="text-xs text-slate">
              This action will destroy all encryption keys and overwrite ciphertexts for all personal memory records for this account. Data will become mathematically irrecoverable.
            </p>

            <div>
              <label className="text-xs text-slate font-medium block mb-1">
                Type <strong className="text-bone font-mono">DELETE ALL MEMORIES</strong> to confirm:
              </label>
              <input
                type="text"
                value={purgeInput}
                onChange={(e) => setPurgeInput(e.target.value)}
                placeholder="DELETE ALL MEMORIES"
                className="w-full bg-surface border border-rose-500/40 rounded-md px-3 py-1.5 text-xs text-rose-400 font-mono focus:outline-none"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setPurgeConfirmOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-border text-xs text-slate hover:text-bone"
              >
                Cancel
              </button>
              <button
                onClick={handlePurgeVault}
                disabled={purgeInput !== "DELETE ALL MEMORIES"}
                className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-40 text-white font-medium text-xs transition-colors"
              >
                Confirm Purge
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

