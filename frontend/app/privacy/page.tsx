"use client";

import { useEffect, useState } from "react";
import {
  Shield,
  Lock,
  Plus,
  Trash2,
  Edit2,
  RefreshCw,
  Eye,
  Sliders,
  Sparkles,
  AlertCircle,
  CheckCircle2,
  FileText,
  KeyRound,
  ShieldCheck,
} from "lucide-react";
import { api } from "@/lib/api";
import { PolicyRule } from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";

export default function PrivacyPage() {
  const [baselinePolicies, setBaselinePolicies] = useState<PolicyRule[]>([]);
  const [customRules, setCustomRules] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(true);

  // Playground state
  const [testText, setTestText] = useState(
    "Contact security lead Alice at alice.smith@privguard.corp or call +1-555-0199. API secret key: sk-ant-api03-abcdef1234567890abcdef."
  );
  const [sanitizing, setSanitizing] = useState(false);
  const [redactResult, setRedactResult] = useState<any>(null);
  const [inspectResult, setInspectResult] = useState<any>(null);

  // Add / Edit Rule Modal state
  const [isRuleModalOpen, setIsRuleModalOpen] = useState(false);
  const [ruleForm, setRuleForm] = useState<Partial<PolicyRule>>({
    id: "",
    name: "",
    description: "",
    category: "PII",
    action: "REDACT",
    severity: "HIGH",
    enabled: true,
  });
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [modalError, setModalError] = useState<string | null>(null);

  const fetchPolicies = async () => {
    try {
      setLoading(true);
      const data = await api.getPolicies();
      setBaselinePolicies(data?.baseline_policies || []);
      setCustomRules(data?.custom_rules || []);
    } catch (err) {
      console.error("Failed to fetch policies:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleTestRedact = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testText.trim()) return;
    try {
      setSanitizing(true);
      const [redact, inspect] = await Promise.all([
        api.redactPrivacy(testText),
        api.inspectPrivacy(testText),
      ]);
      setRedactResult(redact);
      setInspectResult(inspect);
    } catch (err: any) {
      alert(`Sanitization error: ${err.message}`);
    } finally {
      setSanitizing(false);
    }
  };

  const handleSaveRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setModalError(null);

    // Invariant check: cannot set CRITICAL severity to ALLOW
    if (ruleForm.severity === "CRITICAL" && ruleForm.action === "ALLOW") {
      setModalError("Security Invariant: CRITICAL severity rules cannot have an ALLOW action.");
      return;
    }

    try {
      if (editingRuleId) {
        await api.updatePolicyRule(editingRuleId, ruleForm);
      } else {
        await api.createPolicyRule(ruleForm);
      }
      setIsRuleModalOpen(false);
      setEditingRuleId(null);
      setRuleForm({
        id: "",
        name: "",
        description: "",
        category: "PII",
        action: "REDACT",
        severity: "HIGH",
        enabled: true,
      });
      fetchPolicies();
    } catch (err: any) {
      setModalError(err.message || "Failed to save rule");
    }
  };

  const handleDeleteRule = async (id: string) => {
    if (!confirm(`Are you sure you want to delete policy rule '${id}'?`)) return;
    try {
      await api.deletePolicyRule(id);
      fetchPolicies();
    } catch (err: any) {
      alert(`Failed to delete rule: ${err.message}`);
    }
  };

  const openEditModal = (rule: PolicyRule) => {
    setEditingRuleId(rule.id);
    setRuleForm({ ...rule });
    setIsRuleModalOpen(true);
  };

  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border/40 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono text-cyber-ink tracking-tight flex items-center gap-2">
              PRIVACY_CENTER & POLICY_ENGINE
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyber-surface border border-cyber-border text-cyber-slate font-sans font-normal">
                Zero-Leakage Enforcement
              </span>
            </h1>
            <p className="text-sm text-cyber-slate">
              Reversible redaction, secret interception, and granular privacy policy rule enforcement
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              setEditingRuleId(null);
              setRuleForm({
                id: `RULE_${Date.now().toString().slice(-4)}`,
                name: "",
                description: "",
                category: "PII",
                action: "REDACT",
                severity: "HIGH",
                enabled: true,
              });
              setIsRuleModalOpen(true);
            }}
            className="px-3.5 py-1.5 rounded-lg bg-cyber-cyan text-cyber-bg hover:bg-cyan-300 text-xs font-mono font-bold transition-colors flex items-center gap-2"
          >
            <Plus className="w-3.5 h-3.5" />
            Create Custom Rule
          </button>
          <button
            onClick={fetchPolicies}
            disabled={loading}
            className="p-2 rounded-lg border border-cyber-border bg-cyber-surface hover:bg-cyber-muted text-cyber-slate hover:text-cyber-ink transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Interactive Privacy Sandbox Playground */}
      <div className="p-6 rounded-xl border border-cyber-border bg-cyber-card space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border/40 pb-3">
          <div className="flex items-center gap-2 text-cyber-emerald font-mono text-sm font-bold">
            <Sparkles className="w-4 h-4" />
            <span>INTERACTIVE_PLAYGROUND // REVERSIBLE REDACTION & SECRET DETECTION</span>
          </div>
          <span className="text-xs font-mono text-cyber-slate">Live Gateway Pipeline</span>
        </div>

        <p className="text-xs text-cyber-slate">
          Test real-time PII redaction and secret identification. Sensitive tokens are substituted with reversible
          cryptographic placeholders before reaching external LLMs, and restored safely on egress.
        </p>

        <form onSubmit={handleTestRedact} className="space-y-3">
          <textarea
            rows={3}
            value={testText}
            onChange={(e) => setTestText(e.target.value)}
            placeholder="Type sample text with emails, phones, API keys..."
            className="w-full p-3 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink placeholder-cyber-slate focus:outline-none focus:border-cyber-emerald"
          />

          <div className="flex justify-between items-center">
            <span className="text-[11px] font-mono text-cyber-slate">
              Characters: {testText.length} | Guaranteed zero external leakage
            </span>
            <button
              type="submit"
              disabled={sanitizing || !testText.trim()}
              className="px-4 py-2 rounded-lg bg-cyber-emerald text-cyber-bg text-xs font-mono font-bold hover:bg-emerald-400 disabled:opacity-50 transition-colors flex items-center gap-2"
            >
              {sanitizing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
              Redact & Analyze
            </button>
          </div>
        </form>

        {/* Results view */}
        {(redactResult || inspectResult) && (
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-cyber-border/50">
            {/* Sanitized Text */}
            <div className="p-4 rounded-lg bg-cyber-surface border border-cyber-border space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-cyber-emerald font-bold flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" /> SANITIZED PAYLOAD (SENT TO LLM)
                </span>
                <span className="text-cyber-slate text-[11px]">Safe for egress</span>
              </div>
              <p className="p-3 bg-cyber-card rounded border border-cyber-border font-mono text-xs text-cyber-ink whitespace-pre-wrap">
                {redactResult?.sanitized_text || "No output"}
              </p>
            </div>

            {/* Detected Entities breakdown */}
            <div className="p-4 rounded-lg bg-cyber-surface border border-cyber-border space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-cyber-cyan font-bold flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5" /> DETECTED PRIVACY METADATA
                </span>
                <span className="text-cyber-slate text-[11px]">
                  Risk: {inspectResult?.risk_level || "EVALUATING"}
                </span>
              </div>
              <div className="p-3 bg-cyber-card rounded border border-cyber-border font-mono text-xs space-y-2">
                <div className="text-cyber-slate text-[11px]">
                  Fingerprint:{" "}
                  <span className="text-cyber-ink">{inspectResult?.content_fingerprint?.slice(0, 20)}...</span>
                </div>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {inspectResult?.entity_counts &&
                    Object.entries(inspectResult.entity_counts).map(([type, count]) => (
                      <span
                        key={type}
                        className="px-2 py-0.5 rounded bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan text-[11px]"
                      >
                        {type}: {String(count)}
                      </span>
                    ))}
                  {inspectResult?.detected_secrets?.length > 0 && (
                    <span className="px-2 py-0.5 rounded bg-cyber-red/10 border border-cyber-red/30 text-cyber-red text-[11px]">
                      Secrets: {inspectResult.detected_secrets.length} intercepted
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Policy Rules Configuration Table */}
      <div className="border border-cyber-border rounded-xl bg-cyber-card overflow-hidden">
        <div className="p-4 border-b border-cyber-border/40 flex items-center justify-between">
          <div className="flex items-center gap-2 text-cyber-ink font-mono text-sm font-bold">
            <Sliders className="w-4 h-4 text-cyber-cyan" />
            <span>ACTIVE POLICY RULES & ENFORCEMENT ACTIONS</span>
          </div>
          <span className="text-xs font-mono text-cyber-slate">
            {baselinePolicies.length + customRules.length} Total Rules Active
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-cyber-surface/80 border-b border-cyber-border text-cyber-slate uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Rule ID</th>
                <th className="py-3 px-4">Rule Name</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Origin</th>
                <th className="py-3 px-4 text-right">Operations</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/50 text-cyber-ink">
              {/* Baseline system rules */}
              {baselinePolicies.map((rule) => (
                <tr key={rule.id} className="hover:bg-cyber-surface/30 transition-colors">
                  <td className="py-3 px-4 font-bold text-cyber-slate">{rule.id}</td>
                  <td className="py-3 px-4">
                    <div className="font-semibold text-cyber-ink">{rule.name}</div>
                    <div className="text-[11px] text-cyber-slate mt-0.5">{rule.description}</div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-cyber-surface border border-cyber-border text-cyber-slate">
                      {rule.category}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <StatusPill status={rule.action} />
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`text-xs ${
                        rule.severity === "CRITICAL"
                          ? "text-cyber-red font-bold"
                          : rule.severity === "HIGH"
                          ? "text-cyber-amber"
                          : "text-cyber-cyan"
                      }`}
                    >
                      {rule.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-cyber-slate">
                    <span className="text-[11px] px-1.5 py-0.5 rounded bg-cyber-slate/10 text-cyber-slate">
                      SYSTEM BASELINE
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right text-cyber-slate text-[11px] italic">
                    Immutable
                  </td>
                </tr>
              ))}

              {/* Custom user rules */}
              {customRules.map((rule) => (
                <tr key={rule.id} className="hover:bg-cyber-surface/30 transition-colors bg-cyber-cyan/5">
                  <td className="py-3 px-4 font-bold text-cyber-cyan">{rule.id}</td>
                  <td className="py-3 px-4">
                    <div className="font-semibold text-cyber-ink">{rule.name}</div>
                    <div className="text-[11px] text-cyber-slate mt-0.5">{rule.description}</div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-cyber-surface border border-cyber-border text-cyber-slate">
                      {rule.category}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <StatusPill status={rule.action} />
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`text-xs ${
                        rule.severity === "CRITICAL"
                          ? "text-cyber-red font-bold"
                          : rule.severity === "HIGH"
                          ? "text-cyber-amber"
                          : "text-cyber-cyan"
                      }`}
                    >
                      {rule.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-cyber-cyan">
                    <span className="text-[11px] px-1.5 py-0.5 rounded bg-cyber-cyan/15 text-cyber-cyan">
                      CUSTOM
                    </span>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => openEditModal(rule)}
                        className="p-1 rounded hover:bg-cyber-surface text-cyber-slate hover:text-cyber-ink transition-colors"
                        title="Edit rule"
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDeleteRule(rule.id)}
                        className="p-1 rounded hover:bg-cyber-red/20 text-cyber-red transition-colors"
                        title="Delete rule"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add / Edit Policy Rule Modal */}
      {isRuleModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-xl border border-cyber-border bg-cyber-card p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border/40 pb-3">
              <h2 className="text-base font-bold font-mono text-cyber-ink">
                {editingRuleId ? "EDIT CUSTOM POLICY RULE" : "CREATE CUSTOM POLICY RULE"}
              </h2>
              <button
                onClick={() => setIsRuleModalOpen(false)}
                className="text-cyber-slate hover:text-cyber-ink text-sm font-mono"
              >
                ✕
              </button>
            </div>

            {modalError && (
              <div className="p-3 rounded-lg bg-cyber-red/10 border border-cyber-red/30 text-cyber-red text-xs font-mono flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{modalError}</span>
              </div>
            )}

            <form onSubmit={handleSaveRule} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-cyber-slate uppercase mb-1">Rule ID</label>
                <input
                  type="text"
                  disabled={!!editingRuleId}
                  value={ruleForm.id || ""}
                  onChange={(e) => setRuleForm({ ...ruleForm, id: e.target.value.toUpperCase() })}
                  required
                  placeholder="e.g. RULE_CUSTOM_FINANCIAL"
                  className="w-full p-2 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink focus:outline-none focus:border-cyber-cyan disabled:opacity-50"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-cyber-slate uppercase mb-1">Rule Name</label>
                <input
                  type="text"
                  value={ruleForm.name || ""}
                  onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })}
                  required
                  placeholder="e.g. Intercept High-Value Financial Identifiers"
                  className="w-full p-2 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink focus:outline-none focus:border-cyber-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-cyber-slate uppercase mb-1">Description</label>
                <textarea
                  rows={2}
                  value={ruleForm.description || ""}
                  onChange={(e) => setRuleForm({ ...ruleForm, description: e.target.value })}
                  placeholder="Explains the purpose and security rationale of this rule..."
                  className="w-full p-2 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink focus:outline-none focus:border-cyber-cyan"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-cyber-slate uppercase mb-1">Action</label>
                  <select
                    value={ruleForm.action || "REDACT"}
                    onChange={(e) => setRuleForm({ ...ruleForm, action: e.target.value as any })}
                    className="w-full p-2 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink focus:outline-none focus:border-cyber-cyan"
                  >
                    <option value="REDACT">REDACT</option>
                    <option value="BLOCK">BLOCK</option>
                    <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
                    <option value="ALLOW">ALLOW</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-cyber-slate uppercase mb-1">Severity</label>
                  <select
                    value={ruleForm.severity || "HIGH"}
                    onChange={(e) => setRuleForm({ ...ruleForm, severity: e.target.value as any })}
                    className="w-full p-2 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink focus:outline-none focus:border-cyber-cyan"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-cyber-border/40">
                <button
                  type="button"
                  onClick={() => setIsRuleModalOpen(false)}
                  className="px-4 py-2 rounded-lg border border-cyber-border bg-cyber-surface hover:bg-cyber-muted text-xs font-mono text-cyber-slate transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyber-cyan text-cyber-bg hover:bg-cyan-300 text-xs font-mono font-bold transition-colors"
                >
                  Save Policy Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
