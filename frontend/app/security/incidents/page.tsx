"use client";

import { useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  ShieldAlert,
  Flame,
  CheckCircle2,
  Lock,
  Layers,
  KeyRound,
} from "lucide-react";
import { api } from "@/lib/api";
import { KeyCompromiseResult } from "@/lib/types";

export default function KeyIncidentsPage() {
  const [compromiseType, setCompromiseType] = useState("KEK_COMPROMISE");
  const [targetId, setTargetId] = useState("");
  const [notes, setNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [incidentResult, setIncidentResult] = useState<KeyCompromiseResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetId.trim()) return;

    if (
      !confirm(
        `CRITICAL INCIDENT DECLARATION:\nYou are about to trigger emergency compromise response for '${targetId}'.\nThis will restrict keys, revoke active sessions, and force rewrapping or re-encryption. Proceed?`
      )
    ) {
      return;
    }

    try {
      setSubmitting(true);
      setError(null);
      const res = await api.reportCompromise({
        compromise_type: compromiseType,
        target_id: targetId.trim(),
        notes: notes.trim() || undefined,
      });
      setIncidentResult(res);
      setTargetId("");
      setNotes("");
    } catch (err: any) {
      setError(err.message || "Failed to process compromise response");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <Link
          href="/security/keys"
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground mb-3 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Keys Catalog
        </Link>
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-border/40 pb-5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-500">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">
                Cryptographic Incident Response Center
              </h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Emergency key containment, compromise revocation, and automated re-encryption orchestration.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Form Panel */}
        <div className="lg:col-span-2 p-5 rounded-xl border border-border/60 bg-card/50 space-y-4 shadow-sm">
          <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Flame className="w-4 h-4 text-rose-500" /> Declare Cryptographic Compromise
          </h2>
          <p className="text-xs text-muted-foreground">
            Immediately triggers automated containment workflows, restricts the compromised key from new operations, generates a replacement key, and re-encrypts affected payloads where necessary.
          </p>

          {error && <div className="p-3 text-xs rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-500">{error}</div>}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs font-medium text-foreground">Compromise Type</label>
              <select
                value={compromiseType}
                onChange={(e) => setCompromiseType(e.target.value)}
                className="w-full mt-1 px-3 py-2 text-xs rounded-lg border border-border bg-background text-foreground"
              >
                <option value="KEK_COMPROMISE">KEK_COMPROMISE (Key Encryption Key Leak)</option>
                <option value="DEK_COMPROMISE">DEK_COMPROMISE (Individual Memory Plaintext DEK Leak)</option>
                <option value="POLICY_SIGNING_KEY_COMPROMISE">POLICY_SIGNING_KEY_COMPROMISE (Ed25519 Private Key)</option>
                <option value="APPROVAL_HMAC_KEY_COMPROMISE">APPROVAL_HMAC_KEY_COMPROMISE (Approval Action Secret)</option>
              </select>
            </div>

            <div>
              <label className="text-xs font-medium text-foreground">
                Target Identifier ({compromiseType === "DEK_COMPROMISE" ? "Memory ID" : compromiseType === "APPROVAL_HMAC_KEY_COMPROMISE" ? "HMAC KID" : "Key ID"})
              </label>
              <input
                type="text"
                required
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                placeholder={
                  compromiseType === "DEK_COMPROMISE"
                    ? "e.g. mem_a1b2c3d4e5f6"
                    : compromiseType === "APPROVAL_HMAC_KEY_COMPROMISE"
                    ? "e.g. hmac_v1"
                    : "e.g. key_mem_kek_001"
                }
                className="w-full mt-1 px-3 py-2 text-xs rounded-lg border border-border bg-background text-foreground"
              />
            </div>

            <div>
              <label className="text-xs font-medium text-foreground">Incident Notes & Evidence</label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
                placeholder="Details of the detected breach, source of compromise, or anomalous access."
                className="w-full mt-1 px-3 py-2 text-xs rounded-lg border border-border bg-background text-foreground"
              />
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2 text-xs font-medium rounded-lg bg-rose-600 text-white hover:bg-rose-700 transition-colors shadow-sm disabled:opacity-50"
            >
              {submitting ? "Executing Emergency Containment..." : "Execute Emergency Containment"}
            </button>
          </form>

          {incidentResult && (
            <div className="p-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 space-y-2 mt-4">
              <div className="flex items-center gap-2 text-emerald-500 font-semibold text-xs">
                <CheckCircle2 className="w-4 h-4" /> Containment Workflow Executed
              </div>
              <div className="text-xs text-muted-foreground space-y-1 font-mono">
                <div>Status: <span className="text-foreground font-semibold">{incidentResult.status}</span></div>
                <div>Incident Type: <span className="text-foreground">{incidentResult.incident_type}</span></div>
                {incidentResult.action && <div>Action Taken: <span className="text-foreground">{incidentResult.action}</span></div>}
                {incidentResult.rotation_job_id && <div>Rotation Job ID: <span className="text-foreground">{incidentResult.rotation_job_id}</span></div>}
                {incidentResult.records_to_rewrap !== undefined && (
                  <div>Records to Rewrap: <span className="text-foreground">{incidentResult.records_to_rewrap}</span></div>
                )}
                <div>Timestamp: <span className="text-foreground">{new Date(incidentResult.timestamp).toLocaleString()}</span></div>
              </div>
            </div>
          )}
        </div>

        {/* Playbook Rules */}
        <div className="p-5 rounded-xl border border-border/60 bg-card/50 space-y-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-primary" /> Incident Response Playbooks
          </h3>
          <div className="space-y-3 text-xs text-muted-foreground">
            <div className="p-3 rounded-lg border border-border/40 bg-background/50 space-y-1">
              <strong className="text-foreground block">DEK Compromise</strong>
              <p>Generates a fresh 256-bit DEK, fully re-encrypts the specific memory payload with fresh random nonce, and wraps under active KEK.</p>
            </div>
            <div className="p-3 rounded-lg border border-border/40 bg-background/50 space-y-1">
              <strong className="text-foreground block">KEK Compromise</strong>
              <p>Marks compromised version immediately, triggers emergency KMS key rotation, and initiates asynchronous rewrapping across all dependent DEKs.</p>
            </div>
            <div className="p-3 rounded-lg border border-border/40 bg-background/50 space-y-1">
              <strong className="text-foreground block">Signing Key Compromise</strong>
              <p>Revokes trust in compromised Ed25519 public key, provisions new asymmetric keypair, and immediately re-signs all active organizational policy bundles.</p>
            </div>
            <div className="p-3 rounded-lg border border-border/40 bg-background/50 space-y-1">
              <strong className="text-foreground block">Approval HMAC Compromise</strong>
              <p>Revokes the HMAC KID immediately, invalidating any pending unconsumed approvals signed by it, and rotates to a fresh secret.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
