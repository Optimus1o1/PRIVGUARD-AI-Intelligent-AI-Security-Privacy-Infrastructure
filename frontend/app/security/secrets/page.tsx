"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Lock,
  RefreshCw,
  Plus,
  Trash2,
  Shield,
  KeyRound,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";
import { api } from "@/lib/api";
import { SecretMetadata } from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";

export default function SecretsPage() {
  const [secrets, setSecrets] = useState<SecretMetadata[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [registerModalOpen, setRegisterModalOpen] = useState(false);

  // Form
  const [name, setName] = useState("");
  const [secretType, setSecretType] = useState("DATABASE_CREDENTIAL");
  const [providerRef, setProviderRef] = useState("");

  const loadSecrets = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getSecrets();
      setSecrets(data);
    } catch (err: any) {
      setError(err.message || "Failed to load secrets");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSecrets();
  }, []);

  const handleRotate = async (secretId: string) => {
    if (!confirm("Are you sure you want to rotate this credential?")) return;
    try {
      await api.rotateSecret(secretId);
      alert("Credential rotation recorded.");
      loadSecrets();
    } catch (err: any) {
      alert(err.message || "Failed to rotate secret");
    }
  };

  const handleRevoke = async (secretId: string) => {
    if (!confirm("CRITICAL: Revoking this secret will block all services using it immediately. Continue?")) return;
    try {
      await api.revokeSecret(secretId);
      alert("Credential revoked.");
      loadSecrets();
    } catch (err: any) {
      alert(err.message || "Failed to revoke secret");
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.registerSecret({
        name,
        secret_type: secretType,
        provider_ref: providerRef || undefined,
      });
      setRegisterModalOpen(false);
      setName("");
      setProviderRef("");
      loadSecrets();
    } catch (err: any) {
      alert(err.message || "Registration failed");
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-border/40 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">
                Application Secrets & Credentials
              </h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Zero-plaintext credential lifecycle management, rotation tracking, and immediate revocation.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/security/incidents"
            className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-lg border border-border bg-card hover:bg-muted/50 transition-colors text-foreground"
          >
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
            Incident Center
          </Link>
          <button
            onClick={() => setRegisterModalOpen(true)}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            Register Secret Metadata
          </button>
        </div>
      </div>

      {/* Secrets Table */}
      <div className="rounded-xl border border-border/60 bg-card/50 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-border/40 flex justify-between items-center">
          <h2 className="text-sm font-semibold text-foreground">Managed Application Credentials</h2>
          <button
            onClick={loadSecrets}
            className="p-1.5 rounded-lg border border-border text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {loading ? (
          <div className="p-12 text-center text-sm text-muted-foreground">Loading secret metadata...</div>
        ) : error ? (
          <div className="p-12 text-center text-sm text-rose-500">{error}</div>
        ) : secrets.length === 0 ? (
          <div className="p-12 text-center text-sm text-muted-foreground">
            No application secrets registered. Click "Register Secret Metadata" to track credentials.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted/30 text-muted-foreground border-b border-border/40">
                <tr>
                  <th className="px-4 py-3 font-medium">Secret Name</th>
                  <th className="px-4 py-3 font-medium">Type</th>
                  <th className="px-4 py-3 font-medium">Version</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Last Rotated</th>
                  <th className="px-4 py-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20 text-foreground">
                {secrets.map((s) => (
                  <tr key={s.id} className="hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-3 font-medium">
                      <div className="text-foreground">{s.name}</div>
                      <div className="font-mono text-[10px] text-muted-foreground">{s.id}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-muted border border-border">
                        {s.secret_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold">v{s.version}</td>
                    <td className="px-4 py-3">
                      <StatusPill status={s.status} />
                    </td>
                    <td className="px-4 py-3 text-muted-foreground">
                      {new Date(s.last_rotated_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="inline-flex items-center gap-2">
                        <button
                          onClick={() => handleRotate(s.id)}
                          disabled={s.status === "REVOKED"}
                          className="px-2.5 py-1 text-[11px] font-medium rounded border border-border hover:bg-muted/50 transition-colors"
                        >
                          Rotate
                        </button>
                        <button
                          onClick={() => handleRevoke(s.id)}
                          disabled={s.status === "REVOKED"}
                          className="px-2.5 py-1 text-[11px] font-medium rounded border border-rose-500/30 text-rose-500 hover:bg-rose-500/10 transition-colors"
                        >
                          Revoke
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal */}
      {registerModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-card border border-border rounded-xl shadow-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-semibold text-foreground">Register Secret Metadata</h3>
            <p className="text-xs text-muted-foreground">
              Registers tracking metadata for operational credentials. Secret values are never entered or stored here.
            </p>
            <form onSubmit={handleRegister} className="space-y-3">
              <div>
                <label className="text-xs font-medium text-foreground">Secret Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Production PostgreSQL Application Password"
                  className="w-full mt-1 px-3 py-1.5 text-xs rounded-lg border border-border bg-background text-foreground"
                />
              </div>

              <div>
                <label className="text-xs font-medium text-foreground">Secret Type</label>
                <select
                  value={secretType}
                  onChange={(e) => setSecretType(e.target.value)}
                  className="w-full mt-1 px-3 py-1.5 text-xs rounded-lg border border-border bg-background text-foreground"
                >
                  <option value="DATABASE_CREDENTIAL">DATABASE_CREDENTIAL</option>
                  <option value="REDIS_CREDENTIAL">REDIS_CREDENTIAL</option>
                  <option value="LLM_API_KEY">LLM_API_KEY</option>
                  <option value="MCP_CREDENTIAL">MCP_CREDENTIAL</option>
                  <option value="OAUTH_SECRET">OAUTH_SECRET</option>
                  <option value="SIEM_TOKEN">SIEM_TOKEN</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-medium text-foreground">Provider / SecretStore Reference</label>
                <input
                  type="text"
                  value={providerRef}
                  onChange={(e) => setProviderRef(e.target.value)}
                  placeholder="e.g. privguard-database-credentials:postgres_password"
                  className="w-full mt-1 px-3 py-1.5 text-xs rounded-lg border border-border bg-background text-foreground"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setRegisterModalOpen(false)}
                  className="px-3 py-1.5 text-xs rounded-lg border border-border hover:bg-muted/50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 text-xs rounded-lg bg-primary text-primary-foreground hover:bg-primary/90"
                >
                  Register
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
