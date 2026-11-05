"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  KeyRound,
  Shield,
  RefreshCw,
  Plus,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Lock,
  Layers,
  Cpu,
} from "lucide-react";
import { api } from "@/lib/api";
import { ManagedKey } from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";

export default function ManagedKeysPage() {
  const [keys, setKeys] = useState<ManagedKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [registerModalOpen, setRegisterModalOpen] = useState(false);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verifyStatus, setVerifyStatus] = useState<Record<string, boolean>>({});

  // Form states
  const [name, setName] = useState("");
  const [purpose, setPurpose] = useState("MEMORY_ENCRYPTION");
  const [provider, setProvider] = useState("local");
  const [algorithm, setAlgorithm] = useState("AES_256_GCM");
  const [externalKeyRef, setExternalKeyRef] = useState("");

  const loadKeys = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getKeys();
      setKeys(data);
    } catch (err: any) {
      setError(err.message || "Failed to load managed keys");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadKeys();
  }, []);

  const handleVerify = async (keyId: string) => {
    try {
      setVerifyingId(keyId);
      const res = await api.verifyKey(keyId);
      setVerifyStatus((prev) => ({ ...prev, [keyId]: res.healthy }));
    } catch (err) {
      setVerifyStatus((prev) => ({ ...prev, [keyId]: false }));
    } finally {
      setVerifyingId(null);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.registerKey({
        name,
        purpose,
        provider,
        algorithm,
        external_key_ref: externalKeyRef || undefined,
      });
      setRegisterModalOpen(false);
      setName("");
      setExternalKeyRef("");
      loadKeys();
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
              <KeyRound className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">
                Cryptographic Key Management
              </h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Central KMS catalog, envelope encryption KEKs, and asymmetric signing authorities.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/security/rotation"
            className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-lg border border-border bg-card hover:bg-muted/50 transition-colors text-foreground"
          >
            <RefreshCw className="w-3.5 h-3.5 text-muted-foreground" />
            Rotation & Migration
          </Link>
          <button
            onClick={() => setRegisterModalOpen(true)}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            Register Managed Key
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-border/60 bg-card/50">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Total Keys</span>
            <Lock className="w-4 h-4 text-primary" />
          </div>
          <div className="text-2xl font-bold mt-2 text-foreground">{keys.length}</div>
        </div>
        <div className="p-4 rounded-xl border border-border/60 bg-card/50">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Active KEKs</span>
            <Shield className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-bold mt-2 text-foreground">
            {keys.filter((k) => k.purpose === "MEMORY_ENCRYPTION" && k.status === "ACTIVE").length}
          </div>
        </div>
        <div className="p-4 rounded-xl border border-border/60 bg-card/50">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Signing Authorities</span>
            <Layers className="w-4 h-4 text-blue-500" />
          </div>
          <div className="text-2xl font-bold mt-2 text-foreground">
            {keys.filter((k) => k.purpose.includes("SIGNING") || k.purpose.includes("APPROVAL")).length}
          </div>
        </div>
        <div className="p-4 rounded-xl border border-border/60 bg-card/50">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>KMS Providers</span>
            <Cpu className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-bold mt-2 text-foreground">
            {new Set(keys.map((k) => k.provider)).size || 1}
          </div>
        </div>
      </div>

      {/* Keys Table */}
      <div className="rounded-xl border border-border/60 bg-card/50 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-border/40 flex justify-between items-center">
          <h2 className="text-sm font-semibold text-foreground">Registered Key Catalog</h2>
          <button
            onClick={loadKeys}
            className="p-1.5 rounded-lg border border-border text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {loading ? (
          <div className="p-12 text-center text-sm text-muted-foreground">Loading managed keys...</div>
        ) : error ? (
          <div className="p-12 text-center text-sm text-rose-500">{error}</div>
        ) : keys.length === 0 ? (
          <div className="p-12 text-center text-sm text-muted-foreground">
            No managed keys registered. Click "Register Managed Key" to add one.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted/30 text-muted-foreground border-b border-border/40">
                <tr>
                  <th className="px-4 py-3 font-medium">Key Identifier</th>
                  <th className="px-4 py-3 font-medium">Purpose</th>
                  <th className="px-4 py-3 font-medium">Provider</th>
                  <th className="px-4 py-3 font-medium">Algorithm</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Last Rotated</th>
                  <th className="px-4 py-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/20 text-foreground">
                {keys.map((k) => (
                  <tr key={k.id} className="hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-3 font-medium">
                      <Link
                        href={`/security/keys/${k.id}`}
                        className="hover:underline flex items-center gap-1.5 text-primary"
                      >
                        {k.name}
                        <ExternalLink className="w-3 h-3 text-muted-foreground" />
                      </Link>
                      <div className="font-mono text-[10px] text-muted-foreground">{k.id}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-muted border border-border">
                        {k.purpose}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] uppercase">
                      {k.provider}
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px]">{k.algorithm}</td>
                    <td className="px-4 py-3">
                      <StatusPill status={k.status} />
                    </td>
                    <td className="px-4 py-3 text-muted-foreground">
                      {new Date(k.last_rotated_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="inline-flex items-center gap-2">
                        <button
                          onClick={() => handleVerify(k.id)}
                          disabled={verifyingId === k.id}
                          className="px-2.5 py-1 text-[11px] font-medium rounded border border-border hover:bg-muted/50 transition-colors"
                        >
                          {verifyingId === k.id ? (
                            "Verifying..."
                          ) : verifyStatus[k.id] === true ? (
                            <span className="text-emerald-500 flex items-center gap-1">
                              <CheckCircle2 className="w-3 h-3" /> Valid
                            </span>
                          ) : verifyStatus[k.id] === false ? (
                            <span className="text-rose-500 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" /> Failed
                            </span>
                          ) : (
                            "Verify"
                          )}
                        </button>
                        <Link
                          href={`/security/keys/${k.id}`}
                          className="px-2.5 py-1 text-[11px] font-medium rounded bg-secondary hover:bg-secondary/80 transition-colors"
                        >
                          Details
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Registration Modal */}
      {registerModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-card border border-border rounded-xl shadow-xl max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-semibold text-foreground">Register Managed Key</h3>
            <form onSubmit={handleRegister} className="space-y-3">
              <div>
                <label className="text-xs font-medium text-foreground">Key Name</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Production Tenant Memory KEK"
                  className="w-full mt-1 px-3 py-1.5 text-xs rounded-lg border border-border bg-background text-foreground"
                />
              </div>

              <div>
                <label className="text-xs font-medium text-foreground">Purpose</label>
                <select
                  value={purpose}
                  onChange={(e) => setPurpose(e.target.value)}
                  className="w-full mt-1 px-3 py-1.5 text-xs rounded-lg border border-border bg-background text-foreground"
                >
                  <option value="MEMORY_ENCRYPTION">MEMORY_ENCRYPTION (Data Vault KEK)</option>
                  <option value="POLICY_SIGNING">POLICY_SIGNING (Ed25519 Policy Authority)</option>
                  <option value="APPROVAL_BINDING">APPROVAL_BINDING (HMAC Action Binding)</option>
                  <option value="INTEGRATION_SECRETS">INTEGRATION_SECRETS (MCP / Third-Party)</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-medium text-foreground">KMS Provider</label>
                <select
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  className="w-full mt-1 px-3 py-1.5 text-xs rounded-lg border border-border bg-background text-foreground"
                >
                  <option value="local">Local Development (HKDF)</option>
                  <option value="aws_kms">AWS KMS</option>
                  <option value="gcp_kms">GCP Cloud KMS</option>
                  <option value="azure_key_vault">Azure Key Vault</option>
                  <option value="vault_transit">HashiCorp Vault Transit</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-medium text-foreground">Algorithm</label>
                <select
                  value={algorithm}
                  onChange={(e) => setAlgorithm(e.target.value)}
                  className="w-full mt-1 px-3 py-1.5 text-xs rounded-lg border border-border bg-background text-foreground"
                >
                  <option value="AES_256_GCM">AES_256_GCM (Symmetric KEK)</option>
                  <option value="ED25519">ED25519 (Asymmetric Signing)</option>
                  <option value="HMAC_SHA256">HMAC_SHA256 (Action Binding)</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-medium text-foreground">External Key Reference (ARN/URI)</label>
                <input
                  type="text"
                  value={externalKeyRef}
                  onChange={(e) => setExternalKeyRef(e.target.value)}
                  placeholder="e.g. arn:aws:kms:us-east-1:123456789012:key/..."
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
