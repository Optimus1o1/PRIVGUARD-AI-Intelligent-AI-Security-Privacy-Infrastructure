"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ArrowLeft,
  KeyRound,
  Shield,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  History,
  Lock,
} from "lucide-react";
import { api } from "@/lib/api";
import { KeyDetails } from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";

export default function KeyDetailPage() {
  const params = useParams();
  const keyId = params.id as string;

  const [details, setDetails] = useState<KeyDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rotating, setRotating] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyHealth, setVerifyHealth] = useState<boolean | null>(null);

  const loadDetails = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getKey(keyId);
      setDetails(data);
    } catch (err: any) {
      setError(err.message || "Failed to load key details");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (keyId) {
      loadDetails();
    }
  }, [keyId]);

  const handleRotate = async () => {
    if (!confirm("Are you sure you want to rotate this key? A new active version will be provisioned in the KMS.")) {
      return;
    }
    try {
      setRotating(true);
      await api.rotateKey(keyId);
      alert("Key rotation initiated successfully.");
      loadDetails();
    } catch (err: any) {
      alert(err.message || "Failed to initiate rotation");
    } finally {
      setRotating(false);
    }
  };

  const handleVerify = async () => {
    try {
      setVerifying(true);
      const res = await api.verifyKey(keyId);
      setVerifyHealth(res.healthy);
    } catch (err) {
      setVerifyHealth(false);
    } finally {
      setVerifying(false);
    }
  };

  if (loading) {
    return <div className="p-12 text-center text-sm text-muted-foreground">Loading key details...</div>;
  }

  if (error || !details) {
    return <div className="p-12 text-center text-sm text-rose-500">{error || "Key not found"}</div>;
  }

  const { key, versions } = details;

  return (
    <div className="space-y-6">
      {/* Back button & Header */}
      <div>
        <Link
          href="/security/keys"
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground mb-3 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Keys Catalog
        </Link>
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-border/40 pb-5">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <KeyRound className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">{key.name}</h1>
              <p className="font-mono text-xs text-muted-foreground mt-0.5">{key.id}</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleVerify}
              disabled={verifying}
              className="px-3 py-1.5 text-xs font-medium rounded-lg border border-border bg-card hover:bg-muted/50 transition-colors text-foreground"
            >
              {verifying ? (
                "Verifying..."
              ) : verifyHealth === true ? (
                <span className="text-emerald-500 flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> KMS Connected
                </span>
              ) : verifyHealth === false ? (
                <span className="text-rose-500 flex items-center gap-1">
                  <AlertTriangle className="w-3.5 h-3.5" /> Verification Failed
                </span>
              ) : (
                "Verify KMS Access"
              )}
            </button>
            <button
              onClick={handleRotate}
              disabled={rotating}
              className="px-3.5 py-1.5 text-xs font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              {rotating ? "Rotating..." : "Rotate Key"}
            </button>
          </div>
        </div>
      </div>

      {/* Metadata Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl border border-border/60 bg-card/50 space-y-2">
          <div className="text-xs text-muted-foreground font-medium">Cryptographic Purpose</div>
          <div className="text-sm font-semibold text-foreground">{key.purpose}</div>
          <div className="text-xs text-muted-foreground">Algorithm: {key.algorithm}</div>
        </div>
        <div className="p-4 rounded-xl border border-border/60 bg-card/50 space-y-2">
          <div className="text-xs text-muted-foreground font-medium">KMS Provider</div>
          <div className="text-sm font-semibold uppercase text-foreground">{key.provider}</div>
          <div className="text-xs text-muted-foreground truncate">
            Ref: {key.active_version_id || "Managed automatically"}
          </div>
        </div>
        <div className="p-4 rounded-xl border border-border/60 bg-card/50 space-y-2">
          <div className="text-xs text-muted-foreground font-medium">Key Status & Lifecycle</div>
          <div>
            <StatusPill status={key.status} />
          </div>
          <div className="text-xs text-muted-foreground">
            Last rotated: {new Date(key.last_rotated_at).toLocaleString()}
          </div>
        </div>
      </div>

      {/* Version Catalog */}
      <div className="rounded-xl border border-border/60 bg-card/50 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-border/40 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-muted-foreground" />
            <h2 className="text-sm font-semibold text-foreground">Version History & Cryptographic Lineage</h2>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-muted/30 text-muted-foreground border-b border-border/40">
              <tr>
                <th className="px-4 py-3 font-medium">Version #</th>
                <th className="px-4 py-3 font-medium">Provider Version ID</th>
                <th className="px-4 py-3 font-medium">Public Material</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Created Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/20 text-foreground">
              {versions.map((v) => (
                <tr key={v.id} className="hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-3 font-semibold">v{v.version_num}</td>
                  <td className="px-4 py-3 font-mono text-[11px] text-muted-foreground truncate max-w-xs">
                    {v.provider_version_id || "v1"}
                  </td>
                  <td className="px-4 py-3">
                    {v.has_public_key ? (
                      <span className="text-emerald-500 font-medium">Public Key Stored</span>
                    ) : (
                      <span className="text-muted-foreground">Symmetric / Private</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={v.status} />
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {new Date(v.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
