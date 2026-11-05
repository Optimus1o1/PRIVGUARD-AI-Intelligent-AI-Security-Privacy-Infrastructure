"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  RefreshCw,
  ArrowLeft,
  ShieldCheck,
  AlertTriangle,
  Play,
  Layers,
  CheckCircle2,
  Clock,
  Database,
} from "lucide-react";
import { api } from "@/lib/api";
import { MigrationStatus } from "@/lib/types";

export default function RotationAndMigrationPage() {
  const [status, setStatus] = useState<MigrationStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [migrating, setMigrating] = useState(false);
  const [batchSize, setBatchSize] = useState(50);

  const loadStatus = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getMigrationStatus();
      setStatus(data);
    } catch (err: any) {
      setError(err.message || "Failed to load migration status");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  const handleStartMigration = async () => {
    try {
      setMigrating(true);
      const res = await api.startMigration(batchSize);
      alert(`Migration batch processed: ${res.migrated_in_batch} records rewrapped under KMS.`);
      loadStatus();
    } catch (err: any) {
      alert(err.message || "Migration failed");
    } finally {
      setMigrating(false);
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
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <RefreshCw className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">
                Key Rotation & Envelope Migration
              </h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Asynchronous DEK rewrapping, non-destructive V1-to-V2 transitions, and legacy retirement safeguards.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={loadStatus}
              className="p-1.5 rounded-lg border border-border text-muted-foreground hover:text-foreground transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="p-12 text-center text-sm text-muted-foreground">Loading status...</div>
      ) : error ? (
        <div className="p-12 text-center text-sm text-rose-500">{error}</div>
      ) : status ? (
        <div className="space-y-6">
          {/* Migration Banner */}
          <div className="p-5 rounded-xl border border-border/60 bg-card/50 space-y-4">
            <div className="flex items-start justify-between">
              <div className="space-y-1">
                <h3 className="text-base font-semibold text-foreground flex items-center gap-2">
                  <Database className="w-4 h-4 text-primary" /> V1 Legacy to V2 KMS Migration Status
                </h3>
                <p className="text-xs text-muted-foreground">
                  Rewraps memory Data Encryption Keys (DEKs) under the central KMS without decrypting or altering the original data ciphertext.
                </p>
              </div>
              <span
                className={`px-2.5 py-1 rounded-full text-xs font-medium border ${
                  status.unmigrated_records === 0
                    ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-500"
                    : "bg-amber-500/10 border-amber-500/20 text-amber-500"
                }`}
              >
                {status.unmigrated_records === 0 ? "Fully Migrated (V2 Active)" : `${status.unmigrated_records} V1 Records Pending`}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="p-3 rounded-lg border border-border/40 bg-background/50">
                <div className="text-xs text-muted-foreground">Remaining V1 Records</div>
                <div className="text-xl font-bold mt-1 text-foreground">{status.unmigrated_records}</div>
              </div>
              <div className="p-3 rounded-lg border border-border/40 bg-background/50">
                <div className="text-xs text-muted-foreground">Legacy Key Retirement Status</div>
                <div className="text-xs font-medium mt-1 flex items-center gap-1">
                  {status.can_retire_legacy_key ? (
                    <span className="text-emerald-500 flex items-center gap-1">
                      <ShieldCheck className="w-3.5 h-3.5" /> Safe to Retire (Post-Backup)
                    </span>
                  ) : (
                    <span className="text-amber-500 flex items-center gap-1">
                      <AlertTriangle className="w-3.5 h-3.5" /> Blocked (V1 Records Exist)
                    </span>
                  )}
                </div>
              </div>
              <div className="p-3 rounded-lg border border-border/40 bg-background/50">
                <div className="text-xs text-muted-foreground">Latest Job Status</div>
                <div className="text-xs font-medium mt-1 text-foreground">
                  {status.latest_job ? `${status.latest_job.status} (${status.latest_job.records_migrated} / ${status.latest_job.records_total})` : "No jobs run yet"}
                </div>
              </div>
            </div>

            {status.unmigrated_records > 0 && (
              <div className="flex items-center gap-3 pt-3 border-t border-border/40">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Batch size:</span>
                  <input
                    type="number"
                    min={1}
                    max={500}
                    value={batchSize}
                    onChange={(e) => setBatchSize(Number(e.target.value))}
                    className="w-20 px-2 py-1 text-xs rounded border border-border bg-background text-foreground"
                  />
                </div>
                <button
                  onClick={handleStartMigration}
                  disabled={migrating}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                >
                  <Play className="w-3 h-3" />
                  {migrating ? "Processing Batch..." : "Process Migration Batch"}
                </button>
              </div>
            )}
          </div>

          {/* Retirement Policy Rules */}
          <div className="p-5 rounded-xl border border-border/60 bg-card/50 space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Legacy Key Retirement & Recovery Invariants
            </h4>
            <ul className="text-xs text-muted-foreground space-y-2 list-disc list-inside">
              <li>
                <strong className="text-foreground">Never premature destruction</strong>: The legacy Stage 7 master key must not be deleted while encrypted database backups or archive snapshots exist within the retention window.
              </li>
              <li>
                <strong className="text-foreground">Atomic CAS Guarantee</strong>: Database updates during DEK rewrapping check the expected record version, ensuring concurrent updates are never overwritten.
              </li>
              <li>
                <strong className="text-foreground">Post-Rewrap Verification</strong>: Every rewrapped DEK is immediately validated by a roundtrip test decryption before the database transaction is committed.
              </li>
            </ul>
          </div>
        </div>
      ) : null}
    </div>
  );
}
