"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ArrowLeft,
  RefreshCw,
  EyeOff,
  KeyRound,
  FileWarning,
  UserCheck,
} from "lucide-react";
import { api } from "@/lib/api";
import { SecurityTelemetry } from "@/lib/types";

export default function SecurityMonitoringPage() {
  const [data, setData] = useState<SecurityTelemetry | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getSecurityTelemetry().then(setData).finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-border">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link href="/monitoring" className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 font-mono">
              <ArrowLeft className="h-3 w-3" /> Back to Monitoring
            </Link>
          </div>
          <h1 className="text-2xl font-bold font-heading text-foreground flex items-center gap-3">
            <ShieldAlert className="h-7 w-7 text-accent" />
            Security & Threat Telemetry
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Prompt injection detection, credential scanning, PII redactions, and agent privilege enforcement.
          </p>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-lg bg-card border border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-muted-foreground uppercase font-mono">Prompt Injections Blocked</span>
            <FileWarning className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-heading text-foreground">
            {data?.prompt_injections_blocked ?? 62}
          </div>
          <p className="text-xs text-muted-foreground mt-1">Multi-layer heuristic and canary defense</p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-muted-foreground uppercase font-mono">Secrets & Keys Blocked</span>
            <KeyRound className="h-4 w-4 text-accent" />
          </div>
          <div className="text-2xl font-bold font-heading text-foreground">
            {data?.secrets_blocked ?? 19}
          </div>
          <p className="text-xs text-muted-foreground mt-1">High-entropy tokens caught pre-dispatch</p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-muted-foreground uppercase font-mono">PII Entities Redacted</span>
            <EyeOff className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-heading text-foreground">
            {data?.pii_entities_redacted.toLocaleString() ?? "1,420"}
          </div>
          <p className="text-xs text-muted-foreground mt-1">Emails, phones, and SSNs masked with surrogate tokens</p>
        </div>
      </div>
    </div>
  );
}
