"use client";

import { useState } from "react";
import Link from "next/link";
import {
  Users,
  ArrowLeft,
  RefreshCw,
  Cpu,
  Shield,
  Layers,
  CheckCircle2,
} from "lucide-react";

export default function AgentFleetMonitoringPage() {
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
            <Users className="h-7 w-7 text-accent" />
            Agent & MCP Fleet Telemetry
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Tool execution latencies, capability revocations, MCP server connectivity, and catalog integrity.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">Active Tool Calls</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1">12,490</div>
          <p className="text-xs text-muted-foreground mt-1">Processed by Agent Security Broker</p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">Authorization Denials</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1 text-amber-400">3</div>
          <p className="text-xs text-muted-foreground mt-1">Privilege escalation blocks</p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">MCP Servers Active</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1 text-emerald-400">4 / 4</div>
          <p className="text-xs text-muted-foreground mt-1">Zero connection timeouts</p>
        </div>

        <div className="p-5 rounded-lg bg-card border border-border">
          <span className="text-xs text-muted-foreground uppercase font-mono">Quarantined Tools</span>
          <div className="text-2xl font-bold font-heading text-foreground mt-1">0</div>
          <p className="text-xs text-muted-foreground mt-1">No schema drift detected</p>
        </div>
      </div>
    </div>
  );
}
