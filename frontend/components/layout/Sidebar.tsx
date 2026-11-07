"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Bot,
  Building2,
  CheckCircle2,
  ClipboardCheck,
  Database,
  FileText,
  Layers,
  LayoutDashboard,
  Lock,
  Network,
  Settings,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";

const NAV_ITEMS = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/organization", label: "Enterprise Control", icon: Building2 },
  { href: "/threats", label: "Threat Monitor", icon: ShieldAlert, hasBadge: true },
  { href: "/privacy", label: "Privacy Center", icon: Lock },
  { href: "/memory", label: "Memory Vault", icon: Database },
  { href: "/mcp", label: "MCP Gateway", icon: Network },
  { href: "/agents", label: "Agent Management", icon: Bot },
  { href: "/approvals", label: "Approval Center", icon: CheckCircle2, hasApprovalBadge: true },
  { href: "/activity", label: "Activity & Audit", icon: FileText },
  { href: "/compliance", label: "Compliance Engine", icon: ClipboardCheck },
  { href: "/tasks", label: "Task Monitor", icon: Layers },
  { href: "/system-health", label: "System Health", icon: Activity },
  { href: "/settings", label: "Settings", icon: Settings },
];

export const Sidebar: React.FC = () => {
  const pathname = usePathname();
  const [pendingApprovalsCount, setPendingApprovalsCount] = useState<number>(0);
  const [criticalThreatsCount, setCriticalThreatsCount] = useState<number>(0);

  useEffect(() => {
    const fetchCounters = async () => {
      try {
        const summary = await api.getSummary();
        setPendingApprovalsCount(summary.pending_approvals);
        setCriticalThreatsCount(summary.critical_threats);
      } catch {}
    };

    fetchCounters();
    const interval = setInterval(fetchCounters, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <aside className="w-64 bg-surface/90 backdrop-blur-md border-r border-border flex flex-col h-screen sticky top-0 z-30 select-none">
      {/* Brand Header */}
      <div className="p-5 border-b border-border/70 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-3 group">
          {/* 3x3 Matrix Mark preview */}
          <div className="w-8 h-8 rounded-lg bg-card border border-border flex items-center justify-center p-1.5 shadow-sm group-hover:border-cyan-500/50 transition-colors">
            <div className="grid grid-cols-3 gap-0.5 w-full h-full">
              <div className="bg-bone rounded-[1px]" />
              <div className="bg-bone rounded-[1px]" />
              <div className="bg-bone rounded-[1px]" />
              <div className="bg-bone rounded-[1px]" />
              <div className="bg-transparent" />
              <div className="bg-copper rounded-[1px]" />
              <div className="bg-bone rounded-[1px]" />
              <div className="bg-bone rounded-[1px]" />
              <div className="bg-bone rounded-[1px]" />
            </div>
          </div>
          <div>
            <div className="font-display font-bold tracking-wider text-sm text-bone group-hover:text-white transition-colors">
              PRIVGUARD <span className="text-cyan-400 font-mono text-xs">AI</span>
            </div>
            <div className="text-[10px] text-slate tracking-tight">by Moon Sanctum Labs</div>
          </div>
        </Link>
        <span className="flex h-2 w-2 relative">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
        </span>
      </div>

      {/* Slogan */}
      <div className="px-5 py-2.5 bg-background/50 border-b border-border/40 text-[11px] text-slate/80 font-mono">
        Decode. Build. Evolve.
      </div>

      {/* Nav List */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group",
                isActive
                  ? "bg-card border border-border text-bone font-semibold shadow-sm"
                  : "text-slate hover:text-bone hover:bg-card/40 border border-transparent"
              )}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={cn(
                    "w-4 h-4 transition-colors",
                    isActive ? "text-cyan-400" : "text-slate/70 group-hover:text-bone"
                  )}
                />
                <span>{item.label}</span>
              </div>

              {/* Badges */}
              {item.hasApprovalBadge && pendingApprovalsCount > 0 && (
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse">
                  {pendingApprovalsCount}
                </span>
              )}
              {item.hasBadge && criticalThreatsCount > 0 && (
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                  {criticalThreatsCount}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div className="p-4 border-t border-border/70 bg-card/40">
        <div className="flex items-center justify-between text-[11px] text-slate">
          <span>Gateway</span>
          <span className="text-emerald-400 font-mono font-medium flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            127.0.0.1:8000
          </span>
        </div>
        <div className="mt-2 text-[10px] text-slate/60 font-mono">PRIVGUARD AI v0.5.0</div>
      </div>
    </aside>
  );
};

