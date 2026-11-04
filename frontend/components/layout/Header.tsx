"use client";

import React, { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { AlertCircle, CheckCircle, RefreshCw, Search, Shield, Zap } from "lucide-react";
import { api } from "@/lib/api";
import { DashboardSummary } from "@/lib/types";

interface HeaderProps {
  onRefresh?: () => void;
  onOpenInspectModal?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onRefresh, onOpenInspectModal }) => {
  const pathname = usePathname();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchStatus = async () => {
    try {
      const data = await api.getSummary();
      setSummary(data);
    } catch {}
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 8000);
    return () => clearInterval(interval);
  }, []);

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await fetchStatus();
    if (onRefresh) onRefresh();
    setTimeout(() => setIsRefreshing(false), 500);
  };

  const getPageTitle = () => {
    if (pathname === "/") return "Security Overview";
    if (pathname.startsWith("/threats")) return "Threat Monitoring Center";
    if (pathname.startsWith("/privacy")) return "Privacy Center & Policies";
    if (pathname.startsWith("/agents")) return "Agent Management Center";
    if (pathname.startsWith("/approvals")) return "Human Approval Center";
    if (pathname.startsWith("/activity")) return "Activity & Audit Trail";
    if (pathname.startsWith("/tasks")) return "Task Monitoring Center";
    if (pathname.startsWith("/system-health")) return "System Health & Telemetry";
    if (pathname.startsWith("/settings")) return "Settings & Configuration";
    return "Control Center";
  };

  const status = summary?.security_status || "PROTECTED";

  return (
    <header className="h-16 border-b border-border bg-surface/70 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Title */}
      <div className="flex items-center gap-3">
        <h1 className="font-display font-semibold text-bone text-base tracking-wide">
          {getPageTitle()}
        </h1>
        <span className="text-slate/40 text-xs font-mono">/</span>
        <span className="text-slate/70 text-xs font-mono">Production Gateway</span>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* Quick Search trigger */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-card/60 border border-border/80 text-slate/70 text-xs">
          <Search className="w-3.5 h-3.5 text-slate/60" />
          <span>Search events or rules...</span>
          <kbd className="px-1.5 py-0.5 rounded bg-background border border-border text-[10px] font-mono text-slate">
            Ctrl+K
          </kbd>
        </div>

        {/* Manual Refresh */}
        <button
          onClick={handleManualRefresh}
          className="p-2 rounded-lg bg-card/60 border border-border/80 text-slate hover:text-bone hover:border-cyan-500/40 transition-colors"
          title="Refresh dashboard data"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-cyan-400" : ""}`} />
        </button>

        {/* Quick Test Inspection Button */}
        {onOpenInspectModal && (
          <button
            onClick={onOpenInspectModal}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-card border border-cyan-500/40 text-cyan-400 hover:bg-cyan-950/30 text-xs font-medium transition-all shadow-[0_0_12px_rgba(6,182,212,0.15)]"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Test Payload</span>
          </button>
        )}

        {/* Global Security Status Pill */}
        <div
          className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-medium tracking-wide ${
            status === "PROTECTED"
              ? "bg-emerald-950/50 border-emerald-800 text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.2)]"
              : status === "ATTENTION_REQUIRED"
              ? "bg-amber-950/50 border-amber-800 text-amber-400 shadow-[0_0_12px_rgba(245,158,11,0.2)]"
              : "bg-red-950/50 border-red-800 text-red-400 shadow-[0_0_12px_rgba(239,68,68,0.25)]"
          }`}
        >
          <span
            className={`w-2 h-2 rounded-full ${
              status === "PROTECTED"
                ? "bg-emerald-400 animate-pulse"
                : status === "ATTENTION_REQUIRED"
                ? "bg-amber-400"
                : "bg-red-400 animate-ping"
            }`}
          />
          <span className="font-mono text-[11px] uppercase">
            Security Status: {status.replace(/_/g, " ")}
          </span>
        </div>
      </div>
    </header>
  );
};

