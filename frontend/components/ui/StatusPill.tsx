import React from "react";
import { cn } from "@/lib/utils";

interface StatusPillProps {
  status: string;
  className?: string;
}

export const StatusPill: React.FC<StatusPillProps> = ({ status, className }) => {
  const s = (status || "UNKNOWN").toUpperCase();

  const getStyle = () => {
    switch (s) {
      case "PROTECTED":
      case "OPERATIONAL":
      case "HEALTHY":
      case "ACTIVE":
      case "COMPLETED":
      case "SUCCESS":
        return "bg-emerald-950/60 text-emerald-400 border-emerald-800/80";
      case "RUNNING":
        return "bg-cyan-950/60 text-cyan-400 border-cyan-800/80";
      case "ATTENTION_REQUIRED":
      case "WAITING_FOR_APPROVAL":
      case "PENDING":
      case "DEGRADED":
        return "bg-amber-950/60 text-amber-400 border-amber-800/80";
      case "CRITICAL_ALERT":
      case "FAILED":
      case "CANCELLED":
      case "REVOKED":
      case "DISABLED":
      case "DOWN":
      case "BLOCK":
        return "bg-red-950/60 text-red-400 border-red-800/80";
      default:
        return "bg-zinc-900 text-zinc-400 border-zinc-800";
    }
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border tracking-wide uppercase",
        getStyle(),
        className
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80" />
      {s.replace(/_/g, " ")}
    </span>
  );
};

