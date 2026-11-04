import React from "react";
import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className }) => {
  const sev = (severity || "LOW").toUpperCase();

  const styles = {
    CRITICAL: "bg-red-950/60 text-red-400 border-red-800/80 shadow-[0_0_10px_rgba(239,68,68,0.2)]",
    HIGH: "bg-amber-950/60 text-amber-400 border-amber-800/80",
    MEDIUM: "bg-yellow-950/50 text-yellow-400 border-yellow-800/60",
    LOW: "bg-cyan-950/50 text-cyan-400 border-cyan-800/60",
  }[sev] || "bg-zinc-900 text-zinc-400 border-zinc-800";

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-wide border uppercase",
        styles,
        className
      )}
    >
      <span
        className={cn(
          "w-1.5 h-1.5 rounded-full animate-pulse",
          sev === "CRITICAL" && "bg-red-400",
          sev === "HIGH" && "bg-amber-400",
          sev === "MEDIUM" && "bg-yellow-400",
          sev === "LOW" && "bg-cyan-400"
        )}
      />
      {sev}
    </span>
  );
};
