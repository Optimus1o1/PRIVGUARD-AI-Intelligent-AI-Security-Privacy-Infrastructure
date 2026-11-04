import React from "react";
import { LucideIcon } from "lucide-react";
import { formatNumber } from "@/lib/utils";

interface MetricCardProps {
  label: string;
  value: number;
  icon: LucideIcon;
  subtitle?: string;
  badge?: string;
  badgeColor?: "emerald" | "amber" | "red" | "cyan";
  urgent?: boolean;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  icon: Icon,
  subtitle,
  badge,
  badgeColor = "cyan",
  urgent,
}) => {
  const badgeClasses = {
    emerald: "bg-emerald-950/60 text-emerald-400 border-emerald-800/80",
    amber: "bg-amber-950/60 text-amber-400 border-amber-800/80",
    red: "bg-red-950/60 text-red-400 border-red-800/80",
    cyan: "bg-cyan-950/60 text-cyan-400 border-cyan-800/80",
  }[badgeColor];

  return (
    <div
      className={`bg-card border rounded-xl p-5 flex flex-col justify-between transition-all ${
        urgent
          ? "border-amber-500/50 shadow-[0_0_15px_rgba(245,158,11,0.15)] bg-amber-950/10"
          : "border-border hover:border-border/90 shadow-sm"
      }`}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-slate uppercase tracking-wider">
          {label}
        </span>
        <div className="p-2 rounded-lg bg-surface border border-border/80 text-slate">
          <Icon className="w-4 h-4 text-cyan-400" />
        </div>
      </div>

      <div className="flex items-baseline justify-between mt-1">
        <span className="font-display text-2xl font-bold text-bone tracking-tight">
          {formatNumber(value)}
        </span>
        {badge && (
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${badgeClasses}`}>
            {badge}
          </span>
        )}
      </div>

      {subtitle && (
        <div className="text-[11px] text-slate/70 mt-2 font-mono flex items-center gap-1.5">
          <span className="w-1 h-1 rounded-full bg-slate/40" />
          {subtitle}
        </div>
      )}
    </div>
  );
};
