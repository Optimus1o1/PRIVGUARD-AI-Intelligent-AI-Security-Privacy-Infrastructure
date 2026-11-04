"use client";

import React from "react";
import { ShieldCheck, ShieldAlert } from "lucide-react";

interface ProtectionGaugeProps {
  score: number; // 0 to 100
  status: string;
}

export const ProtectionGauge: React.FC<ProtectionGaugeProps> = ({ score, status }) => {
  const totalSegments = 24;
  const activeSegments = Math.round((score / 100) * totalSegments);

  // Generate arc segments
  const segments = Array.from({ length: totalSegments }, (_, i) => {
    // Arc from -135deg to +45deg (or -180 to 0)
    const angle = -180 + (i / (totalSegments - 1)) * 180;
    const isActive = i < activeSegments;

    return {
      index: i,
      angle,
      isActive,
    };
  });

  const isHealthy = score >= 80;

  return (
    <div className="bg-card border border-border rounded-xl p-5 flex flex-col justify-between shadow-sm relative overflow-hidden">
      {/* Top Title */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {isHealthy ? (
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          ) : (
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          )}
          <span className="text-xs font-semibold uppercase tracking-wider text-slate">
            System Protection Score
          </span>
        </div>
        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-background border border-border text-emerald-400">
          Continuous Guard
        </span>
      </div>

      {/* Radial Segmented Gauge Visual (Inspired by demo layout) */}
      <div className="relative flex flex-col items-center justify-center my-4 py-2">
        <svg viewBox="0 0 200 110" className="w-48 h-28 overflow-visible">
          {segments.map((seg) => {
            const rad = (seg.angle * Math.PI) / 180;
            const rInner = 68;
            const rOuter = 88;
            const cx = 100;
            const cy = 95;

            const x1 = cx + rInner * Math.cos(rad);
            const y1 = cy + rInner * Math.sin(rad);
            const x2 = cx + rOuter * Math.cos(rad);
            const y2 = cy + rOuter * Math.sin(rad);

            return (
              <line
                key={seg.index}
                x1={x1}
                y1={y1}
                x2={x2}
                y2={y2}
                stroke={
                  seg.isActive
                    ? score >= 80
                      ? "#10B981"
                      : score >= 60
                      ? "#F59E0B"
                      : "#EF4444"
                    : "#1F2430"
                }
                strokeWidth="4"
                strokeLinecap="round"
                className="transition-all duration-300"
              />
            );
          })}
        </svg>

        {/* Center Score Text */}
        <div className="absolute bottom-2 flex flex-col items-center">
          <span className="font-display text-3xl font-bold text-bone tracking-tight">
            {score}%
          </span>
          <span className="text-[10px] text-slate/70 uppercase tracking-wider font-mono">
            {status.replace(/_/g, " ")}
          </span>
        </div>
      </div>

      {/* Subsystem Metrics Matrix */}
      <div className="grid grid-cols-2 gap-2 pt-3 border-t border-border/60 text-[11px]">
        <div className="flex items-center justify-between text-slate">
          <span>Secret Scanner:</span>
          <span className="text-emerald-400 font-mono">Enforcing</span>
        </div>
        <div className="flex items-center justify-between text-slate">
          <span>Threat Defense:</span>
          <span className="text-emerald-400 font-mono">Active</span>
        </div>
        <div className="flex items-center justify-between text-slate">
          <span>PII Redactor:</span>
          <span className="text-emerald-400 font-mono">Reversible</span>
        </div>
        <div className="flex items-center justify-between text-slate">
          <span>Sandbox Isolation:</span>
          <span className="text-emerald-400 font-mono">Locked</span>
        </div>
      </div>
    </div>
  );
};
