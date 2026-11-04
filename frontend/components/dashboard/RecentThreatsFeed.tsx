"use client";

import React from "react";
import Link from "next/link";
import { ChevronRight, ShieldAlert } from "lucide-react";
import { ThreatEvent } from "@/lib/types";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { formatDate, truncateMiddle } from "@/lib/utils";

interface RecentThreatsFeedProps {
  threats: ThreatEvent[];
}

export const RecentThreatsFeed: React.FC<RecentThreatsFeedProps> = ({ threats }) => {
  return (
    <div className="bg-card border border-border rounded-xl p-5 flex flex-col justify-between shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400" />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate">
            Recent Security Interceptions
          </span>
        </div>
        <Link
          href="/threats"
          className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition-colors"
        >
          <span>Investigate in Threat Center</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-border/80 text-slate/70">
              <th className="pb-2.5 font-medium">Threat Category</th>
              <th className="pb-2.5 font-medium">Severity</th>
              <th className="pb-2.5 font-medium">Enforced Action</th>
              <th className="pb-2.5 font-medium">Fingerprint (SHA-256)</th>
              <th className="pb-2.5 font-medium text-right">Detected At</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/40 font-mono">
            {threats.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-6 text-center text-slate/60 text-xs">
                  Zero active threats detected. All perimeter defenses operating normally.
                </td>
              </tr>
            ) : (
              threats.slice(0, 5).map((t) => (
                <tr key={t.id} className="hover:bg-surface/50 transition-colors">
                  <td className="py-3 text-bone font-sans font-medium">
                    {t.threat_type.replace(/_/g, " ")}
                  </td>
                  <td className="py-3">
                    <SeverityBadge severity={t.severity} />
                  </td>
                  <td className="py-3">
                    <span className="px-2 py-0.5 rounded bg-background border border-border text-red-400 text-[11px]">
                      {t.action_taken}
                    </span>
                  </td>
                  <td className="py-3 text-slate text-[11px]" title={t.content_hash}>
                    {truncateMiddle(t.content_hash, 6, 4)}
                  </td>
                  <td className="py-3 text-right text-slate text-[11px]">
                    {formatDate(t.created_at)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
