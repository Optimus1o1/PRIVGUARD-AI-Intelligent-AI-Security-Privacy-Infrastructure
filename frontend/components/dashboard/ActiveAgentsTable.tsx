"use client";

import React from "react";
import Link from "next/link";
import { Bot, ChevronRight, Wrench } from "lucide-react";
import { Agent } from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";
import { formatDate } from "@/lib/utils";

interface ActiveAgentsTableProps {
  agents: Agent[];
}

export const ActiveAgentsTable: React.FC<ActiveAgentsTableProps> = ({ agents }) => {
  return (
    <div className="bg-card border border-border rounded-xl p-5 flex flex-col justify-between shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate">
            Connected AI Agents
          </span>
        </div>
        <Link
          href="/agents"
          className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition-colors"
        >
          <span>View All Agents</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-border/80 text-slate/70">
              <th className="pb-2.5 font-medium">Agent</th>
              <th className="pb-2.5 font-medium">Status</th>
              <th className="pb-2.5 font-medium">Permitted Tools</th>
              <th className="pb-2.5 font-medium">Registered</th>
              <th className="pb-2.5 font-medium text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/40 font-mono">
            {agents.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-6 text-center text-slate/60 text-xs">
                  No registered agents found. Register agents via /v1/agents/register.
                </td>
              </tr>
            ) : (
              agents.slice(0, 5).map((agent) => (
                <tr key={agent.id} className="hover:bg-surface/50 transition-colors">
                  <td className="py-3 text-bone font-sans font-medium flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-cyan-400" />
                    <span>{agent.name}</span>
                  </td>
                  <td className="py-3">
                    <StatusPill status={agent.status} />
                  </td>
                  <td className="py-3 text-slate">
                    <span className="flex items-center gap-1.5 text-[11px]">
                      <Wrench className="w-3 h-3 text-slate/60" />
                      {agent.allowed_tools?.length || 0} tools
                    </span>
                  </td>
                  <td className="py-3 text-slate text-[11px]">
                    {formatDate(agent.created_at)}
                  </td>
                  <td className="py-3 text-right">
                    <Link
                      href={`/agents/${agent.id}`}
                      className="text-slate hover:text-cyan-400 p-1 transition-colors inline-block"
                    >
                      <ChevronRight className="w-4 h-4" />
                    </Link>
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
