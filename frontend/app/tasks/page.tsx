"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ListChecks,
  Search,
  Filter,
  RefreshCw,
  XCircle,
  ExternalLink,
  Clock,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Terminal,
} from "lucide-react";
import { api } from "@/lib/api";
import { Task } from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";
import { InspectPayloadModal } from "@/components/ui/InspectPayloadModal";

export default function TasksPage() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedStatus, setSelectedStatus] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [inspectTask, setInspectTask] = useState<Task | null>(null);

  const fetchTasks = async () => {
    try {
      setLoading(true);
      const data = await api.getTasks(selectedStatus === "ALL" ? undefined : selectedStatus);
      setTasks(data || []);
    } catch (err) {
      console.error("Failed to fetch tasks:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTasks();
  }, [selectedStatus]);

  const handleCancelTask = async (id: string) => {
    if (!confirm(`Are you sure you want to cancel and terminate Task '${id}'? This will immediately revoke all issued temporary capabilities.`)) {
      return;
    }
    try {
      await api.cancelTask(id);
      fetchTasks();
    } catch (err: any) {
      alert(`Failed to cancel task: ${err.message}`);
    }
  };

  const filteredTasks = tasks.filter((t) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      t.id?.toLowerCase().includes(q) ||
      t.agent_id?.toLowerCase().includes(q) ||
      t.description?.toLowerCase().includes(q)
    );
  });

  const runningCount = tasks.filter((t) => t.status === "RUNNING").length;
  const waitingCount = tasks.filter((t) => t.status === "WAITING_FOR_APPROVAL").length;
  const completedCount = tasks.filter((t) => t.status === "COMPLETED").length;
  const cancelledCount = tasks.filter((t) => t.status === "CANCELLED").length;

  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border/40 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan">
            <ListChecks className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono text-cyber-ink tracking-tight flex items-center gap-2">
              TASK_SESSIONS & CAPABILITY_TRACKING
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyber-surface border border-cyber-border text-cyber-slate font-sans font-normal">
                Scoped Execution
              </span>
            </h1>
            <p className="text-sm text-cyber-slate">
              Active autonomous agent task sessions, short-lived tokens, and execution taint monitoring
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchTasks}
            disabled={loading}
            className="p-2 rounded-lg border border-cyber-border bg-cyber-surface hover:bg-cyber-muted text-cyber-slate hover:text-cyber-ink transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* KPI Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-cyber-border bg-cyber-card/60">
          <span className="text-xs font-mono text-cyber-slate uppercase tracking-wider">Active Running Tasks</span>
          <div className="text-2xl font-bold font-mono text-cyber-cyan mt-1">{runningCount}</div>
          <span className="text-[11px] text-cyber-slate mt-1 block">Live tool execution sessions</span>
        </div>
        <div className="p-4 rounded-xl border border-cyber-amber/30 bg-cyber-amber/5">
          <span className="text-xs font-mono text-cyber-amber uppercase tracking-wider">Awaiting Human Approval</span>
          <div className="text-2xl font-bold font-mono text-cyber-amber mt-1">{waitingCount}</div>
          <span className="text-[11px] text-cyber-slate mt-1 block">Execution halted for review</span>
        </div>
        <div className="p-4 rounded-xl border border-cyber-emerald/30 bg-cyber-emerald/5">
          <span className="text-xs font-mono text-cyber-emerald uppercase tracking-wider">Completed Sessions</span>
          <div className="text-2xl font-bold font-mono text-cyber-emerald mt-1">{completedCount}</div>
          <span className="text-[11px] text-cyber-slate mt-1 block">Capabilities expired safely</span>
        </div>
        <div className="p-4 rounded-xl border border-cyber-red/30 bg-cyber-red/5">
          <span className="text-xs font-mono text-cyber-red uppercase tracking-wider">Cancelled / Aborted</span>
          <div className="text-2xl font-bold font-mono text-cyber-red mt-1">{cancelledCount}</div>
          <span className="text-[11px] text-cyber-slate mt-1 block">Revoked or terminated</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl border border-cyber-border bg-cyber-card flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          <span className="text-xs font-mono text-cyber-slate uppercase mr-2 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Status:
          </span>
          {["ALL", "RUNNING", "WAITING_FOR_APPROVAL", "COMPLETED", "CANCELLED"].map((st) => (
            <button
              key={st}
              onClick={() => setSelectedStatus(st)}
              className={`px-2.5 py-1 rounded-md text-xs font-mono transition-colors ${
                selectedStatus === st
                  ? "bg-cyber-cyan/15 border border-cyber-cyan text-cyber-cyan"
                  : "bg-cyber-surface border border-cyber-border text-cyber-slate hover:text-cyber-ink"
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-cyber-slate" />
          <input
            type="text"
            placeholder="Search task ID, agent..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink placeholder-cyber-slate focus:outline-none focus:border-cyber-cyan"
          />
        </div>
      </div>

      {/* Tasks Table */}
      {loading ? (
        <div className="p-12 text-center border border-cyber-border rounded-xl bg-cyber-card">
          <RefreshCw className="w-6 h-6 animate-spin text-cyber-cyan mx-auto mb-3" />
          <p className="text-sm font-mono text-cyber-slate">Querying task broker...</p>
        </div>
      ) : filteredTasks.length === 0 ? (
        <div className="p-12 text-center border border-cyber-border rounded-xl bg-cyber-card">
          <ShieldCheck className="w-8 h-8 text-cyber-emerald mx-auto mb-2" />
          <h3 className="text-sm font-bold font-mono text-cyber-ink">NO TASKS IN THIS VIEW</h3>
          <p className="text-xs text-cyber-slate mt-1">No active or historical tasks match the selected status.</p>
        </div>
      ) : (
        <div className="border border-cyber-border rounded-xl bg-cyber-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-cyber-surface/80 border-b border-cyber-border text-cyber-slate uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">Task ID</th>
                  <th className="py-3 px-4">Agent ID</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Taint Status</th>
                  <th className="py-3 px-4">Created Time</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/50 text-cyber-ink">
                {filteredTasks.map((task) => (
                  <tr key={task.id} className="hover:bg-cyber-surface/40 transition-colors">
                    <td className="py-3 px-4 font-bold text-cyber-cyan truncate max-w-[140px]" title={task.id}>
                      {task.id}
                    </td>
                    <td className="py-3 px-4">
                      <Link
                        href={`/agents/${task.agent_id}`}
                        className="text-cyber-slate hover:text-cyber-cyan transition-colors flex items-center gap-1.5"
                      >
                        <Terminal className="w-3 h-3 text-cyber-slate" />
                        <span className="truncate max-w-[120px]">{task.agent_id}</span>
                        <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                      </Link>
                    </td>
                    <td className="py-3 px-4">
                      <StatusPill status={task.status} />
                    </td>
                    <td className="py-3 px-4">
                      {task.is_tainted ? (
                        <span className="px-2 py-0.5 rounded bg-cyber-red/10 border border-cyber-red/30 text-cyber-red text-[11px] font-bold flex items-center gap-1 w-fit">
                          <ShieldAlert className="w-3 h-3" /> TAINTED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald text-[11px] flex items-center gap-1 w-fit">
                          <CheckCircle2 className="w-3 h-3" /> CLEAN
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-cyber-slate whitespace-nowrap">
                      {new Date(task.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setInspectTask(task)}
                          className="px-2.5 py-1 rounded bg-cyber-surface border border-cyber-border text-cyber-cyan hover:bg-cyber-muted text-xs transition-colors"
                        >
                          Inspect
                        </button>
                        {(task.status === "RUNNING" || task.status === "WAITING_FOR_APPROVAL") && (
                          <button
                            onClick={() => handleCancelTask(task.id)}
                            className="px-2.5 py-1 rounded bg-cyber-red/10 border border-cyber-red/30 text-cyber-red hover:bg-cyber-red/20 text-xs transition-colors flex items-center gap-1"
                            title="Abort task and revoke capabilities"
                          >
                            <XCircle className="w-3 h-3" />
                            Abort
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Inspect Modal */}
      {inspectTask && (
        <InspectPayloadModal
          isOpen={true}
          onClose={() => setInspectTask(null)}
          title={`Task Session // ${inspectTask.id}`}
          payload={{
            task_id: inspectTask.id,
            agent_id: inspectTask.agent_id,
            status: inspectTask.status,
            description: inspectTask.description,
            is_tainted: inspectTask.is_tainted,
            taint_reasons: inspectTask.taint_reasons,
            context_summary: inspectTask.context_summary,
            created_at: inspectTask.created_at,
            completed_at: inspectTask.completed_at,
          }}
        />
      )}
    </div>
  );
}
