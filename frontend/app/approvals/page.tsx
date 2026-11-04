"use client";

import React, { useEffect, useState } from "react";
import { AlertCircle, CheckCircle2, Clock, ShieldAlert, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import { ApprovalRequest } from "@/lib/types";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { formatDate, truncateMiddle } from "@/lib/utils";

export default function ApprovalsPage() {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedApproval, setSelectedApproval] = useState<ApprovalRequest | null>(null);
  const [actionType, setActionType] = useState<"APPROVE" | "REJECT" | null>(null);
  const [processing, setProcessing] = useState(false);
  const [notification, setNotification] = useState<{ type: "success" | "error"; message: string } | null>(null);

  const loadApprovals = async () => {
    try {
      setError(null);
      const data = await api.getPendingApprovals();
      setApprovals(data);
    } catch (err: any) {
      setError(err.message || "Failed to load pending approvals.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadApprovals();
    const interval = setInterval(loadApprovals, 6000);
    return () => clearInterval(interval);
  }, []);

  const handleConfirmAction = async () => {
    if (!selectedApproval || !actionType) return;
    setProcessing(true);
    setNotification(null);
    try {
      if (actionType === "APPROVE") {
        await api.approveAction(selectedApproval.id);
        setNotification({
          type: "success",
          message: `Operation approved. Action bound to hash ${truncateMiddle(selectedApproval.action_hash, 6, 4)}.`,
        });
      } else {
        await api.rejectAction(selectedApproval.id);
        setNotification({
          type: "success",
          message: `Operation rejected. Agent request denied.`,
        });
      }
      setSelectedApproval(null);
      setActionType(null);
      await loadApprovals();
    } catch (err: any) {
      setNotification({
        type: "error",
        message: err.message || "Action failed.",
      });
    } finally {
      setProcessing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Description */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-card border border-border rounded-xl p-5 shadow-sm">
        <div>
          <h2 className="font-display font-bold text-bone text-base tracking-wide flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-amber-400" />
            Human-in-the-Loop Approval Center
          </h2>
          <p className="text-xs text-slate mt-1">
            Autonomous agent operations with HIGH or CRITICAL risk classifications are held in escrow pending human authorization.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate">Pending Hold:</span>
          <span className="px-2.5 py-1 rounded bg-amber-500/20 border border-amber-500/30 text-amber-400 font-bold font-mono text-xs">
            {approvals.length} Actions
          </span>
        </div>
      </div>

      {notification && (
        <div
          className={`p-4 rounded-xl border text-xs flex items-center justify-between ${
            notification.type === "success"
              ? "bg-emerald-950/40 border-emerald-800 text-emerald-300"
              : "bg-red-950/40 border-red-800 text-red-300"
          }`}
        >
          <span>{notification.message}</span>
          <button onClick={() => setNotification(null)} className="text-slate hover:text-bone text-xs">
            Dismiss
          </button>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-xs">
          {error}
        </div>
      )}

      {/* Approvals List */}
      <div className="space-y-4">
        {loading && approvals.length === 0 ? (
          <div className="text-center py-12 text-slate text-xs font-mono">
            Checking pending authorization queue...
          </div>
        ) : approvals.length === 0 ? (
          <div className="text-center py-16 bg-card border border-border rounded-xl">
            <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3 opacity-80" />
            <h3 className="font-display font-medium text-bone text-sm">
              Approval Queue Clear
            </h3>
            <p className="text-xs text-slate mt-1">
              No autonomous agent operations are currently waiting for human intervention.
            </p>
          </div>
        ) : (
          approvals.map((req) => (
            <div
              key={req.id}
              className="bg-card border border-border hover:border-amber-500/40 rounded-xl p-5 transition-all shadow-sm space-y-4"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/60 pb-3">
                <div className="flex items-center gap-3">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse" />
                  <span className="font-display font-semibold text-bone text-sm">
                    Tool Execution Request: <span className="text-cyan-400 font-mono">{req.tool_name}</span>
                  </span>
                  <SeverityBadge severity={req.risk_level} />
                </div>
                <div className="text-xs text-slate font-mono flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-slate/60" />
                  <span>Requested: {formatDate(req.created_at)}</span>
                </div>
              </div>

              {/* Grid Details */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
                <div className="bg-surface/60 p-2.5 rounded-lg border border-border/80">
                  <span className="text-slate text-[11px] block">Requesting Agent</span>
                  <span className="text-bone font-medium">{req.agent_id}</span>
                </div>
                <div className="bg-surface/60 p-2.5 rounded-lg border border-border/80">
                  <span className="text-slate text-[11px] block">Task Session</span>
                  <span className="text-bone font-medium">{req.task_id}</span>
                </div>
                <div className="bg-surface/60 p-2.5 rounded-lg border border-border/80">
                  <span className="text-slate text-[11px] block">Cryptographic Action Hash</span>
                  <span className="text-bone font-medium" title={req.action_hash}>
                    {truncateMiddle(req.action_hash, 8, 6)}
                  </span>
                </div>
              </div>

              {/* Action Parameters Preview */}
              <div>
                <span className="text-[11px] uppercase tracking-wider text-slate font-medium block mb-1.5">
                  Proposed Action Parameters (Sanitized Preview):
                </span>
                <pre className="p-3 bg-background/80 border border-border rounded-lg text-bone font-mono text-xs overflow-x-auto">
                  {typeof req.action_parameters === "string"
                    ? req.action_parameters
                    : JSON.stringify(req.action_parameters, null, 2)}
                </pre>
              </div>

              {/* Action Controls */}
              <div className="flex items-center justify-between pt-2">
                <div className="text-[11px] text-amber-400/90 font-mono flex items-center gap-1.5">
                  <AlertCircle className="w-3.5 h-3.5" />
                  <span>Approval is cryptographically bound to exact parameters. Tampering triggers auto-rejection.</span>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => {
                      setSelectedApproval(req);
                      setActionType("REJECT");
                    }}
                    className="px-3 py-1.5 rounded-lg border border-red-800 text-red-400 hover:bg-red-950/40 text-xs font-semibold transition-colors"
                  >
                    Reject Action
                  </button>
                  <button
                    onClick={() => {
                      setSelectedApproval(req);
                      setActionType("APPROVE");
                    }}
                    className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-bone text-xs font-semibold shadow-md transition-colors flex items-center gap-1.5"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Approve Execution</span>
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Confirmation Modal */}
      {selectedApproval && actionType && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
          <div className="bg-surface border border-border rounded-xl w-full max-w-md p-6 space-y-4 shadow-2xl">
            <h3 className="font-display font-bold text-bone text-base">
              {actionType === "APPROVE" ? "Confirm Action Authorization" : "Confirm Action Rejection"}
            </h3>

            <p className="text-xs text-slate">
              {actionType === "APPROVE"
                ? `You are granting human authorization for Agent '${selectedApproval.agent_id}' to execute tool '${selectedApproval.tool_name}'. This authorization is single-use and non-replayable.`
                : `You are rejecting the tool execution request for '${selectedApproval.tool_name}'. The task will receive a permission denied response.`}
            </p>

            <div className="p-3 bg-card border border-border rounded-lg text-xs font-mono space-y-1">
              <div><span className="text-slate">Tool:</span> <span className="text-cyan-400">{selectedApproval.tool_name}</span></div>
              <div><span className="text-slate">Action Hash:</span> <span className="text-bone">{truncateMiddle(selectedApproval.action_hash, 10, 8)}</span></div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => {
                  setSelectedApproval(null);
                  setActionType(null);
                }}
                disabled={processing}
                className="px-3 py-1.5 rounded-lg border border-border text-slate hover:text-bone text-xs"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmAction}
                disabled={processing}
                className={`px-4 py-1.5 rounded-lg text-bone text-xs font-semibold shadow-md transition-colors ${
                  actionType === "APPROVE"
                    ? "bg-emerald-600 hover:bg-emerald-500"
                    : "bg-red-600 hover:bg-red-500"
                }`}
              >
                {processing ? "Submitting..." : actionType === "APPROVE" ? "Confirm Authorization" : "Confirm Rejection"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
