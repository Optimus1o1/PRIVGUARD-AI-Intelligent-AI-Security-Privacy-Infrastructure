"use client";

import { useEffect, useState } from "react";
import {
  FileText,
  Search,
  Filter,
  RefreshCw,
  Download,
  Fingerprint,
  Clock,
  ShieldCheck,
  Lock,
  Layers,
} from "lucide-react";
import { api } from "@/lib/api";
import { AuditEvent } from "@/lib/types";
import { StatusPill } from "@/components/ui/StatusPill";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { InspectPayloadModal } from "@/components/ui/InspectPayloadModal";

export default function ActivityPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAction, setSelectedAction] = useState<string>("ALL");
  const [selectedEventType, setSelectedEventType] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [inspectEvent, setInspectEvent] = useState<AuditEvent | null>(null);

  const fetchAuditEvents = async () => {
    try {
      setLoading(true);
      const data = await api.getAuditEvents(100);
      setEvents(data || []);
    } catch (err) {
      console.error("Failed to fetch audit events:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditEvents();
  }, []);

  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(events, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `privguard_audit_trail_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const filteredEvents = events.filter((e) => {
    if (selectedAction !== "ALL" && e.action_taken !== selectedAction) return false;
    if (selectedEventType !== "ALL" && e.event_type !== selectedEventType) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      e.id?.toLowerCase().includes(q) ||
      e.event_type?.toLowerCase().includes(q) ||
      e.content_fingerprint?.toLowerCase().includes(q) ||
      e.action_taken?.toLowerCase().includes(q) ||
      e.risk_level?.toLowerCase().includes(q)
    );
  });

  const totalBlocked = events.filter((e) => e.action_taken === "BLOCKED").length;
  const totalRedacted = events.filter((e) => e.action_taken === "REDACTED").length;
  const totalAllowed = events.filter((e) => e.action_taken === "ALLOWED").length;

  return (
    <div className="space-y-8">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border/40 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono text-cyber-ink tracking-tight flex items-center gap-2">
              ACTIVITY_LEDGER & AUDIT_LOG
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyber-surface border border-cyber-border text-cyber-slate font-sans font-normal">
                Cryptographic Index
              </span>
            </h1>
            <p className="text-sm text-cyber-slate">
              Immutable ledger of gateway inspections, broker authorizations, and policy enforcement decisions
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleExportJSON}
            disabled={events.length === 0}
            className="px-3.5 py-1.5 rounded-lg border border-cyber-border bg-cyber-surface hover:bg-cyber-muted text-xs font-mono text-cyber-ink transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5 text-cyber-cyan" />
            Export Audit Trail (JSON)
          </button>
          <button
            onClick={fetchAuditEvents}
            disabled={loading}
            className="p-2 rounded-lg border border-cyber-border bg-cyber-surface hover:bg-cyber-muted text-cyber-slate hover:text-cyber-ink transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Zero Content Guarantee Card */}
      <div className="p-4 rounded-xl border border-cyber-cyan/30 bg-cyber-cyan/5 flex items-start gap-3">
        <Lock className="w-5 h-5 text-cyber-cyan shrink-0 mt-0.5" />
        <div className="text-xs space-y-1">
          <div className="font-bold font-mono text-cyber-ink">ZERO-CONTENT AUDIT GUARANTEE</div>
          <div className="text-cyber-slate">
            PRIVGUARD never logs raw prompt inputs, external LLM outputs, or unmasked confidential secrets to persistent
            storage. Every audit record retains strictly SHA-256 content hashes, policy match tallies, rule identifiers,
            and millisecond execution durations for zero-knowledge compliance.
          </div>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-cyber-border bg-cyber-card/60">
          <span className="text-xs font-mono text-cyber-slate uppercase tracking-wider">Total Recorded Events</span>
          <div className="text-2xl font-bold font-mono text-cyber-ink mt-1">{events.length}</div>
          <span className="text-[11px] text-cyber-slate mt-1 block">Indexed records</span>
        </div>
        <div className="p-4 rounded-xl border border-cyber-red/30 bg-cyber-red/5">
          <span className="text-xs font-mono text-cyber-red uppercase tracking-wider">Interceptions / Blocks</span>
          <div className="text-2xl font-bold font-mono text-cyber-red mt-1">{totalBlocked}</div>
          <span className="text-[11px] text-cyber-slate mt-1 block">Threat / Policy violations</span>
        </div>
        <div className="p-4 rounded-xl border border-cyber-emerald/30 bg-cyber-emerald/5">
          <span className="text-xs font-mono text-cyber-emerald uppercase tracking-wider">Redaction Events</span>
          <div className="text-2xl font-bold font-mono text-cyber-emerald mt-1">{totalRedacted}</div>
          <span className="text-[11px] text-cyber-slate mt-1 block">Reversible sanitized transfers</span>
        </div>
        <div className="p-4 rounded-xl border border-cyber-cyan/30 bg-cyber-cyan/5">
          <span className="text-xs font-mono text-cyber-cyan uppercase tracking-wider">Allowed & Passed</span>
          <div className="text-2xl font-bold font-mono text-cyber-cyan mt-1">{totalAllowed}</div>
          <span className="text-[11px] text-cyber-slate mt-1 block">Clean interactions</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl border border-cyber-border bg-cyber-card flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          <span className="text-xs font-mono text-cyber-slate uppercase mr-2 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Action:
          </span>
          {["ALL", "BLOCKED", "REDACTED", "ALLOWED", "QUARANTINED"].map((act) => (
            <button
              key={act}
              onClick={() => setSelectedAction(act)}
              className={`px-2.5 py-1 rounded-md text-xs font-mono transition-colors ${
                selectedAction === act
                  ? "bg-cyber-cyan/15 border border-cyber-cyan text-cyber-cyan"
                  : "bg-cyber-surface border border-cyber-border text-cyber-slate hover:text-cyber-ink"
              }`}
            >
              {act}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <select
            value={selectedEventType}
            onChange={(e) => setSelectedEventType(e.target.value)}
            className="px-3 py-1.5 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink focus:outline-none focus:border-cyber-cyan"
          >
            <option value="ALL">All Event Types</option>
            <option value="REQUEST_INSPECTED">REQUEST_INSPECTED</option>
            <option value="RESPONSE_INSPECTED">RESPONSE_INSPECTED</option>
            <option value="TOOL_EXECUTION">TOOL_EXECUTION</option>
            <option value="APPROVAL_DECISION">APPROVAL_DECISION</option>
            <option value="THREAT_DETECTED">THREAT_DETECTED</option>
          </select>

          <div className="relative flex-1 md:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-cyber-slate" />
            <input
              type="text"
              placeholder="Search fingerprint, ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink placeholder-cyber-slate focus:outline-none focus:border-cyber-cyan"
            />
          </div>
        </div>
      </div>

      {/* Main Table */}
      {loading ? (
        <div className="p-12 text-center border border-cyber-border rounded-xl bg-cyber-card">
          <RefreshCw className="w-6 h-6 animate-spin text-cyber-cyan mx-auto mb-3" />
          <p className="text-sm font-mono text-cyber-slate">Loading audit records...</p>
        </div>
      ) : filteredEvents.length === 0 ? (
        <div className="p-12 text-center border border-cyber-border rounded-xl bg-cyber-card">
          <ShieldCheck className="w-8 h-8 text-cyber-emerald mx-auto mb-2" />
          <h3 className="text-sm font-bold font-mono text-cyber-ink">NO MATCHING AUDIT RECORDS</h3>
          <p className="text-xs text-cyber-slate mt-1">No events found matching the active filter criteria.</p>
        </div>
      ) : (
        <div className="border border-cyber-border rounded-xl bg-cyber-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-cyber-surface/80 border-b border-cyber-border text-cyber-slate uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Event Type</th>
                  <th className="py-3 px-4">Action Taken</th>
                  <th className="py-3 px-4">Risk Level</th>
                  <th className="py-3 px-4">Processing Time</th>
                  <th className="py-3 px-4">Content Fingerprint</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/50 text-cyber-ink">
                {filteredEvents.map((evt) => (
                  <tr key={evt.id} className="hover:bg-cyber-surface/40 transition-colors">
                    <td className="py-3 px-4 text-cyber-slate whitespace-nowrap">
                      {new Date(evt.timestamp || evt.created_at || "").toLocaleString()}
                    </td>
                    <td className="py-3 px-4 font-bold">{evt.event_type}</td>
                    <td className="py-3 px-4">
                      <StatusPill status={evt.action_taken} />
                    </td>
                    <td className="py-3 px-4">
                      <SeverityBadge severity={evt.risk_level} />
                    </td>
                    <td className="py-3 px-4 text-cyber-slate">
                      {evt.processing_time_ms ? `${evt.processing_time_ms.toFixed(1)} ms` : "N/A"}
                    </td>
                    <td className="py-3 px-4 text-cyber-slate truncate max-w-[140px]" title={evt.content_fingerprint || "N/A"}>
                      {evt.content_fingerprint ? `${evt.content_fingerprint.slice(0, 16)}...` : "—"}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setInspectEvent(evt)}
                        className="px-2.5 py-1 rounded bg-cyber-surface border border-cyber-border text-cyber-cyan hover:bg-cyber-muted text-xs transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Inspect Detail Modal */}
      {inspectEvent && (
        <InspectPayloadModal
          isOpen={true}
          onClose={() => setInspectEvent(null)}
          title={`Audit Record // ${inspectEvent.event_type}`}
          payload={{
            audit_id: inspectEvent.id,
            event_type: inspectEvent.event_type,
            action_taken: inspectEvent.action_taken,
            risk_level: inspectEvent.risk_level,
            processing_time_ms: inspectEvent.processing_time_ms,
            content_fingerprint: inspectEvent.content_fingerprint,
            created_at: inspectEvent.created_at,
            metadata: inspectEvent.metadata,
            compliance_standard: "PRIVGUARD Zero-Content Audit Standard (RFC-compliant)",
          }}
        />
      )}
    </div>
  );
}
