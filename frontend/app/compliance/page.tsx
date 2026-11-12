"use client";

import { useEffect, useState } from "react";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardCheck,
  Copy,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileCheck,
  FileCode,
  FileSpreadsheet,
  FileText,
  Filter,
  Fingerprint,
  Info,
  Key,
  Layers,
  Lock,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Sparkles,
  Terminal,
  Zap,
} from "lucide-react";
import { api } from "@/lib/api";
import {
  ComplianceControl,
  ComplianceEvidenceRecord,
  ComplianceFramework,
  ComplianceGapAnalysis,
  CompliancePublicKey,
} from "@/lib/types";

type TabType = "overview" | "frameworks" | "controls" | "vault" | "gaps" | "exports";

export default function CompliancePage() {
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Core Data
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [evidenceList, setEvidenceList] = useState<ComplianceEvidenceRecord[]>([]);
  const [gaps, setGaps] = useState<ComplianceGapAnalysis | null>(null);
  const [publicKeyMeta, setPublicKeyMeta] = useState<CompliancePublicKey | null>(null);

  // Sub-states
  const [selectedFrameworkId, setSelectedFrameworkId] = useState<string>("dpdp-2023");
  const [selectedFrameworkDetail, setSelectedFrameworkDetail] = useState<ComplianceFramework | null>(null);
  const [selectedDomain, setSelectedDomain] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [expandedControlId, setExpandedControlId] = useState<string | null>(null);
  const [collecting, setCollecting] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportFormat, setExportFormat] = useState<"ZIP" | "JSON" | "CSV">("ZIP");
  const [copiedKey, setCopiedKey] = useState(false);
  const [verifiedArtifacts, setVerifiedArtifacts] = useState<Record<string, boolean>>({});

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [fwList, ctrlList, evList, gapData, keyMeta] = await Promise.all([
        api.getComplianceFrameworks().catch(() => []),
        api.getComplianceControls().catch(() => []),
        api.getComplianceEvidence().catch(() => []),
        api.getComplianceGaps().catch(() => null),
        api.getCompliancePublicKey().catch(() => null),
      ]);

      setFrameworks(fwList);
      setControls(ctrlList);
      setEvidenceList(evList);
      setGaps(gapData);
      setPublicKeyMeta(keyMeta);

      if (fwList.length > 0) {
        const initialFw = fwList.find((f) => f.id === "dpdp-2023") || fwList[0];
        setSelectedFrameworkId(initialFw.id);
        const detail = await api.getComplianceFramework(initialFw.id).catch(() => null);
        setSelectedFrameworkDetail(detail);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load compliance evidence data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSelectFramework = async (fwId: string) => {
    setSelectedFrameworkId(fwId);
    try {
      const detail = await api.getComplianceFramework(fwId);
      setSelectedFrameworkDetail(detail);
    } catch (err) {
      console.error(err);
    }
  };

  const handleTriggerCollection = async () => {
    try {
      setCollecting(true);
      await api.collectComplianceEvidence();
      await loadData();
    } catch (err: any) {
      alert("Evidence collection failed: " + (err?.message || err));
    } finally {
      setCollecting(false);
    }
  };

  const handleVerifyEvidence = async (evId: string) => {
    try {
      const res = await api.verifyComplianceEvidence(evId);
      setVerifiedArtifacts((prev) => ({ ...prev, [evId]: res.integrity_verified }));
    } catch (err) {
      console.error(err);
    }
  };

  const handleExport = async () => {
    try {
      setExporting(true);
      const res = await api.createComplianceExport({
        framework_id: selectedFrameworkId === "ALL" ? null : selectedFrameworkId,
        export_format: exportFormat,
      });
      window.open(`/api/backend${res.download_url}`, "_blank");
    } catch (err: any) {
      alert("Export failed: " + (err?.message || err));
    } finally {
      setExporting(false);
    }
  };

  // Metrics calculation
  const totalControls = controls.length;
  const verifiedCount = evidenceList.filter((e) => e.verification_status === "VERIFIED").length;
  const staleCount = evidenceList.filter((e) => e.freshness_status === "STALE" || e.freshness_status === "EXPIRED").length;
  const activeGapsCount = gaps?.total_gaps || 0;
  const criticalGapsCount = gaps?.critical_gaps || 0;

  // Filter controls
  const distinctDomains = Array.from(new Set(controls.map((c) => c.domain)));
  const filteredControls = controls.filter((c) => {
    const matchDomain = selectedDomain === "ALL" || c.domain === selectedDomain;
    const matchSearch =
      searchQuery === "" ||
      c.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.domain.toLowerCase().includes(searchQuery.toLowerCase());
    return matchDomain && matchSearch;
  });

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8 animate-fade-in">
      {/* Top Banner / Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <ClipboardCheck className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-display font-bold text-bone flex items-center gap-2">
                Compliance Evidence Engine
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-800/50 font-mono">
                  Stage 10.9
                </span>
              </h1>
              <p className="text-sm text-slate">
                Cryptographic evidence collection, statutory control mappings & tamper-evident export audit packages
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading || refreshing}
            className="px-3.5 py-2 rounded-lg bg-surface border border-border hover:bg-card text-xs font-mono text-slate hover:text-bone transition-all flex items-center gap-2 shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={handleTriggerCollection}
            disabled={collecting}
            className="px-4 py-2 rounded-lg bg-cyan-500/15 border border-cyan-500/40 hover:bg-cyan-500/25 text-xs font-mono font-medium text-cyan-300 transition-all flex items-center gap-2 shadow-sm"
          >
            <Zap className={`w-3.5 h-3.5 ${collecting ? "animate-pulse" : ""}`} />
            {collecting ? "Collecting Evidence..." : "Collect Live Evidence"}
          </button>
        </div>
      </div>

      {/* Prominent Legal Disclaimer Banner */}
      <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-3.5">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-amber-200/90 leading-relaxed">
          <span className="font-semibold text-amber-300">LEGAL COMPLIANCE & AUDIT DISCLAIMER:</span> PRIVGUARD AI
          provides cryptographically verifiable technical enforcement artifacts for its internal controls. Passing
          technical tests prove that the control functioned as designed; it does not constitute statutory legal
          certification, regulatory safe-harbor, or an independent third-party audit opinion. Formal compliance requires
          independent legal assessment by qualified counsel.
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-surface border border-border shadow-sm">
          <div className="text-xs text-slate font-mono uppercase tracking-wider mb-1">Standardized Controls</div>
          <div className="text-2xl font-bold font-display text-bone flex items-baseline gap-2">
            35
            <span className="text-xs text-slate font-mono font-normal">in 20 Domains</span>
          </div>
          <div className="text-[11px] text-emerald-400 mt-2 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> 100% Implemented in Baseline
          </div>
        </div>

        <div className="p-5 rounded-xl bg-surface border border-border shadow-sm">
          <div className="text-xs text-slate font-mono uppercase tracking-wider mb-1">Evidence Records</div>
          <div className="text-2xl font-bold font-display text-cyan-400 flex items-baseline gap-2">
            {evidenceList.length}
            <span className="text-xs text-slate font-mono font-normal">artifacts</span>
          </div>
          <div className="text-[11px] text-slate mt-2 flex items-center gap-1">
            <Fingerprint className="w-3 h-3 text-cyan-400" /> RFC 8785 Hashed
          </div>
        </div>

        <div className="p-5 rounded-xl bg-surface border border-border shadow-sm">
          <div className="text-xs text-slate font-mono uppercase tracking-wider mb-1">Assurance Freshness</div>
          <div className="text-2xl font-bold font-display text-emerald-400 flex items-baseline gap-2">
            {verifiedCount}
            <span className="text-xs text-amber-400 font-mono font-normal">({staleCount} stale)</span>
          </div>
          <div className="text-[11px] text-slate mt-2 flex items-center gap-1">
            <Activity className="w-3 h-3 text-emerald-400" /> 5-State Decoupled Model
          </div>
        </div>

        <div className="p-5 rounded-xl bg-surface border border-border shadow-sm">
          <div className="text-xs text-slate font-mono uppercase tracking-wider mb-1">Active Compliance Gaps</div>
          <div className="text-2xl font-bold font-display text-bone flex items-baseline gap-2">
            {activeGapsCount}
            {criticalGapsCount > 0 && (
              <span className="text-xs text-rose-400 font-mono font-normal">({criticalGapsCount} critical)</span>
            )}
          </div>
          <div className="text-[11px] text-slate mt-2 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3 text-amber-400" /> Remediation Actions Available
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="border-b border-border flex items-center gap-2 overflow-x-auto pb-px">
        {[
          { id: "overview", label: "Overview & Timelines", icon: LayoutDashboardIcon },
          { id: "frameworks", label: "Framework Explorer", icon: FileText },
          { id: "controls", label: "Control Library (35)", icon: ShieldCheck },
          { id: "vault", label: "Evidence Vault", icon: Database },
          { id: "gaps", label: "Gap Analysis", icon: AlertCircle },
          { id: "exports", label: "Export Center & Public Key", icon: Download },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as TabType)}
              className={`px-4 py-2.5 text-xs font-mono font-medium rounded-t-lg transition-all flex items-center gap-2 border-b-2 whitespace-nowrap ${
                isActive
                  ? "border-cyan-400 text-cyan-300 bg-cyan-950/20"
                  : "border-transparent text-slate hover:text-bone hover:border-slate/40"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB 1: OVERVIEW & TIMELINES */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Statutory Commencement Timelines Card */}
            <div className="p-6 rounded-xl bg-surface border border-border shadow-sm space-y-4">
              <h3 className="text-sm font-display font-semibold text-bone flex items-center gap-2">
                <ClockIcon className="w-4 h-4 text-cyan-400" />
                Statutory Commencement Schedules (Phased Modeling)
              </h3>
              <p className="text-xs text-slate">
                PRIVGUARD AI models section-level and rule-level commencement schedules independently:
              </p>

              <div className="space-y-3 pt-2">
                <div className="p-3 rounded-lg bg-card/60 border border-border/80 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-bone">India DPDP Rules, 2025</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                      3 Phased Milestones
                    </span>
                  </div>
                  <ul className="text-[11px] text-slate space-y-1 pt-1 font-mono">
                    <li>• 13 Nov 2025: Rules 1, 2, 17–21 (Inquiry & Preliminary) [COMMENCED]</li>
                    <li>• 13 Nov 2026: Rule 4 (Security Safeguards & Breach Reporting) [1 Year]</li>
                    <li>• 13 May 2027: Rules 3, 5–16, 22–23 (Notice & Consent Managers) [18 Months]</li>
                  </ul>
                </div>

                <div className="p-3 rounded-lg bg-card/60 border border-border/80 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-bone">EU AI Act (Regulation (EU) 2024/1689)</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                      6 Phased Milestones
                    </span>
                  </div>
                  <ul className="text-[11px] text-slate space-y-1 pt-1 font-mono">
                    <li>• 2 Feb 2025: Prohibitions (Art. 5) & AI Literacy [COMMENCED]</li>
                    <li>• 2 Aug 2025: GPAI Obligations & Systemic Risk [COMMENCED]</li>
                    <li>• 2 Aug 2026: General Provisions & Transparency (Art. 50) [COMMENCED]</li>
                    <li>• 2 Dec 2026: Harmonised Standards Technical Update [Pending]</li>
                    <li>• 2 Dec 2027: Annex III High-Risk AI Classification [Pending]</li>
                    <li>• 2 Aug 2028: Annex I Embedded Safety Components [Pending]</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Architecture Overview Card */}
            <div className="p-6 rounded-xl bg-surface border border-border shadow-sm space-y-4">
              <h3 className="text-sm font-display font-semibold text-bone flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                Five-State Assurance Separation Model
              </h3>
              <p className="text-xs text-slate leading-relaxed">
                Prevents misleading audit claims by separating whether software code is built from whether recent
                operational verification evidence is current:
              </p>

              <div className="space-y-2 text-xs font-mono pt-2">
                <div className="p-2.5 rounded bg-card/50 border border-border flex items-center justify-between">
                  <span className="text-slate">1. Implementation Status</span>
                  <span className="text-emerald-400 font-semibold">IMPLEMENTED</span>
                </div>
                <div className="p-2.5 rounded bg-card/50 border border-border flex items-center justify-between">
                  <span className="text-slate">2. Verification Status</span>
                  <span className="text-cyan-400 font-semibold">VERIFIED</span>
                </div>
                <div className="p-2.5 rounded bg-card/50 border border-border flex items-center justify-between">
                  <span className="text-slate">3. Evidence Freshness</span>
                  <span className="text-bone font-semibold">CURRENT / STALE</span>
                </div>
                <div className="p-2.5 rounded bg-card/50 border border-border flex items-center justify-between">
                  <span className="text-slate">4. Assurance Level</span>
                  <span className="text-emerald-400 font-semibold">HIGH / MEDIUM / LOW</span>
                </div>
                <div className="p-2.5 rounded bg-card/50 border border-border flex items-center justify-between">
                  <span className="text-slate">5. Applicability Decision</span>
                  <span className="text-purple-400 font-semibold">APPLICABLE</span>
                </div>
              </div>

              <div className="text-[11px] text-slate italic pt-1">
                * Semantic Invariant: Stale evidence reduces assurance to LOW, but preserves code implementation status.
              </div>
            </div>
          </div>

          {/* Registered Frameworks Cards */}
          <div className="space-y-4">
            <h3 className="text-sm font-display font-semibold text-bone">Registered Compliance Frameworks (7)</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {frameworks.map((fw) => (
                <div
                  key={fw.id}
                  onClick={() => {
                    handleSelectFramework(fw.id);
                    setActiveTab("frameworks");
                  }}
                  className="p-5 rounded-xl bg-surface border border-border hover:border-cyan-500/40 hover:bg-card/50 transition-all cursor-pointer group shadow-sm flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-card text-slate border border-border">
                        {fw.jurisdiction}
                      </span>
                      <span className="text-xs font-mono text-cyan-400 group-hover:translate-x-1 transition-transform">
                        Explore →
                      </span>
                    </div>
                    <h4 className="text-sm font-bold text-bone group-hover:text-cyan-300 transition-colors">
                      {fw.name}
                    </h4>
                    <p className="text-xs text-slate mt-1 line-clamp-2">{fw.description}</p>
                  </div>

                  <div className="mt-4 pt-3 border-t border-border/60 flex items-center justify-between text-xs font-mono text-slate">
                    <span>{fw.total_requirements} Clauses</span>
                    <span className="text-emerald-400">{fw.mapped_requirements} Mapped</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: FRAMEWORK EXPLORER */}
      {activeTab === "frameworks" && (
        <div className="space-y-6">
          {/* Framework Selector Pills */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2">
            {frameworks.map((fw) => (
              <button
                key={fw.id}
                onClick={() => handleSelectFramework(fw.id)}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all whitespace-nowrap ${
                  selectedFrameworkId === fw.id
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                    : "bg-surface border border-border text-slate hover:text-bone"
                }`}
              >
                {fw.name}
              </button>
            ))}
          </div>

          {selectedFrameworkDetail && (
            <div className="p-6 rounded-xl bg-surface border border-border shadow-sm space-y-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
                <div>
                  <h3 className="text-base font-display font-bold text-bone">{selectedFrameworkDetail.name}</h3>
                  <p className="text-xs text-slate mt-1">{selectedFrameworkDetail.description}</p>
                </div>
                <div className="text-xs font-mono text-slate flex items-center gap-4">
                  <div>
                    Authority: <span className="text-bone">{selectedFrameworkDetail.authority}</span>
                  </div>
                  <div>
                    Reference: <span className="text-cyan-400">{selectedFrameworkDetail.official_reference}</span>
                  </div>
                </div>
              </div>

              {/* Requirements Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-border text-slate">
                      <th className="pb-3 font-semibold">Identifier</th>
                      <th className="pb-3 font-semibold">Title</th>
                      <th className="pb-3 font-semibold">Domain</th>
                      <th className="pb-3 font-semibold">Commencement Status</th>
                      <th className="pb-3 font-semibold">Phase / Date</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {selectedFrameworkDetail.requirements?.map((req) => (
                      <tr key={req.id} className="hover:bg-card/40 transition-colors">
                        <td className="py-3 font-bold text-cyan-400">{req.identifier}</td>
                        <td className="py-3 text-bone font-sans font-medium">
                          <div>{req.title}</div>
                          <div className="text-[11px] text-slate mt-0.5">{req.description}</div>
                        </td>
                        <td className="py-3 text-slate">{req.domain}</td>
                        <td className="py-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                              req.commencement_status === "COMMENCED"
                                ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/40"
                                : "bg-amber-950/60 text-amber-400 border-amber-800/40"
                            }`}
                          >
                            {req.commencement_status}
                          </span>
                        </td>
                        <td className="py-3 text-slate">
                          {req.commencement_date
                            ? new Date(req.commencement_date).toLocaleDateString()
                            : req.phase_category || "Enacted"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: CONTROL LIBRARY (35) */}
      {activeTab === "controls" && (
        <div className="space-y-6">
          {/* Controls Filter Bar */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-xl bg-surface border border-border">
            <div className="flex items-center gap-3 flex-1">
              <div className="relative flex-1 max-w-sm">
                <Search className="w-3.5 h-3.5 text-slate absolute left-3 top-3" />
                <input
                  type="text"
                  placeholder="Search controls by ID, title, domain..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-card border border-border text-xs text-bone placeholder:text-slate focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <select
                value={selectedDomain}
                onChange={(e) => setSelectedDomain(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-card border border-border text-xs text-bone font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Domains ({distinctDomains.length})</option>
                {distinctDomains.map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>
            </div>

            <div className="text-xs font-mono text-slate">
              Showing {filteredControls.length} of {totalControls} Controls
            </div>
          </div>

          {/* Controls List */}
          <div className="space-y-3">
            {filteredControls.map((ctrl) => {
              const isExpanded = expandedControlId === ctrl.id;
              return (
                <div
                  key={ctrl.id}
                  className="rounded-xl bg-surface border border-border hover:border-border/80 transition-all overflow-hidden"
                >
                  <div
                    onClick={() => setExpandedControlId(isExpanded ? null : ctrl.id)}
                    className="p-4 flex items-center justify-between cursor-pointer select-none"
                  >
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950/60 px-2 py-1 rounded border border-cyan-800/40">
                        {ctrl.id}
                      </span>
                      <div>
                        <h4 className="text-sm font-semibold text-bone font-sans">{ctrl.title}</h4>
                        <div className="text-[11px] text-slate font-mono mt-0.5">{ctrl.domain}</div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/40">
                        {ctrl.implementation_status}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-card text-slate border border-border">
                        {ctrl.criticality}
                      </span>
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-slate" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-slate" />
                      )}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="p-4 bg-card/40 border-t border-border/60 text-xs space-y-4">
                      <div>
                        <span className="font-mono text-slate text-[11px]">DESCRIPTION:</span>
                        <p className="text-bone text-xs mt-1 font-sans">{ctrl.description}</p>
                      </div>

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-[11px] font-mono">
                        <div>
                          <span className="text-slate">Owner Role:</span>{" "}
                          <span className="text-bone">{ctrl.owner_role}</span>
                        </div>
                        <div>
                          <span className="text-slate">Verification:</span>{" "}
                          <span className="text-cyan-400">{ctrl.verification_method}</span>
                        </div>
                        <div>
                          <span className="text-slate">Review Frequency:</span>{" "}
                          <span className="text-bone">{ctrl.review_frequency_days} days</span>
                        </div>
                        <div>
                          <span className="text-slate">Version:</span>{" "}
                          <span className="text-bone">{ctrl.version}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 4: EVIDENCE VAULT */}
      {activeTab === "vault" && (
        <div className="space-y-6">
          <div className="p-6 rounded-xl bg-surface border border-border shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-display font-bold text-bone">Cryptographic Evidence Vault</h3>
                <p className="text-xs text-slate mt-1">
                  RFC 8785 canonical JSON fingerprints and Ed25519-signed verification artifacts
                </p>
              </div>
              <div className="text-xs font-mono text-slate">
                Total Artifacts: <span className="text-bone">{evidenceList.length}</span>
              </div>
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-border text-slate">
                    <th className="pb-3 font-semibold">Evidence ID</th>
                    <th className="pb-3 font-semibold">Control ID</th>
                    <th className="pb-3 font-semibold">Collector</th>
                    <th className="pb-3 font-semibold">SHA-256 Hash</th>
                    <th className="pb-3 font-semibold">Status</th>
                    <th className="pb-3 font-semibold">Freshness</th>
                    <th className="pb-3 font-semibold">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {evidenceList.map((ev) => (
                    <tr key={ev.id} className="hover:bg-card/40 transition-colors">
                      <td className="py-3 font-bold text-bone">{ev.id}</td>
                      <td className="py-3 text-cyan-400">{ev.control_id}</td>
                      <td className="py-3 text-slate">{ev.collector_name}</td>
                      <td className="py-3 text-slate" title={ev.artifact_hash_sha256}>
                        {ev.artifact_hash_sha256.substring(0, 12)}...
                      </td>
                      <td className="py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/40">
                          {ev.verification_status}
                        </span>
                      </td>
                      <td className="py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                            ev.freshness_status === "CURRENT"
                              ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/40"
                              : "bg-amber-950/60 text-amber-400 border-amber-800/40"
                          }`}
                        >
                          {ev.freshness_status}
                        </span>
                      </td>
                      <td className="py-3">
                        <button
                          onClick={() => handleVerifyEvidence(ev.id)}
                          className="px-2.5 py-1 rounded bg-card hover:bg-surface border border-border text-[11px] text-cyan-300 transition-colors flex items-center gap-1.5"
                        >
                          <Fingerprint className="w-3 h-3" />
                          {verifiedArtifacts[ev.id] ? "Verified ✓" : "Verify Digest"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: GAP ANALYSIS */}
      {activeTab === "gaps" && (
        <div className="space-y-6">
          <div className="p-6 rounded-xl bg-surface border border-border shadow-sm space-y-4">
            <h3 className="text-base font-display font-bold text-bone">Actionable Compliance Gaps</h3>
            <p className="text-xs text-slate">
              Discovers unmapped clauses, missing evidence, failed tests, and stale artifacts across statutory requirements:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              {gaps?.items.map((gap, idx) => (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border space-y-2 ${
                    gap.severity === "CRITICAL"
                      ? "bg-rose-950/20 border-rose-800/40"
                      : gap.severity === "HIGH"
                      ? "bg-amber-950/20 border-amber-800/40"
                      : "bg-surface border-border"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-card border border-border text-slate">
                      {gap.gap_type}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        gap.severity === "CRITICAL"
                          ? "text-rose-400 bg-rose-950/60"
                          : gap.severity === "HIGH"
                          ? "text-amber-400 bg-amber-950/60"
                          : "text-slate bg-card"
                      }`}
                    >
                      {gap.severity}
                    </span>
                  </div>

                  <h4 className="text-xs font-semibold text-bone font-sans">{gap.title}</h4>
                  <p className="text-[11px] text-slate">{gap.description}</p>

                  <div className="p-2.5 rounded bg-card/60 border border-border/80 text-[11px] font-mono text-cyan-300">
                    <span className="text-slate font-sans">REMEDIATION:</span> {gap.remediation_action}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: EXPORT CENTER & PUBLIC KEY */}
      {activeTab === "exports" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Package Generator */}
            <div className="p-6 rounded-xl bg-surface border border-border shadow-sm space-y-4">
              <h3 className="text-base font-display font-bold text-bone flex items-center gap-2">
                <Download className="w-4 h-4 text-cyan-400" />
                Generate Audit Evidence Package
              </h3>
              <p className="text-xs text-slate">
                Generates a cryptographically signed archive with RFC 8785 canonical digests, Ed25519 signature,
                and standalone verification instructions for third-party auditors.
              </p>

              <div className="space-y-3 pt-2">
                <div>
                  <label className="text-[11px] font-mono text-slate block mb-1">Target Framework Scope:</label>
                  <select
                    value={selectedFrameworkId}
                    onChange={(e) => setSelectedFrameworkId(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-card border border-border text-xs text-bone font-mono focus:outline-none focus:border-cyan-500"
                  >
                    <option value="ALL">All Registered Frameworks</option>
                    {frameworks.map((f) => (
                      <option key={f.id} value={f.id}>
                        {f.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="text-[11px] font-mono text-slate block mb-1">Export Format:</label>
                  <div className="grid grid-cols-3 gap-2">
                    {(["ZIP", "JSON", "CSV"] as const).map((fmt) => (
                      <button
                        key={fmt}
                        onClick={() => setExportFormat(fmt)}
                        className={`py-2 rounded-lg text-xs font-mono border transition-all ${
                          exportFormat === fmt
                            ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/50"
                            : "bg-card border-border text-slate hover:text-bone"
                        }`}
                      >
                        {fmt}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    onClick={handleExport}
                    disabled={exporting}
                    className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all shadow-md flex items-center justify-center gap-2"
                  >
                    <Download className={`w-4 h-4 ${exporting ? "animate-bounce" : ""}`} />
                    {exporting ? "Packaging & Signing..." : `Download Signed ${exportFormat} Package`}
                  </button>
                </div>
              </div>
            </div>

            {/* Public Verification Key Card */}
            <div className="p-6 rounded-xl bg-surface border border-border shadow-sm space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-base font-display font-bold text-bone flex items-center gap-2">
                  <Key className="w-4 h-4 text-emerald-400" />
                  Public Evidence Verification Key
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                  Unauthenticated Public Endpoint
                </span>
              </div>
              <p className="text-xs text-slate">
                External auditors verify manifest signatures independently using this Ed25519 SubjectPublicKeyInfo PEM:
              </p>

              {publicKeyMeta && (
                <div className="space-y-2 text-xs font-mono">
                  <div className="p-2.5 rounded bg-card/60 border border-border flex items-center justify-between">
                    <span className="text-slate">Key ID (kid):</span>
                    <span className="text-cyan-400 font-bold">{publicKeyMeta.kid}</span>
                  </div>
                  <div className="p-2.5 rounded bg-card/60 border border-border flex items-center justify-between">
                    <span className="text-slate">Algorithm:</span>
                    <span className="text-bone">{publicKeyMeta.algorithm}</span>
                  </div>
                  <div className="p-2.5 rounded bg-card/60 border border-border">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-slate">Public Key PEM:</span>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(publicKeyMeta.public_key_pem);
                          setCopiedKey(true);
                          setTimeout(() => setCopiedKey(false), 2000);
                        }}
                        className="text-[10px] text-cyan-300 hover:text-cyan-200 flex items-center gap-1"
                      >
                        <Copy className="w-3 h-3" />
                        {copiedKey ? "Copied!" : "Copy PEM"}
                      </button>
                    </div>
                    <pre className="text-[10px] text-slate/80 overflow-x-auto p-2 bg-surface rounded border border-border/60">
                      {publicKeyMeta.public_key_pem}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function LayoutDashboardIcon(props: any) {
  return <Layers {...props} />;
}

function ClockIcon(props: any) {
  return <Activity {...props} />;
}

