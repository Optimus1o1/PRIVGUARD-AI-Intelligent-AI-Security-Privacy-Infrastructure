"use client";

import { useState } from "react";
import {
  Settings as SettingsIcon,
  Shield,
  KeyRound,
  Server,
  Lock,
  Clock,
  Terminal,
  Save,
  CheckCircle2,
  Info,
} from "lucide-react";

export default function SettingsPage() {
  const [approvalTimeout, setApprovalTimeout] = useState(300);
  const [failClosed, setFailClosed] = useState(true);
  const [upstreamModel, setUpstreamModel] = useState("gpt-4o-mini");
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="space-y-8 max-w-4xl">
      {/* Top Banner */}
      <div className="border-b border-cyber-border/40 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyber-surface border border-cyber-border text-cyber-slate">
            <SettingsIcon className="w-5 h-5 text-cyber-ink" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono text-cyber-ink tracking-tight flex items-center gap-2">
              GATEWAY_CONFIG & SECURITY_DEFAULTS
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyber-surface border border-cyber-border text-cyber-slate font-sans font-normal">
                BFF Server-Enforced
              </span>
            </h1>
            <p className="text-sm text-cyber-slate">
              Configure upstream provider routing, human approval timeouts, and local security thresholds
            </p>
          </div>
        </div>
      </div>

      {saved && (
        <div className="p-4 rounded-xl bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald text-xs font-mono flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>Settings saved. Note: Production secret keys must be updated via environment variables (.env).</span>
        </div>
      )}

      {/* Backend-For-Frontend Security Info */}
      <div className="p-4 rounded-xl border border-cyber-cyan/30 bg-cyber-cyan/5 flex items-start gap-3">
        <Lock className="w-5 h-5 text-cyber-cyan shrink-0 mt-0.5" />
        <div className="text-xs space-y-1">
          <div className="font-bold font-mono text-cyber-ink">ZERO-LEAK CREDENTIAL ARCHITECTURE</div>
          <div className="text-cyber-slate">
            All upstream LLM API credentials and database connection strings are secured on the PRIVGUARD backend server.
            The frontend control plane communicates via an authenticated Backend-for-Frontend (BFF) proxy route,
            guaranteeing no private API keys are ever transmitted to or stored in the browser.
          </div>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Upstream LLM Configuration */}
        <div className="p-6 rounded-xl border border-cyber-border bg-cyber-card space-y-4">
          <div className="flex items-center gap-2 text-cyber-ink font-mono text-sm font-bold border-b border-cyber-border/40 pb-3">
            <Server className="w-4 h-4 text-cyber-cyan" />
            <span>UPSTREAM LLM PROVIDER & GATEWAY ROUTING</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-cyber-slate uppercase mb-1">
                Active Upstream Gateway
              </label>
              <input
                type="text"
                disabled
                value="http://127.0.0.1:8000/v1"
                className="w-full p-2.5 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-slate opacity-75 cursor-not-allowed"
              />
              <span className="text-[10px] text-cyber-slate mt-1 block">Local PRIVGUARD inspection reverse proxy</span>
            </div>

            <div>
              <label className="block text-xs font-mono text-cyber-slate uppercase mb-1">
                Default Target Model
              </label>
              <select
                value={upstreamModel}
                onChange={(e) => setUpstreamModel(e.target.value)}
                className="w-full p-2.5 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink focus:outline-none focus:border-cyber-cyan"
              >
                <option value="gpt-4o">gpt-4o</option>
                <option value="gpt-4o-mini">gpt-4o-mini</option>
                <option value="claude-3-5-sonnet-20241022">claude-3-5-sonnet</option>
                <option value="gemini-1.5-pro">gemini-1.5-pro</option>
              </select>
              <span className="text-[10px] text-cyber-slate mt-1 block">Configured upstream target alias</span>
            </div>
          </div>
        </div>

        {/* HITL & Broker Policies */}
        <div className="p-6 rounded-xl border border-cyber-border bg-cyber-card space-y-4">
          <div className="flex items-center gap-2 text-cyber-ink font-mono text-sm font-bold border-b border-cyber-border/40 pb-3">
            <Shield className="w-4 h-4 text-cyber-cyan" />
            <span>AGENT BROKER & HUMAN-IN-THE-LOOP (HITL) CONTROLS</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-cyber-slate uppercase mb-1">
                Approval Request Timeout (Seconds)
              </label>
              <div className="relative">
                <Clock className="w-3.5 h-3.5 absolute left-3 top-3 text-cyber-slate" />
                <input
                  type="number"
                  min={30}
                  max={3600}
                  value={approvalTimeout}
                  onChange={(e) => setApprovalTimeout(Number(e.target.value))}
                  className="w-full pl-9 pr-3 py-2 rounded-lg border border-cyber-border bg-cyber-surface text-xs font-mono text-cyber-ink focus:outline-none focus:border-cyber-cyan"
                />
              </div>
              <span className="text-[10px] text-cyber-slate mt-1 block">Default: 300s (5 minutes). Requests expire automatically if unapproved.</span>
            </div>

            <div>
              <label className="block text-xs font-mono text-cyber-slate uppercase mb-1">
                Fail-Closed Mode
              </label>
              <div className="flex items-center gap-3 p-2.5 rounded-lg border border-cyber-border bg-cyber-surface">
                <input
                  type="checkbox"
                  id="failClosedToggle"
                  checked={failClosed}
                  onChange={(e) => setFailClosed(e.target.checked)}
                  className="rounded border-cyber-border text-cyber-cyan focus:ring-0"
                />
                <label htmlFor="failClosedToggle" className="text-xs font-mono text-cyber-ink cursor-pointer">
                  Always Deny on Engine Anomaly (Strict Enforcement)
                </label>
              </div>
              <span className="text-[10px] text-cyber-slate mt-1 block">Mandatory for OWASP 2026 security compliance</span>
            </div>
          </div>
        </div>

        {/* Agency Identity & Metadata */}
        <div className="p-6 rounded-xl border border-cyber-border bg-cyber-card space-y-3">
          <div className="flex items-center justify-between border-b border-cyber-border/40 pb-3">
            <div className="font-mono text-xs font-bold text-cyber-slate uppercase tracking-wider">
              Product Identity & Architecture
            </div>
            <span className="text-xs font-mono text-cyber-cyan">Moon Sanctum Labs</span>
          </div>
          <div className="text-xs text-cyber-slate leading-relaxed">
            <p className="font-mono text-cyber-ink font-semibold">
              PRIVGUARD AI — <span className="text-copper italic">Decode. Build. Evolve.</span>
            </p>
            <p className="mt-1">
              Engineered by lead full-stack developer and designer at Moon Sanctum Labs with Aniket Nandi (Kolkata, IST).
              Designed for local-first, developer-first autonomous AI security, prompt injection defense, and agent capability brokering.
            </p>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            className="px-5 py-2.5 rounded-lg bg-cyber-cyan text-cyber-bg font-mono font-bold text-xs hover:bg-cyan-300 transition-colors flex items-center gap-2"
          >
            <Save className="w-3.5 h-3.5" />
            Save Configuration Changes
          </button>
        </div>
      </form>
    </div>
  );
}
