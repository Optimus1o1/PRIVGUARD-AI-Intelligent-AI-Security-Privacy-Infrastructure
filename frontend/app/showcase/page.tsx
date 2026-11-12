"use client";

import React from "react";
import Link from "next/link";
import {
  Shield,
  ShieldCheck,
  Lock,
  Wrench,
  FileText,
  Sliders,
  Terminal,
  Zap,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Layers,
  Sparkles,
} from "lucide-react";

export default function ShowcasePage() {
  return (
    <div className="space-y-12 max-w-6xl mx-auto pb-16">
      {/* Hero Section */}
      <section className="text-center space-y-6 pt-8 pb-4">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold tracking-wide uppercase">
          <Sparkles className="w-3.5 h-3.5" />
          Startup Buildathon India 2026 Submission
        </div>

        <h1 className="text-4xl md:text-5xl lg:text-6xl font-extrabold text-white tracking-tight leading-tight">
          The Independent Security Layer <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400">
            For AI Applications.
          </span>
        </h1>

        <p className="text-lg md:text-xl text-slate-300 max-w-3xl mx-auto font-light leading-relaxed">
          Secure every prompt. Govern every tool. Protect every interaction. <br />
          PRIVGUARD decouples security and privacy policy enforcement from generative models, eliminating the fallacy of LLM self-governance.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
          <Link
            href="/"
            className="flex items-center gap-2 px-6 py-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-sm transition-all shadow-lg shadow-cyan-900/30 hover:shadow-cyan-800/40"
          >
            Explore Executive Dashboard
            <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            href="/playground"
            className="flex items-center gap-2 px-6 py-3 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 font-semibold text-sm transition-colors"
          >
            <Terminal className="w-4 h-4 text-cyan-400" />
            Run Security Playground
          </Link>
        </div>
      </section>

      {/* The Core Problem */}
      <section className="bg-slate-900/60 border border-slate-800 rounded-2xl p-8 space-y-6">
        <div className="max-w-2xl">
          <h2 className="text-xs font-mono uppercase tracking-wider text-red-400 font-bold mb-1">
            The Fundamental Flaw
          </h2>
          <h3 className="text-2xl font-bold text-white">Why AI Security is Currently Broken</h3>
          <p className="text-sm text-slate-300 mt-2">
            Most teams rely on soft system prompts or fine-tuned safeguards to enforce security. But language models are probabilistic text generators—they cannot serve as their own security kernels.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div className="bg-slate-950/80 border border-slate-800/80 p-5 rounded-xl space-y-2">
            <div className="w-8 h-8 rounded-lg bg-red-500/10 text-red-400 flex items-center justify-center font-bold">
              1
            </div>
            <h4 className="font-semibold text-white text-sm">Data Ingress Exposure</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Customer emails, phone numbers, and cloud secrets are transmitted raw across public model provider APIs, triggering severe DPDP & GDPR compliance risks.
            </p>
          </div>

          <div className="bg-slate-950/80 border border-slate-800/80 p-5 rounded-xl space-y-2">
            <div className="w-8 h-8 rounded-lg bg-red-500/10 text-red-400 flex items-center justify-center font-bold">
              2
            </div>
            <h4 className="font-semibold text-white text-sm">Adversarial Hijacking</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Direct instruction overrides and prompt injections force models to ignore developer constraints, dump internal reasoning, and extract system secrets.
            </p>
          </div>

          <div className="bg-slate-950/80 border border-slate-800/80 p-5 rounded-xl space-y-2">
            <div className="w-8 h-8 rounded-lg bg-red-500/10 text-red-400 flex items-center justify-center font-bold">
              3
            </div>
            <h4 className="font-semibold text-white text-sm">Ungoverned Agent Tools</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Autonomous agents invoke tools without independent authorization. Compromised agents can trigger destructive database or code execution APIs.
            </p>
          </div>
        </div>
      </section>

      {/* The Five Capabilities */}
      <section className="space-y-6">
        <div className="text-center max-w-2xl mx-auto">
          <h2 className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold mb-1">
            Proven Architecture
          </h2>
          <h3 className="text-2xl font-bold text-white">Five Delivered Phase 1 Capabilities</h3>
          <p className="text-sm text-slate-400 mt-1">
            Fully implemented, deployment-qualified, and verified with 438+ automated tests.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {/* Card 1 */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-3 hover:border-cyan-500/40 transition-colors">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center">
              <Lock className="w-5 h-5" />
            </div>
            <h4 className="text-base font-semibold text-white">Sensitive Data Protection</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Presidio and heuristic scanners tokenize PII and credentials into indexed placeholders before socket transmission. Values are restored seamlessly upon client return.
            </p>
            <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Socket Boundary Verified
            </div>
          </div>

          {/* Card 2 */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-3 hover:border-red-500/40 transition-colors">
            <div className="w-10 h-10 rounded-lg bg-red-500/10 text-red-400 flex items-center justify-center">
              <Shield className="w-5 h-5" />
            </div>
            <h4 className="text-base font-semibold text-white">Prompt Injection Defense</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Multi-layer heuristic and signature engine intercepts adversarial overrides, jailbreaks, and zero-width obfuscation fail-closed before model execution.
            </p>
            <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Fail-Closed Quarantine
            </div>
          </div>

          {/* Card 3 */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-3 hover:border-amber-500/40 transition-colors">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 text-amber-400 flex items-center justify-center">
              <Wrench className="w-5 h-5" />
            </div>
            <h4 className="text-base font-semibold text-white">Server-Side Tool Authorization</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Autonomous agents must present single-use, task-scoped, HMAC-signed capability tokens. Stolen or replayed grants are rejected out-of-band.
            </p>
            <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Cryptographic Grants
            </div>
          </div>

          {/* Card 4 */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-3 hover:border-teal-500/40 transition-colors">
            <div className="w-10 h-10 rounded-lg bg-teal-500/10 text-teal-400 flex items-center justify-center">
              <FileText className="w-5 h-5" />
            </div>
            <h4 className="text-base font-semibold text-white">Content-Free Activity Logs</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Full forensic audibility via keyed HMAC-SHA256 content fingerprints. Raw prompts and secrets are never stored to disk, eliminating secondary database breaches.
            </p>
            <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> DPDP &amp; GDPR Compliant
            </div>
          </div>

          {/* Card 5 */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-3 hover:border-indigo-500/40 transition-colors">
            <div className="w-10 h-10 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center">
              <Sliders className="w-5 h-5" />
            </div>
            <h4 className="text-base font-semibold text-white">Policy Control Center</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Configure deterministic policies across data classifications (ALLOW, REDACT, BLOCK). Includes dry-run simulation and immediate rule validation.
            </p>
            <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Live Rule Simulator
            </div>
          </div>

          {/* Card 6: Local-First */}
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-3 hover:border-emerald-500/40 transition-colors">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center">
              <Cpu className="w-5 h-5" />
            </div>
            <h4 className="text-base font-semibold text-white">Local-First Deployment</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Zero-dependency local execution with SQLite (WAL) and Ollama, or scalable enterprise deployment with PostgreSQL, Redis, and cloud foundation models.
            </p>
            <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Zero Data Egress
            </div>
          </div>
        </div>
      </section>

      {/* Strategic Roadmap */}
      <section className="bg-slate-900/40 border border-slate-800 rounded-2xl p-8 space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold mb-1">
              Product Roadmap
            </h2>
            <h3 className="text-xl font-bold text-white">The Three-Phase Vision</h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Phase 1 Qualified on Commit 4e10caf
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl bg-slate-950 border border-emerald-500/40 relative">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-emerald-400 uppercase font-mono">Phase 1</span>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-500/20 text-emerald-300">
                COMPLETED MVP
              </span>
            </div>
            <h4 className="font-semibold text-white text-sm mb-1">Local-First Security Gateway</h4>
            <p className="text-xs text-slate-400">
              Core proxy, reversible PII tokenization, prompt injection defense, capability tokens, and forensic audit.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 opacity-80">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slate-400 uppercase font-mono">Phase 2</span>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-slate-800 text-slate-300">
                PLANNED EXPANSION
              </span>
            </div>
            <h4 className="font-semibold text-white text-sm mb-1">Agent Security Mesh</h4>
            <p className="text-xs text-slate-400">
              Distributed capability propagation, multi-hop runtime taint tracking, and human-in-the-loop approval escalation.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 opacity-80">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slate-400 uppercase font-mono">Phase 3</span>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-slate-800 text-slate-300">
                LONG-TERM
              </span>
            </div>
            <h4 className="font-semibold text-white text-sm mb-1">Privacy Infrastructure</h4>
            <p className="text-xs text-slate-400">
              Verifiable confidential computing enclaves, zero-knowledge redaction proofs, and autonomous compliance synthesis.
            </p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="text-center pt-8 border-t border-slate-800 space-y-2">
        <div className="text-sm font-semibold text-slate-300">
          Moon Sanctum Labs — <span className="text-cyan-400">Decode. Build. Evolve.</span>
        </div>
        <p className="text-xs text-slate-500">
          PRIVGUARD AI is engineered by Aniket Nandi (Kolkata, India) for Startup Buildathon India 2026.
        </p>
      </footer>
    </div>
  );
}

