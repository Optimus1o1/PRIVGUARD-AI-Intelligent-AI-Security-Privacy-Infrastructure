# PRIVGUARD AI — Phase 1 MVP Known Limitations & Boundary Disclosures

**Document ID**: DOC-PHASE1-LIMIT-001  
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Developer**: ANIKET NANDI (Kolkata, IST)  
**Version**: 1.0.0-rc1  
**Execution Date**: 2026-11-08

---

## 1. Purpose of Boundary Disclosures

Trust in security software requires full transparency about what the system can and cannot guarantee. This document outlines the technical boundaries, heuristic constraints, and intentional trade-offs in **PRIVGUARD AI Phase 1 MVP**.

---

## 2. Sensitive Data & Secret Detection Limits

### 2.1 Regex-Based PII Scanners
- **Supported Patterns**: Email addresses (RFC 5322), E.164 and standard North American/Indian phone numbers, SSNs, credit card PANs (with Luhn check), IPv4/IPv6 addresses.
- **Limitation**: Unconventional, obfuscated, or spaced PII (e.g. `u s e r [at] e x a m p l e . c o m` or phonetic transcriptions like "nine eight seven six...") may evade simple regex matching.
- **Future Roadmap (Phase 3)**: Semantic NER (Named Entity Recognition) embedding models will augment regexes to capture informal and spaced PII.

### 2.2 Shannon Entropy Heuristics for Secrets
- **Threshold**: Shannon entropy $H \ge 3.8$ across strings of length $\ge 20$.
- **Known False Positives**: Long random hashes (e.g. Git commit SHAs, UUID strings, base64 encoded binary chunks) can trigger high-entropy alerts.
- **Known False Negatives**: Short low-entropy credentials (e.g. `password123`, `admin`) are not detected by entropy scanners and must be covered by dictionary lookup rules.

---

## 3. Prompt Injection Detection Limits

### 3.1 Known Structural Patterns
- **Detected Vectors**: Direct instruction overrides (`Ignore all prior instructions`, `System prompt override`), delimiter injections (`---`, `<system>`, ````json`), and extraction commands.
- **Limitation**: Multi-turn indirect prompt injections distributed across lengthy conversation histories, cipher-based evasions (Base64/ROT13 encoding), or translation into low-resource human languages may bypass structural heuristics.
- **Mitigation in Place**: Server-side tool execution boundaries (`ToolBroker`) and output response inspection prevent an exploited model from causing unauthorized state changes, providing defense-in-depth even if prompt injection succeeds in changing model behavior.
- **Future Roadmap (Phase 2)**: Context-aware semantic threat analysis and runtime taint tracking across agent steps.

---

## 4. Agent Tool Security Boundaries

### 4.1 Phase 1 Demonstration Tools
- **Built-in Harmless Tools**: `calculator`, `lookup_file_metadata`, `search_mock_kb`.
- **Limitation**: These tools are demonstration-safe and run in sandboxed in-memory/read-only contexts. They do not execute external arbitrary code, execute SQL migrations, or communicate across network boundaries.
- **Enforcement Boundary**: The `ToolBroker` strictly enforces capability tokens and parameters schema. However, if a custom tool implementation outside PRIVGUARD contains internal logic vulnerabilities, PRIVGUARD can only enforce authorization and schema conformance, not arbitrary third-party code soundness.

---

## 5. Storage & Deployment Modes

### 5.1 Standalone SQLite Local Mode vs Distributed PostgreSQL
- **Default Local Mode**: For quick developer onboarding, PRIVGUARD runs with SQLite (`aiosqlite`) and in-memory mock caching. SQLite is suitable for single-node development and verification.
- **Concurrency Limitation**: SQLite does not support high-concurrency multi-worker writes and will experience table locks under heavy stress.
- **Production Mode**: Full enterprise production deployments require PostgreSQL 16+ and Redis 7+ as documented in `docs/phase_1_local_deployment.md`.

### 5.2 Disaster Recovery Replay vs Full Snapshot Restore
- **Local Ledger Replay**: Takes 0.0911 seconds to verify cryptographic signatures and replay journals.
- **Full Database Snapshot Restore**: For large datasets, standard network and disk I/O requires 5–15 minutes. Enterprise RTO and RTO metrics remain marked as `PENDING_OWNER_APPROVAL`.

---

## 6. Summary: Phase 1 vs Future Phases

| Capability | Phase 1 MVP (Current) | Phase 2 (Agent Security) | Phase 3 (Privacy Infrastructure) |
|---|---|---|---|
| **PII Detection** | Regex + Luhn check | Multi-step agent scrubbing | On-device SLM / NER models |
| **Secret Detection** | Pattern + Shannon Entropy | Ephemeral token rotation | Multi-cloud HSM / KMS integration |
| **Prompt Injection** | Delimiter & Pattern Heuristics | Dynamic taint tracking | Semantic intent vector classifiers |
| **Tool Execution** | Capability tokens (HMAC) | Multi-agent delegation mesh | Distributed MPC tool signing |
| **Activity Logging** | Content-free metadata logs | Agent session graph visualizer | Zero-Knowledge proof compliance |
| **Deployment** | Local Docker / SQLite | Kubernetes Helm multi-node | Global edge gateway distribution |

---

## 7. Sign-Off
All limitations documented above are understood, categorized, and accepted for the Phase 1 MVP baseline.

