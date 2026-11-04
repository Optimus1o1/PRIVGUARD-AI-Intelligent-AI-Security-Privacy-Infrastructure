# PRIVGUARD AI — Known Limitations & Architectural Boundaries
**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Author:** ANIKET NANDI (Kolkata, IST)

---

## 1. Purpose & Transparency Principles

In alignment with our agency philosophy at Moon Sanctum Labs (*Decode. Build. Evolve.*), security products must be explicitly honest about what they protect and where current operational boundaries lie. This document outlines the documented technical boundaries and known constraints of PRIVGUARD AI as of **v0.1 (Stage 6 Validation)**.

---

## 2. Documented Architectural Boundaries

### 2.1 Code Execution Sandboxing
- **Current State:** The `execute_code` tool is disabled by default in v0.1 (`TOOL_DISABLED`).
- **Limitation:** In-process Python execution sandboxing cannot guarantee kernel isolation against zero-day syscall escapes or resource exhaustion (fork bombs).
- **Evolution Path:** Stage 7+ will introduce a dedicated containerized microVM or gVisor sandbox runner communicating over an isolated gRPC socket.

### 2.2 In-Memory Taint Tracking
- **Current State:** The `ExfiltrationDetector` records active taints in SQLite (`ActiveTaint` table) and maintains an in-memory session cache for fast lookup.
- **Limitation:** In a multi-replica or auto-scaling container environment, in-memory caches across distinct backend nodes must be synchronized to prevent taint evasion if subsequent tool calls land on different nodes.
- **Evolution Path:** Synchronize active task taints via Redis Pub/Sub or distributed key-value storage.

### 2.3 Single-Node Database Concurrency
- **Current State:** The local development and test environment runs SQLite in WAL mode with `NullPool`.
- **Limitation:** SQLite enforces a single file-level write lock. Under heavy concurrent load (>100 clients), write queues will experience elevated P95 latency (1–3 seconds).
- **Evolution Path:** Deploy PRIVGUARD AI against a distributed PostgreSQL instance (Supabase, Neon, or AWS RDS) with PgBouncer connection pooling.

### 2.4 Prompt Injection Regex & Heuristic Boundaries
- **Current State:** Detection combines NFKC Unicode normalization, zero-width character stripping, base64 payload extraction, and high-precision regex signatures for direct, indirect, jailbreak, and delimiter overrides.
- **Limitation:** Novel syntactic obfuscation, semantic evasion (e.g. complex multilingual metaphor or steganographic ciphers), or emerging adversarial jailbreak prompts can theoretically bypass purely deterministic pattern matching without a secondary small language model (SLM) classification pass.
- **Evolution Path:** Integrate an on-premise lightweight transformer classifier (e.g. Llama Guard 3 or ProtectAI DeBERTa) as an asynchronous secondary consensus layer alongside deterministic rules.

### 2.5 Buffer-Before-Stream Latency Invariant
- **Current State:** To guarantee zero token leakage when an upstream model begins outputting credentials, PRIVGUARD buffers the upstream stream until completion before streaming verified SSE chunks to the client.
- **Limitation:** The first chunk latency (Time-to-First-Token / TTFT) for streaming responses is bound by the total generation time of the upstream model.
- **Evolution Path:** Implement a sliding window token buffer (e.g. 32–64 tokens) that releases inspected text continuously while maintaining sufficient lookahead to detect multi-token secrets.

---

## 3. Maintenance & Review Cadence

This document is reviewed and updated after every major architectural release. Open security boundaries are tracked as engineering deliverables for subsequent iterations of the PRIVGUARD AI platform.
