# PRIVGUARD AI — Phase 1 MVP User Guide

**Document ID**: DOC-PHASE1-USER-001  
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Developer**: ANIKET NANDI (Kolkata, IST)  
**Version**: 1.0.0-rc1  
**Execution Date**: 2026-11-08

---

## 1. Introduction

PRIVGUARD AI is an **independent security and privacy enforcement layer for AI**. It operates between your end-users, client applications, AI agents, and upstream language models to safeguard sensitive personal data, neutralize prompt injection attacks, enforce strict tool execution permissions, and maintain tamper-evident, content-free audit logs.

This guide walks operators and administrators through configuring, monitoring, and operating PRIVGUARD using the web dashboard and REST APIs.

---

## 2. Navigating the Security Dashboard

The PRIVGUARD web console is accessible locally at `http://localhost:3000`.

### 2.1 Overview Dashboard (`/dashboard`)
- **System Health**: Real-time status of backend services, database connections, and cache layers.
- **Traffic Telemetry**: Total requests processed, blocked threats, redacted PII entities, and tool execution counts.
- **Threat Heatmap**: Visual categorization of observed threat vectors (direct injection, secrets, delimiters).

### 2.2 Privacy & Sensitive Data Control (`/privacy`)
- **Active Entity Scanners**: Status of built-in pattern detectors (Email, Phone Numbers, Credit Cards, SSN, API Keys).
- **Redaction Mode**: Reversible tokenization (`<EMAIL_1>`) vs irreversible masking (`[REDACTED]`).
- **Interactive Inspector**: Paste sample text into the interactive testing sandbox to see live redaction output and token mappings.

### 2.3 Threat Detection Center (`/threats`)
- **Threat Event Stream**: Real-time list of intercepted security incidents.
- **Quarantined Prompts**: Records of prompt injection and system override attempts.
- **Explainable Diagnostics**: For every blocked prompt, view the specific triggered rule ID, risk score, and recommended action. Note: Prompt contents are fingerprinted via keyed HMACs to preserve audit integrity without storing raw attack strings.

### 2.4 Agent Tool Permissions (`/tools`)
- **Registered Tools**: View available server-side tools (`calculator`, `lookup_file_metadata`, `search_mock_kb`).
- **Tool Schemas & Sandboxing**: Review JSON schema parameters, timeout ceilings, and permission scopes.
- **Active Capability Grants**: Inspect active, task-scoped capability tokens and execution counters.

### 2.5 Security Policies (`/policies`)
- **Baseline Policies**: View hardcoded baseline rules for data categories (`PUBLIC`, `INTERNAL`, `PERSONAL`, `CONFIDENTIAL`, `CRITICAL`).
- **Custom Rules**: Add application-specific overrides (e.g., set `INTERNAL` category to `REQUIRE_APPROVAL`).
- **Policy Simulation Sandbox**: Test how an arbitrary combination of detected entities and risk categories will be evaluated before activating the rule.

### 2.6 Content-Free Activity Logs (`/audit`)
- **Audit Event Ledger**: Searchable, filterable event history.
- **Zero-Content Invariant**: Audit records display request IDs, action types, entity counts, and cryptographic fingerprints—strictly guaranteeing that sensitive user prompts, passwords, or emails are never written to disk or displayed.

---

## 3. Standard Operational Workflows

### 3.1 Creating and Activating a Custom Policy
1. Navigate to **Policies** (`http://localhost:3000/policies`).
2. Click **Add Policy Rule**.
3. Select the target **Data Category** (e.g. `INTERNAL`).
4. Select the desired **Action** (`ALLOW`, `REDACT`, `BLOCK`, or `REQUIRE_APPROVAL`).
5. Select the **Risk Level** (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
6. Enter an operational description and click **Save Rule**.
7. Test the rule in the **Simulation Panel** to verify that synthetic requests trigger the expected verdict.

> [!NOTE]  
> The `CRITICAL` data category (e.g., detected production credentials or API keys) is governed by an immutable hardcoded invariant: it cannot be set to `ALLOW`. Attempting to save a rule allowing critical credentials will be rejected with an `INVALID_POLICY_INVARIANT` error.

### 3.2 Reviewing Security Incidents
1. Navigate to **Threats** (`http://localhost:3000/threats`).
2. Review events flagged with severity `CRITICAL` or `HIGH`.
3. Filter by threat type (`DIRECT_PROMPT_INJECTION`, `SYSTEM_PROMPT_EXTRACTION`, or `SECRET_BLOCKED`).
4. Note the associated `app_id` and `request_id` to correlate with upstream client logs.

---

## 4. Support and Assistance

For questions or assistance with PRIVGUARD configurations, contact **Moon Sanctum Labs**:
- **Email**: `aniket@moonsanctumlabs.com`
- **Agency Slogan**: *Decode. Build. Evolve.*

