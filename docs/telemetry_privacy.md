# Zero-Content Telemetry Privacy & Data Leakage Prevention

Organization: **Moon Sanctum Labs**  
Slogan: **Decode. Build. Evolve.**  
System: **PRIVGUARD AI**  
Document: **Telemetry Privacy Invariant & Verification Guide**  

---

## 1. Executive Privacy Principles

As a privacy enforcement gateway, PRIVGUARD AI itself must never become a source of data leakage. Observability infrastructure—including distributed traces, metrics, log collectors, and monitoring dashboards—is frequently subject to lower access control scrutiny than primary databases. 

Consequently, PRIVGUARD implements a strict **Zero-Content Telemetry Invariant**:
> **No raw prompts, LLM responses, memory plaintext, tool argument secrets, or API keys may appear in spans, metrics, or operational logs under any operational or error condition.**

---

## 2. Telemetry Privacy Defense-in-Depth

PRIVGUARD achieves zero-content privacy through four interlocking layers:

```
[ INCOMING TRAFFIC / INTERNAL DATA ]
                │
                ▼
┌────────────────────────────────────────────────────────┐
│ LAYER 1: STRICT SPAN ATTRIBUTE ALLOWLIST               │
│ - Drops all keys not explicitly permitted              │
│ - Drops any key matching PROHIBITED_KEY_PATTERNS       │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│ LAYER 2: REGEX VALUE SANITIZATION                      │
│ - Sanitizes values for Bearer tokens, OpenAI,          │
│   Anthropic, GitHub tokens, passwords                  │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│ LAYER 3: SANITIZED EXCEPTION RECORDING                 │
│ - Suppresses default OTel error descriptions           │
│ - Records only exception class names & scrubbed texts  │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│ LAYER 4: INLINE LOG REDACTION FILTER                   │
│ - Filters all Python log records at root handler       │
│ - Replaces detected secrets with [REDACTED_CREDENTIAL] │
└────────────────────────────────────────────────────────┘
```

---

## 3. Prohibited Attribute Patterns

In `app/observability/attributes.py`, regex patterns actively inspect attribute keys. If an engineer attempts to set an unvetted key, it is blocked:

```python
PROHIBITED_KEY_PATTERNS = [
    re.compile(r".*prompt.*", re.IGNORECASE),
    re.compile(r".*completion.*", re.IGNORECASE),
    re.compile(r".*raw.*", re.IGNORECASE),
    re.compile(r".*memory_text.*", re.IGNORECASE),
    re.compile(r".*secret.*", re.IGNORECASE),
    re.compile(r".*token.*", re.IGNORECASE),
    re.compile(r".*password.*", re.IGNORECASE),
    re.compile(r".*content.*", re.IGNORECASE),
]
```

### Prohibited vs Allowed Examples
- `prompt_text`: **BLOCKED**
- `user_prompt`: **BLOCKED**
- `completion_body`: **BLOCKED**
- `raw_argument`: **BLOCKED**
- `privguard.pii_detected`: **ALLOWED** (Boolean)
- `privguard.entity_count`: **ALLOWED** (Integer)
- `http.route`: **ALLOWED** (Normalized path string)

---

## 4. Credential & Key Sanitization Rules

In `app/observability/sanitization.py`:
- `Bearer [A-Za-z0-9\-\._~\+\/]+=*` $\to$ `Bearer [REDACTED_CREDENTIAL]`
- `sk-[A-Za-z0-9_\-]{20,}` $\to$ `[REDACTED_CREDENTIAL]`
- `sk-ant-[A-Za-z0-9_\-]{20,}` $\to$ `[REDACTED_CREDENTIAL]`
- `ghp_[A-Za-z0-9]{36}` $\to$ `[REDACTED_CREDENTIAL]`
- `password: "admin123"` $\to$ `password: [REDACTED_CREDENTIAL]`

---

## 5. Automated Verification Tests

The test suite `backend/tests/test_stage_10_6_telemetry_privacy.py` rigorously verifies that these protections hold:
1. `test_01_sanitizer_masks_bearer_tokens`: Asserts Bearer tokens in headers or text are replaced.
2. `test_02_sanitizer_masks_openai_and_anthropic_keys`: Injects valid-format API keys and verifies redaction.
3. `test_03_span_attributes_drop_prohibited_keys`: Attempts to set `user_prompt` and `raw_content` on spans; asserts attributes are absent from span dict.
4. `test_04_span_attributes_allowlist_enforced`: Asserts only allowlisted keys are retained.
5. `test_05_logging_redaction_filter`: Logs records containing secrets and asserts formatted JSON output contains only `[REDACTED_CREDENTIAL]`.
6. `test_06_tracing_exception_recording_scrubs_secrets`: Throws an exception containing a simulated DB connection string with password; verifies the trace span does not contain the password.
7. `test_07_end_to_end_middleware_privacy`: Issues an HTTP request with sensitive headers; verifies Prometheus and logs do not expose sensitive parameters.
