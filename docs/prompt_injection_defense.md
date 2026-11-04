# Deterministic Prompt Injection & Jailbreak Defense

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Lead Engineer:** [ANIKET NANDI] ([KOLKATA], [IST])  
**Product:** PRIVGUARD AI  

---

## 1. Defensive Philosophy

Prompt injection cannot be solved by asking an LLM to evaluate whether another prompt is malicious. Secondary model invocations are non-deterministic, double inference costs, add 500ms+ latency, and can themselves be jailbroken.

PRIVGUARD AI implements **fast, deterministic, zero-dependency token and structural inspection** running in `< 0.1ms` per prompt:
1. **Normalization Layer:** Collapses homoglyphs and styled unicode chars using Unicode Normalization Form KC (NFKC).
2. **Invisible Token Stripping:** Strips zero-width spaces (`\u200b`, `\u200c`, `\u200d`, `\ufeff`) and bidirectional control overrides (`\u202a`–`\u202e`).
3. **Base64 Payload Unpacking:** Automatically identifies, decodes, and recursively scans base64 encoded text.
4. **Structural Delimiter Enforcement:** Intercepts fake system prompts, instruction boundaries (`### SYSTEM:`, `<|im_start|>`), and DAN-style persona overrides.
5. **System Prompt Canaries:** Injects high-entropy random tokens into system context and halts upstream output streaming if the token appears in generated responses.

---

## 2. Rule Taxonomy

| Rule ID | Category | Detection Pattern / Logic | Severity | Action |
| :--- | :--- | :--- | :--- | :--- |
| `INJ_OVERRIDE_001` | Direct Override | `(ignore\|disregard\|forget\|override)\s+all\s+(previous\|prior\|above)\s+instructions` | `CRITICAL` | `BLOCK` |
| `INJ_OVERRIDE_002` | Prefix Hijack | `(new instruction\|system override\|admin override)\s*:` | `HIGH` | `BLOCK` |
| `INJ_JAILBREAK_001`| Persona Jailbreak| `dan mode\|jailbreak\|developer mode v\d+\|godmode` | `CRITICAL` | `BLOCK` |
| `INJ_JAILBREAK_002`| Roleplay Evasion | `(pretend\|act as if\|roleplay as)\s+you have no (safety\|filters\|rules)` | `HIGH` | `BLOCK` |
| `INJ_EXTRACT_001`  | System Extraction| `(repeat\|print\|output\|reveal)\s+all\s+the\s+text above` | `HIGH` | `BLOCK` |
| `INJ_DELIM_001`    | Delimiter Attack | `<\|im_start\|>\|<\|im_end\|>\|<\|system\|>\|\[INST\] <<SYS>>` | `CRITICAL` | `BLOCK` |
| `INJ_OBF_001`      | Evasion / Unicode| Zero-width chars `[\u200B-\u200D\uFEFF\u202A-\u202E]` | `MEDIUM` | `FLAG` |
| `INJ_CANARY_001`   | Canary Leakage   | Detection of registered `PRIVGUARD_CANARY_*` in model output stream | `CRITICAL` | `BLOCK` |

---

## 3. False Positive Mitigation

Technical or pedagogical queries often discuss injection terms (e.g. `What does "ignore previous instructions" mean?`).
- **Contextual Discounting:** When injection phrases appear within quotation marks and are preceded by pedagogical inquiry verbs (`how to defend against`, `what does`, `explain`, `define`), confidence is discounted and the action is downgraded from `BLOCK` to `FLAG`.
- **Whitelisted Testing:** Admins can designate trusted evaluation test suites via `TrustLevel.TRUSTED`.
