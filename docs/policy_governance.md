# Central Policy Governance & Ed25519 Signing

> **PRIVGUARD AI** — *Cryptographic Policy Integrity & Hierarchy Resolution*  
> **Target Version**: Stage 9

---

## 1. Deterministic 5-Layer Policy Hierarchy

Security decisions are resolved deterministically across five layers:

```
[Layer 1] Platform Guardrails (Immutable System Defense)
   |
   v
[Layer 2] Organization Baseline (Enterprise Master Policy)
   |
   v
[Layer 3] Departmental Workspace Policy
   |
   v
[Layer 4] Application Scope Policy
   |
   v
[Layer 5] Agent Task Scope (Least-Privilege Allowlist)
```

### Hierarchy Rules
1. **No Weakening Upwards**: Lower-level policies can only tighten restrictions; they can never weaken or disable higher-level restrictions.
2. **Deterministic Conflict Resolution**: When rules conflict on the same target, PRIVGUARD enforces the **most restrictive** action:
   `BLOCK` / `TERMINATE_TASK` > `REQUIRE_APPROVAL` > `REDACT` / `SANITIZE` > `WARN` > `ALLOW`.

---

## 2. Ed25519 Cryptographic Bundle Signing

Policy bundles are compiled, canonically serialized according to RFC 8785, and signed using an asymmetric Ed25519 keypair:

```python
canonical_bytes = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
signature_hex = private_key.sign(canonical_bytes).hex()
```

### Protection Against Tampering, Downgrade & Replay
- **Tamper Evidence**: Any modification of rules or actions invalidates the signature, causing agents and brokers to reject the bundle.
- **Anti-Downgrade Defense**: Bundles carry monotonically increasing version numbers (`version = 1, 2, 3...`). Direct deployment of a bundle with a lower version than the currently active version is rejected.
- **Audited Rollbacks**: If a previous configuration must be restored, the administrator invokes an audited rollback endpoint, which records the rollback in the tamper-evident audit ledger.
