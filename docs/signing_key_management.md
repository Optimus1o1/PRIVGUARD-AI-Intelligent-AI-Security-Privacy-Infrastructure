# PRIVGUARD AI — Signing Key Management Specification
## Asymmetric Policy Signing & Decoupled Approval Action Binding

**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Author:** Aniket Nandi (Kolkata, IST)  
**Baseline:** Stage 10.5  

---

### 1. Purpose Segregation

Prior to Stage 10.5, some signature operations relied on HMAC derivation from the application master key. Stage 10.5 decouples all signing keys from data encryption keys to prevent compromise lateral movement:

```
[ Master Encryption Key ]  --> Used exclusively for KEK operations in Local provider
           |
      [ DECOUPLED ]
           |
           +----> [ Ed25519 Policy Signing Keypair ] (Asymmetric integrity)
           |
           +----> [ Approval Action Binding Secret ] (Dedicated HMAC-SHA256, versioned kid)
```

---

### 2. Ed25519 Policy Bundle Signing

Enterprise security and privacy policies distributed across the fleet are signed using Ed25519:
1. **Key Generation:** Private keys are 32-byte seeds generating 32-byte public keys (`SigningKeyManager.generate_ed25519_keypair()`).
2. **Canonical Signing:** Bundles are canonicalized to deterministic JSON bytes before signing.
3. **Public Key Registry:** When a signing key is generated, its public key material is persisted in `KeyVersion.public_key_material`.
4. **Historical Verification:** Gateways and agents verify bundles by looking up the historical public key corresponding to `signing_key_id`. A retired key version remains valid for verifying historical bundles, ensuring bundle verification never breaks upon key rotation.

---

### 3. Approval Action Binding (HMAC-SHA256)

To defend against Man-in-the-Middle (MitM) parameter tampering or approval reuse attacks (MITRE T1548 / T1078), human approval requests are bound to their execution context:
1. **Payload Formulation:**
   `payload = tool_name + "|" + target_resource + "|" + canonical_json(parameters)`
2. **Versioned Key ID (`kid`):**
   `action_hash = HMAC-SHA256(key_material, payload)`
   The resulting action hash and the active `kid` (e.g., `hmac_v1`) are recorded in the `ApprovalRequest`.
3. **Dedicated Key Configuration:**
   Configured via `APPROVAL_HMAC_KEY` or file path `APPROVAL_HMAC_KEY_FILE` (Docker/K8s secret). If unspecified in dev mode, derived deterministically using HKDF with a distinct domain-separated info string (`privguard_approval_action_binding_key`).
4. **Graceful Rotation:**
   `SigningKeyManager.rotate_hmac_key()` generates `hmac_v2`. Previous keys are retained in memory during their TTL window so in-flight requests remain verifiable until consumed or expired.
5. **Emergency Revocation:**
   `SigningKeyManager.revoke_hmac_key(kid)` instantly drops the key from memory. Any pending approval signed under that `kid` will be rejected immediately upon execution.
