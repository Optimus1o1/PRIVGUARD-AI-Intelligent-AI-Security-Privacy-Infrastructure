# PRIVGUARD AI — Key Compromise Incident Response Playbook
## Containment Workflows, Re-encryption & Rapid Revocation

**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Author:** Aniket Nandi (Kolkata, IST)  
**Baseline:** Stage 10.5  

---

### 1. Incident Taxonomy

When a cryptographic credential or key is leaked or suspected of exposure, the incident must be classified into one of four response tracks:

```
                            INCIDENT IDENTIFIED
                                     |
         +-----------------+---------+---------+-----------------+
         |                 |                   |                 |
         v                 v                   v                 v
   DEK Compromise    KEK Compromise     Signing Key Leak   HMAC Key Leak
  (Single Record)   (Master Key/KMS)   (Policy Bundles)   (Action Binding)
         |                 |                   |                 |
         v                 v                   v                 v
   Track 1: Re-enc   Track 2: Emergency  Track 3: Re-sign   Track 4: Revoke
   Fresh 256-bit     Rotation + Rewrap   Fresh Ed25519      kid + Rotate
```

---

### 2. Operational Containment Workflows

#### Track 1: DEK Compromise (`DEK_COMPROMISE`)
- **Impact:** Confidentiality of one individual memory record is compromised.
- **Workflow:**
  1. Operator invokes `POST /v1/incidents/compromise` with `compromise_type="DEK_COMPROMISE"` and `target_id="{memory_id}"`.
  2. `KeyCompromiseManager.handle_dek_compromise()` decrypts the record using current active credentials.
  3. Generates a fresh 256-bit DEK (`os.urandom(32)`) and new 12-byte random nonce.
  4. Re-encrypts the plaintext under the fresh DEK and wraps it with the active KMS KEK.
  5. Updates the database record with the new ciphertext, nonce, and wrapped DEK.
  6. The previous DEK is permanently unusable.

#### Track 2: KEK Compromise (`KEK_COMPROMISE`)
- **Impact:** Wrapping key is exposed; stored DEKs could potentially be unwrapped if database ciphertext was also exfiltrated.
- **Workflow:**
  1. Operator invokes `POST /v1/incidents/compromise` with `compromise_type="KEK_COMPROMISE"` and `target_id="{key_id}"`.
  2. `KeyCompromiseManager.handle_kek_compromise()` immediately updates the active `KeyVersion.status` to `COMPROMISED`.
  3. Triggers `KeyRotationEngine.initiate_rotation(mode="EMERGENCY")` to advance the KMS provider version and create a fresh `ACTIVE` key version.
  4. Spawns an emergency `KeyRotationJob` to rewrap all dependent record DEKs under the fresh KEK.
  5. Any attempt to use the compromised version is logged and rejected.

#### Track 3: Policy Signing Key Compromise (`POLICY_SIGNING_KEY_COMPROMISE`)
- **Impact:** Adversary could forge authorized security policies or tamper with permissions.
- **Workflow:**
  1. Operator invokes `POST /v1/incidents/compromise` with `compromise_type="POLICY_SIGNING_KEY_COMPROMISE"` and `target_id="{signing_key_id}"`.
  2. `KeyCompromiseManager.handle_policy_signing_key_compromise()` marks the existing version `COMPROMISED`.
  3. Generates a fresh Ed25519 keypair (`SigningKeyManager.generate_ed25519_keypair()`).
  4. Re-signs all currently `ACTIVE` policy bundles across the tenant using the fresh private key and updates their signatures and `signing_key_id`.
  5. Agents and gateways receive push notifications or pull fresh bundles with the new signature.

#### Track 4: Approval Action Binding Key Compromise (`APPROVAL_HMAC_KEY_COMPROMISE`)
- **Impact:** Adversary could forge approval requests or tamper with tool parameters during pending requests.
- **Workflow:**
  1. Operator invokes `POST /v1/incidents/compromise` with `compromise_type="APPROVAL_HMAC_KEY_COMPROMISE"` and `target_id="{kid}"`.
  2. `KeyCompromiseManager.handle_hmac_key_compromise()` executes instant revocation of the compromised `kid` via `SigningKeyManager.revoke_hmac_key(kid)`.
  3. All pending approvals signed under the compromised `kid` are immediately rejected.
  4. Rotates to a new high-entropy HMAC secret with a new `kid`.
