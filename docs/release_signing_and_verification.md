# PRIVGUARD AI — Release Signing & Verification

## 1. Overview

PRIVGUARD AI implements cryptographic release signing using **Sigstore Cosign** keyless infrastructure combined with client-side verification via [`scripts/security/verify_release.py`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/scripts/security/verify_release.py).

This guarantees that:
1. No release artifact can be altered post-build without invalidating its signature.
2. Signatures are tied to GitHub OIDC workflow identities, eliminating the need to store long-lived private keys as CI secrets.
3. Every signature is permanently logged in Sigstore's public transparency log (Rekor).

---

## 2. Keyless OIDC Signing Architecture

```
[ GitHub Actions Runner ]
           |
           | 1. Request Ephemeral OIDC Token (id-token: write)
           v
[ GitHub OIDC Token Issuer ]
           |
           | 2. Returns JWT containing:
           |    - repository: privguard-ai/privguard
           |    - workflow: .github/workflows/release.yml
           |    - ref: refs/tags/v*.*.*
           v
[ Sigstore Fulcio CA ]
           |
           | 3. Issues short-lived X.509 certificate bound to GitHub identity
           v
[ Sigstore Cosign ]
           |
           | 4. Digitally signs container image & artifacts
           v
[ Sigstore Rekor Log ]
           |
           | 5. Records signature & cert in tamper-evident transparency log
           v
[ Container Registry / GitHub Release ]
```

### Keyless Benefits
- **Zero Secret Management**: No private keys stored in GitHub Secrets or on developer laptops.
- **Identity Attestation**: Signatures cryptographically attest that the artifact was built by PRIVGUARD's approved GitHub workflow from an immutable tag.
- **Auditability**: All signing events are publicly verifiable in Rekor.

---

## 3. Cryptographic Verification Utility (`verify_release.py`)

PRIVGUARD provides a standalone verification tool designed to run in air-gapped or target Kubernetes clusters before deployments:

```bash
python scripts/security/verify_release.py \
  --manifest-path dist/release-manifest.json \
  --expected-repo "privguard-ai/privguard" \
  --expected-tag "v1.0.0"
```

### Verification Pipeline Checklist
1. **Manifest Schema**: Validates that required fields (`version`, `commit`, `timestamp`, `artifacts`) exist.
2. **Digest Validation**: Computes the SHA-256 digest of every listed artifact on disk and compares it to the manifest digest.
3. **CycloneDX SBOMs**: Confirms that backend and frontend SBOMs exist, are valid JSON, declare `specVersion: "1.6"`, and contain non-empty component inventories.
4. **Cosign Signatures**: Runs `cosign verify` to ensure signatures match the authorized GitHub repository and workflow identity.
5. **SLSA Provenance**: Inspects in-toto provenance statements to verify build parameters and builder identity.

### Fail-Closed Design
If any verification check fails, `verify_release.py`:
- Logs the exact mismatch or missing artifact to `stderr`.
- Exits immediately with return code `1`.
- Prohibits deployment from proceeding.
