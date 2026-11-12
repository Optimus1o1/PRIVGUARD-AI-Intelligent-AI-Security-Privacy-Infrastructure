# PRIVGUARD AI — Software Bill of Materials (SBOM) & SLSA Provenance

## 1. Overview

To guarantee complete visibility into components and compile-time provenance, PRIVGUARD AI produces:
1. **CycloneDX 1.6 Machine-Readable SBOMs** for all application runtimes.
2. **SLSA v1.0 Level 3 Build Provenance Attestations** linking build outputs to source code and CI runner identity.

---

## 2. CycloneDX 1.6 SBOM Generation

SBOM generation is managed by [`scripts/security/generate_sboms.py`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/scripts/security/generate_sboms.py) and executed during every automated release:

```bash
python scripts/security/generate_sboms.py --output-dir dist/sboms --version 1.0.0
```

### Generated Artifacts
1. **`cyclonedx-backend-sbom.json`**:
   - Standard: CycloneDX 1.6 JSON (`bom-1.6.schema.json`).
   - Catalog: 94 Python packages, version numbers, package URLs (`pkg:pypi/...`), license expressions, author data, and component descriptions.
2. **`cyclonedx-frontend-sbom.json`**:
   - Standard: CycloneDX 1.6 JSON.
   - Catalog: 173 Node.js production dependencies extracted directly from `package-lock.json` with package URLs (`pkg:npm/...`), semver tags, and licenses.
3. **`release-manifest.json`**:
   - Canonical inventory linking release version, build commit, release timestamp, and cryptographic SHA-256 digests of all generated files.

---

## 3. SLSA v1.0 Level 3 Build Provenance

PRIVGUARD implements **SLSA (Supply-chain Levels for Software Artifacts) v1.0 Level 3** build provenance generated inside GitHub Actions using official SLSA generators:

```yaml
provenance:
  needs: [build-and-sign]
  permissions:
    id-token: write
    contents: read
    actions: read
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@2924fa6060c5a17684cc8eecf97808298feefee1 # v2.1.0
  with:
    base64-subjects: "${{ needs.build-and-sign.outputs.hashes }}"
    provenance-name: "privguard-provenance.intoto.jsonl"
```

### Provenance Properties Enforced
- **Build Service Integrity**: Built on hosted GitHub runners isolated from external modification.
- **Hermetic Build Definitions**: Parameters, inputs, and build environment captured in an immutable in-toto statement.
- **Cryptographic Attestation**: The statement is digitally signed by GitHub's OIDC root authority.
- **Fail-Closed Verification**: `verify_release.py` enforces builder workflow origin (`.github/workflows/release.yml`) and tag matching before any deployment proceeds.

