# PRIVGUARD AI — Secret Management & Key Validation

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Author**: [ANIKET NANDI] ([KOLKATA], [IST])  
**Date**: November 2026  

---

## 1. Secrets Architecture

In production, PRIVGUARD AI never relies on committed `.env` files or hardcoded environment variables for sensitive cryptographic material. 

Secrets are provisioned via **Docker Compose Secrets** mounted as files under `/run/secrets/`. The application configuration in [`backend/app/core/config.py`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/core/config.py) dynamically reads secrets from file paths specified by `*_FILE` environment variables:
- `PRIVGUARD_MASTER_KEY_FILE`: Path to master encryption key file.
- `DATABASE_PASSWORD_FILE`: Path to PostgreSQL password file.
- `MIGRATION_PASSWORD_FILE`: Path to Alembic migration role password file.
- `REDIS_PASSWORD_FILE`: Path to Redis ACL password file.

---

## 2. Master Key Validation & Fail-Closed Invariants

When `ENVIRONMENT=production`, the application executes strict invariant validation during startup:
1. **No Default Placeholder**: Rejects `change-me-in-production-min-32-chars-long-secret`.
2. **Entropy & Length**: Enforces that the key is at least 32 characters (256 bits of entropy).
3. **No Silent Generation**: Will fail closed with a fatal `ValueError` rather than silently generating an ephemeral key.
4. **No DEBUG Backdoor**: Fails closed if `DEBUG=True` when `ENVIRONMENT=production`.

---

## 3. Secret Initialization Tool

The helper script [`scripts/init_secrets.py`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/scripts/init_secrets.py) generates cryptographically secure secrets:

```bash
python scripts/init_secrets.py --dir ./secrets
```

### Generated Files:
| File | Format | Entropy | Purpose |
|---|---|---|---|
| `privguard_master_key.txt` | URL-safe base64 | 48 bytes (384 bits) | AES-256-GCM envelope KEK derivation & API key hashing. |
| `postgres_password.txt` | URL-safe base64 | 32 bytes (256 bits) | PostgreSQL `postgres` and `privguard_app` password. |
| `migration_password.txt` | URL-safe base64 | 32 bytes (256 bits) | PostgreSQL `privguard_migrator` password. |
| `redis_password.txt` | URL-safe base64 | 32 bytes (256 bits) | Redis ACL authentication token. |
| `privguard_admin_api_key.txt` | Hex (`pg_live_...`) | 24 bytes (192 bits) | Initial administrative API key. |
| `ed25519_policy_signing.key` | PKCS#8 PEM | 32 bytes (256 bits) | Private key for signing organization policy bundles. |
| `ed25519_policy_signing.pub` | SubjectPublicKeyInfo | 32 bytes (256 bits) | Public key for verifying policy bundle authenticity. |

---

## 4. Secure Storage & Backup Requirements

- **Permissions**: Secret files must be set to `chmod 600` (read/write only by the process owner).
- **Git Exclusion**: The `./secrets/` directory is strictly ignored in `.gitignore` and `.dockerignore`.
- **Disaster Recovery**: Back up the `secrets/` directory to an encrypted offline vault or enterprise secrets manager (AWS Secrets Manager, HashiCorp Vault, Google Secret Manager). Loss of `privguard_master_key.txt` permanently renders all encrypted memory records irrecoverable.
