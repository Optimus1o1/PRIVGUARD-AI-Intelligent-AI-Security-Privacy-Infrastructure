# PRIVGUARD AI — Cryptographic Capability Security

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## 1. Capability Token Design

Unlike self-contained, unrevocable JWTs, PRIVGUARD capability tokens are **opaque, task-scoped, and instantly revocable**.

* **Token Format:** `pg_cap_<256-bit cryptographically secure random urlsafe token>`
* **Storage Invariant:** Plaintext tokens are returned **once** to the caller upon issuance. The database stores ONLY the SHA-256 hash (`secret_hash`).
* **Validation:** On every tool execution, PRIVGUARD re-hashes the provided token and looks up the grant record atomically in SQLite.

## 2. Invariants & Guarantees

1. **Task-Scoped Expiration:** Every capability is bound to a task session (`task_id`). When a task is completed, cancelled, or expires, all associated capabilities are automatically revoked.
2. **Usage Limits:** Enforces strict execution quotas (`max_uses`). Once the quota is exhausted, subsequent execution attempts are rejected with `CAPABILITY_MAX_USES_EXCEEDED`.
3. **Instant Revocation:** Calling `/v1/capabilities/{id}/revoke` immediately sets `is_revoked = True`. All subsequent calls with the token fail closed instantly.
4. **Boundary Isolation:** A capability token issued for `agent_A` cannot be used by `agent_B`, nor can a token issued for `read_file` be reused on `delete_file`.
