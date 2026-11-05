# PRIVGUARD AI — Kubernetes Database Migrations & Zero-Downtime Rollouts
## Alembic Hook Jobs, Role Separation & Expand-Contract Transitions
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Milestone**: Stage 10.4

---

## 1. Migration Architecture in Kubernetes

Database schema migrations in PRIVGUARD are executed via an explicit Kubernetes `Job` triggered automatically by Helm lifecycle hooks before application pods are upgraded:

```
               [ helm upgrade privguard ]
                           |
                           v
              [ Pre-Upgrade Hook Triggers ]
                           |
                           v
            +------------------------------+
            |    Migration Kubernetes Job  |
            |     (alembic upgrade head)   |
            |   Role: privguard_migrator   |
            +------------------------------+
                           |
                 +---------+---------+
                 |                   |
            [ Success ]          [ Failure ]
                 |                   |
                 v                   v
      [ Rolling Upgrade of ]    [ Helm Upgrade Aborted ]
      [ Backend / Frontend ]    [ Old Pods Remain Active ]
```

---

## 2. Helm Hook Configuration

The migration Job manifest (`templates/migration-job.yaml`) defines specific Helm annotations:

```yaml
metadata:
  name: {{ include "privguard.fullname" . }}-migration-{{ .Chart.AppVersion | replace "." "-" }}
  annotations:
    "helm.sh/hook": pre-install,pre-upgrade
    "helm.sh/hook-weight": "-5"
    "helm.sh/hook-delete-policy": before-hook-creation
```

### Key Guarantees:
1. **Pre-Upgrade Execution**: Schema migrations run and complete before new backend and frontend pods begin rolling out.
2. **Versioned Job Naming**: Appending the chart app version ensures every release generates a unique Job resource, preventing Kubernetes immutable field conflicts.
3. **Automatic Cleanup**: `before-hook-creation` automatically cleans up older migration jobs prior to launching a new migration attempt.
4. **Failure Safeguard**: `backoffLimit: 3` and `restartPolicy: OnFailure`. If migrations fail, the Helm upgrade halts, keeping the existing stable application pods serving traffic.

---

## 3. Database Role Separation

To minimize the blast radius of database access, PRIVGUARD enforces strict role separation:

| Role Name | Scope | Permissions | Used By |
| :--- | :--- | :--- | :--- |
| **`privguard_migrator`** | DDL & Migrations | `CREATE`, `ALTER`, `DROP`, `INDEX`, `TRIGGER` on `privguard_*` schemas | Migration Job (`privguard-migration`) |
| **`privguard_app`** | Runtime Operations | `SELECT`, `INSERT`, `UPDATE`, `DELETE` on tenant application tables. No DDL. | Backend (`privguard-backend`), Worker (`privguard-worker`) |

Runtime application pods never receive credentials for `privguard_migrator`, preventing SQL injection or compromised application pods from altering database schemas or executing arbitrary DDL.

---

## 4. Zero-Downtime Migration Policy (Expand-Contract)

To avoid locking tables or breaking running application instances during rolling deployments, all PRIVGUARD migrations follow the **Expand-Contract (Parallel Run)** methodology:

### 4.1 Golden Rules for Migrations
1. **Never Drop Columns in an Active Migration**: Dropping a column immediately breaks running pods that still query that column.
2. **Never Rename Columns in a Single Migration**: Add the new column, dual-write in application code, backfill, and drop the legacy column in a subsequent release.
3. **Columns Must Be Nullable or Have Safe Defaults**: When adding a column, it must be nullable (`nullable=True`) or specify a `server_default` so older running pods can continue inserting rows without knowing about the new column.
4. **Indexes Created Concurrently**: Large indexes must use `CREATE INDEX CONCURRENTLY` to avoid blocking writes during index builds.

---

## 5. Rollback Procedures & Forward-Fix Policy

### 5.1 Application Rollback
If a new release exhibits application-level regressions after rollout:
```bash
helm rollback privguard <PREVIOUS_REVISION_NUMBER> --namespace privguard
```

Because migrations adhere to the Expand-Contract pattern, the previous application version will continue to function correctly against the expanded database schema.

### 5.2 Forward-Fix Migration Policy
> [!IMPORTANT]
> **Production Forward-Fix Policy**: PRIVGUARD strictly prohibits automated `alembic downgrade` in production. Downward migrations often result in data loss (dropping columns or tables). In case of schema anomalies:
> 1. Roll back the application container to the previous version.
> 2. Author a forward migration script (e.g. `alembic revision -m "fix_..."`) that repairs the schema or drops deprecated objects safely.
> 3. Deploy the fix via `helm upgrade`.

