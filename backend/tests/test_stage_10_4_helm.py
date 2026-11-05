"""Automated Tests for Stage 10.4: Helm Chart, Pod Security, and Kubernetes Deployment.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import json
import os
import shutil
import subprocess
import pytest
import yaml

from app.infrastructure.rate_limiter import DistributedRateLimiter, RateLimitPolicy

# Locate helm binary
HELM_CMD = shutil.which("helm")
if not HELM_CMD:
    # Check WinGet package location on Windows
    candidate = os.path.expandvars(
        r"%LOCALAPPDATA%\Microsoft\WinGet\Packages\Helm.Helm_Microsoft.Winget.Source_8wekyb3d8bbwe\windows-amd64\helm.exe"
    )
    if os.path.isfile(candidate):
        HELM_CMD = candidate
    else:
        HELM_CMD = "helm"

CHART_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "helm", "privguard"))


def run_helm_command(*args: str) -> tuple[int, str, str]:
    """Helper executing helm subprocess command."""
    cmd = [HELM_CMD] + list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return proc.returncode, proc.stdout, proc.stderr


def test_01_helm_lint():
    """Verify helm lint passes with zero errors on privguard chart."""
    code, stdout, stderr = run_helm_command("lint", CHART_DIR)
    assert code == 0, f"helm lint failed:\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    assert "0 chart(s) failed" in stdout


def test_02_helm_template_production():
    """Verify helm template successfully renders production values."""
    prod_values = os.path.join(CHART_DIR, "values", "production.yaml")
    code, stdout, stderr = run_helm_command("template", "privguard", CHART_DIR, "-f", prod_values)
    assert code == 0, f"helm template failed:\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    docs = [d for d in yaml.safe_load_all(stdout) if d is not None]
    kinds = {d.get("kind") for d in docs}
    assert "Deployment" in kinds
    assert "Service" in kinds
    assert "NetworkPolicy" in kinds
    assert "Ingress" in kinds
    assert "Job" in kinds
    assert "ConfigMap" in kinds
    assert "PodDisruptionBudget" in kinds


def test_03_restricted_pod_security_standards():
    """Verify all Deployments and Jobs strictly comply with Kubernetes Restricted Pod Security Standard."""
    prod_values = os.path.join(CHART_DIR, "values", "production.yaml")
    code, stdout, _ = run_helm_command("template", "privguard", CHART_DIR, "-f", prod_values)
    assert code == 0

    docs = [d for d in yaml.safe_load_all(stdout) if d is not None]
    workload_docs = [d for d in docs if d.get("kind") in ("Deployment", "Job")]
    assert len(workload_docs) >= 4  # backend, frontend, worker, migration job

    for doc in workload_docs:
        name = doc["metadata"]["name"]
        pod_spec = (
            doc["spec"]["template"]["spec"]
            if "template" in doc["spec"]
            else doc["spec"]
        )

        # 1. Pod-level security context
        pod_sc = pod_spec.get("securityContext", {})
        assert pod_sc.get("runAsNonRoot") is True, f"{name}: runAsNonRoot must be true"
        assert pod_sc.get("seccompProfile", {}).get("type") == "RuntimeDefault", f"{name}: seccompProfile must be RuntimeDefault"

        # 2. Container-level security context
        for container in pod_spec.get("containers", []):
            c_name = container["name"]
            c_sc = container.get("securityContext", {})
            assert c_sc.get("allowPrivilegeEscalation") is False, f"{name}/{c_name}: allowPrivilegeEscalation must be false"
            assert c_sc.get("readOnlyRootFilesystem") is True, f"{name}/{c_name}: readOnlyRootFilesystem must be true"
            dropped_caps = c_sc.get("capabilities", {}).get("drop", [])
            assert "ALL" in dropped_caps, f"{name}/{c_name}: capabilities must drop ALL"

            # 3. Memory-backed scratch tmpfs
            vol_mounts = [vm["mountPath"] for vm in container.get("volumeMounts", [])]
            assert "/tmp" in vol_mounts, f"{name}/{c_name}: must mount /tmp for scratch"


def test_04_no_plaintext_secrets_in_rendered_manifests():
    """Verify zero plaintext passwords, tokens, or private keys exist in rendered manifests."""
    prod_values = os.path.join(CHART_DIR, "values", "production.yaml")
    code, stdout, _ = run_helm_command("template", "privguard", CHART_DIR, "-f", prod_values)
    assert code == 0

    prohibited_strings = [
        "postgres_password: ",
        "redis_password: ",
        "BEGIN PRIVATE KEY",
        "BEGIN ED25519 PRIVATE KEY",
        "secretKeyRef: null",
    ]

    for prohibited in prohibited_strings:
        assert prohibited not in stdout, f"Found forbidden plaintext secret indicator '{prohibited}' in rendered manifest."


def test_05_network_policies_default_deny_and_isolation():
    """Verify NetworkPolicies define default-deny and strict multi-tier isolation."""
    prod_values = os.path.join(CHART_DIR, "values", "production.yaml")
    code, stdout, _ = run_helm_command("template", "privguard", CHART_DIR, "-f", prod_values)
    assert code == 0

    docs = [d for d in yaml.safe_load_all(stdout) if d is not None and d.get("kind") == "NetworkPolicy"]
    netpol_names = {d["metadata"]["name"] for d in docs}

    assert any("default-deny" in n for n in netpol_names), "Must include a default-deny NetworkPolicy"
    assert any("frontend" in n for n in netpol_names), "Must include frontend NetworkPolicy"
    assert any("backend" in n for n in netpol_names), "Must include backend NetworkPolicy"
    assert any("worker" in n for n in netpol_names), "Must include worker NetworkPolicy"

    # Backend netpol must allow ingress only from frontend
    backend_netpol = next(d for d in docs if "backend" in d["metadata"]["name"])
    ingress_rules = backend_netpol["spec"].get("ingress", [])
    assert len(ingress_rules) >= 1
    # Check that ingress rule specifies frontend selector
    selectors = [
        f.get("podSelector", {}).get("matchLabels", {}).get("app.kubernetes.io/component")
        for rule in ingress_rules for f in rule.get("from", [])
    ]
    assert "frontend" in selectors, "Backend NetworkPolicy must restrict ingress to frontend pods"


def test_06_ingress_exclusively_targets_frontend():
    """Verify Ingress exposes ONLY frontend service (port 3000), never backend (port 8000)."""
    prod_values = os.path.join(CHART_DIR, "values", "production.yaml")
    code, stdout, _ = run_helm_command("template", "privguard", CHART_DIR, "-f", prod_values)
    assert code == 0

    docs = [d for d in yaml.safe_load_all(stdout) if d is not None and d.get("kind") == "Ingress"]
    assert len(docs) == 1, "Must render exactly one Ingress"

    ingress = docs[0]
    rules = ingress["spec"].get("rules", [])
    assert len(rules) >= 1

    for rule in rules:
        for path in rule.get("http", {}).get("paths", []):
            service_name = path["backend"]["service"]["name"]
            service_port = path["backend"]["service"]["port"]["number"]
            assert "frontend" in service_name, f"Ingress must target frontend, but targets: {service_name}"
            assert service_port == 3000, f"Ingress must route to port 3000, got {service_port}"


def test_07_migration_job_dedicated_credentials():
    """Verify database migration Job uses dedicated migrator role and credentials."""
    prod_values = os.path.join(CHART_DIR, "values", "production.yaml")
    code, stdout, _ = run_helm_command("template", "privguard", CHART_DIR, "-f", prod_values)
    assert code == 0

    docs = [d for d in yaml.safe_load_all(stdout) if d is not None and d.get("kind") == "Job"]
    assert len(docs) >= 1

    mig_job = docs[0]
    containers = mig_job["spec"]["template"]["spec"]["containers"]
    assert len(containers) == 1
    mig_container = containers[0]

    assert mig_container["command"] == ["alembic", "upgrade", "head"]

    # Check that DATABASE_USER is privguard_migrator
    env_vars = {e["name"]: e.get("value") for e in mig_container["env"]}
    assert env_vars.get("DATABASE_USER") == "privguard_migrator"


def test_08_service_account_automount_token_disabled():
    """Verify ServiceAccount and workloads disable automountServiceAccountToken by default."""
    prod_values = os.path.join(CHART_DIR, "values", "production.yaml")
    code, stdout, _ = run_helm_command("template", "privguard", CHART_DIR, "-f", prod_values)
    assert code == 0

    docs = [d for d in yaml.safe_load_all(stdout) if d is not None]
    sa_docs = [d for d in docs if d.get("kind") == "ServiceAccount"]
    assert len(sa_docs) == 1
    assert sa_docs[0].get("automountServiceAccountToken") is False

    workload_docs = [d for d in docs if d.get("kind") in ("Deployment", "Job")]
    for doc in workload_docs:
        pod_spec = (
            doc["spec"]["template"]["spec"]
            if "template" in doc["spec"]
            else doc["spec"]
        )
        assert pod_spec.get("automountServiceAccountToken") is False


def test_09_values_schema_validation():
    """Verify values.schema.json exists and validates required fields."""
    schema_path = os.path.join(CHART_DIR, "values.schema.json")
    assert os.path.isfile(schema_path)

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    assert "database" in schema["required"]
    assert "redis" in schema["required"]
    assert "secrets" in schema["required"]


@pytest.mark.asyncio
async def test_10_rate_limiter_fail_closed_in_production():
    """Verify DistributedRateLimiter fails closed for sensitive tiers when Redis is offline under strict policy."""
    limiter = DistributedRateLimiter(custom_redis=None)
    policy = RateLimitPolicy(max_requests=10, window_seconds=60)

    # In strict fail-closed mode (Kubernetes production), AUTHENTICATION fails closed immediately
    res_auth = await limiter.check_rate_limit(
        tenant_id="prod_tenant",
        category="AUTHENTICATION",
        identifier="admin_login_ip",
        custom_policy=policy,
        strict_fail_closed=True,
    )
    assert res_auth.allowed is False
    assert res_auth.backend_mode == "fail_closed_redis_unavailable"

    # ADMIN mutations also fail closed
    res_admin = await limiter.check_rate_limit(
        tenant_id="prod_tenant",
        category="ADMIN",
        identifier="admin_user_id",
        custom_policy=policy,
        strict_fail_closed=True,
    )
    assert res_admin.allowed is False
    assert res_admin.backend_mode == "fail_closed_redis_unavailable"
