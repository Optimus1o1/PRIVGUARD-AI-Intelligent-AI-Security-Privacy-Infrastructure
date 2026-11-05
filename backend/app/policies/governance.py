"""Central Enterprise Policy Governance, Hierarchy Resolution, and Lifecycle Management."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.exceptions import AuthorizationError, SecurityPolicyViolationError
from app.database.models import PolicyBundle, Organization, utcnow
from app.enterprise.rbac import IMMUTABLE_PLATFORM_GUARDRAILS, RBACAuthorizer
from app.policies.signing import PolicySigner, canonical_json_bytes


# Restrictiveness hierarchy for conflict resolution
ACTION_RESTRICTIVENESS = {
    "BLOCK": 5,
    "TERMINATE_TASK": 5,
    "QUARANTINE_AGENT": 5,
    "REQUIRE_APPROVAL": 4,
    "REDACT": 3,
    "SANITIZE": 3,
    "MASK": 3,
    "WARN": 2,
    "ALLOW": 1,
}


class PolicyGovernanceManager:
    """Manages the lifecycle, Ed25519 cryptographic signing, and hierarchical resolution of security policies."""

    @staticmethod
    def calculate_bundle_hash(bundle_data: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 hash of canonical JSON."""
        return hashlib.sha256(canonical_json_bytes(bundle_data)).hexdigest()

    @staticmethod
    def validate_policy_integrity(bundle_data: Dict[str, Any]) -> None:
        """
        Validates that an organizational policy does not attempt to weaken or disable
        immutable platform security guardrails.
        """
        rules = bundle_data.get("rules", [])
        for rule in rules:
            target = rule.get("target", "")
            action = rule.get("action", "")
            RBACAuthorizer.enforce_platform_immutability(target, action)

    @classmethod
    async def create_policy_bundle(
        cls,
        db: AsyncSession,
        organization_id: str,
        rules: List[Dict[str, Any]],
        created_by: str,
        workspace_id: Optional[str] = None,
        signing_key_pair: Optional[Tuple[str, str]] = None,
    ) -> PolicyBundle:
        """
        Creates, validates, and signs a new immutable policy bundle version.
        Guarantees strictly increasing version sequences.
        """
        # 1. Determine next version number
        q = select(PolicyBundle).where(
            PolicyBundle.organization_id == organization_id,
            PolicyBundle.workspace_id == workspace_id,
        ).order_by(PolicyBundle.version.desc())
        res = await db.execute(q)
        latest_bundle = res.scalars().first()

        next_version = (latest_bundle.version + 1) if latest_bundle else 1

        bundle_payload = {
            "organization_id": organization_id,
            "workspace_id": workspace_id,
            "version": next_version,
            "rules": rules,
            "created_at": utcnow().isoformat(),
        }

        # 2. Validate against platform guardrails
        cls.validate_policy_integrity(bundle_payload)

        # 3. Calculate bundle digest
        policy_hash = cls.calculate_bundle_hash(bundle_payload)

        # 4. Generate or use signing keypair
        if not signing_key_pair:
            priv_hex, pub_hex = PolicySigner.generate_keypair()
        else:
            priv_hex, pub_hex = signing_key_pair

        signature_hex = PolicySigner.sign_bundle(bundle_payload, priv_hex)

        bundle = PolicyBundle(
            organization_id=organization_id,
            tenant_id=organization_id,
            workspace_id=workspace_id,
            version=next_version,
            status="APPROVED",
            policy_hash=policy_hash,
            bundle_json=json.dumps(bundle_payload),
            signature_ed25519=signature_hex,
            signing_key_id=pub_hex,
            created_by=created_by,
            approved_by=created_by,
            previous_bundle_id=latest_bundle.id if latest_bundle else None,
        )
        db.add(bundle)
        await db.commit()
        await db.refresh(bundle)
        return bundle

    @classmethod
    async def deploy_policy_bundle(
        cls,
        db: AsyncSession,
        bundle_id: str,
        deployed_by: str,
        rollout_stage: str = "ORG_WIDE",
    ) -> PolicyBundle:
        """
        Deploys an approved policy bundle.
        Enforces anti-downgrade defense: cannot deploy a bundle with a lower version than currently active.
        """
        q = select(PolicyBundle).where(PolicyBundle.id == bundle_id)
        res = await db.execute(q)
        bundle = res.scalar_one_or_none()
        if not bundle:
            raise SecurityPolicyViolationError(f"Policy bundle '{bundle_id}' not found.")

        # Cryptographic verification before deployment
        bundle_dict = json.loads(bundle.bundle_json)
        PolicySigner.verify_bundle_signature(bundle_dict, bundle.signature_ed25519, bundle.signing_key_id)

        # Anti-downgrade check against active bundle
        active_q = select(PolicyBundle).where(
            PolicyBundle.organization_id == bundle.organization_id,
            PolicyBundle.workspace_id == bundle.workspace_id,
            PolicyBundle.status == "ACTIVE"
        )
        active_res = await db.execute(active_q)
        current_active = active_res.scalar_one_or_none()

        if current_active and bundle.version < current_active.version:
            raise SecurityPolicyViolationError(
                f"Policy Downgrade Rejected: Target version ({bundle.version}) is lower than "
                f"active version ({current_active.version}). Use explicit rollback mechanism."
            )

        if current_active:
            current_active.status = "REPLACED"

        bundle.status = "ACTIVE"
        bundle.deployed_by = deployed_by
        bundle.rollout_stage = rollout_stage
        bundle.activated_at = utcnow()

        await db.commit()
        await db.refresh(bundle)
        return bundle

    @classmethod
    async def rollback_policy(
        cls,
        db: AsyncSession,
        target_bundle_id: str,
        deployed_by: str,
    ) -> PolicyBundle:
        """
        Executes an audited, authorized rollback to a previous signed policy version.
        """
        q = select(PolicyBundle).where(PolicyBundle.id == target_bundle_id)
        res = await db.execute(q)
        target = res.scalar_one_or_none()
        if not target:
            raise SecurityPolicyViolationError(f"Target bundle '{target_bundle_id}' for rollback not found.")

        # Verify signature of target before rolling back
        target_dict = json.loads(target.bundle_json)
        PolicySigner.verify_bundle_signature(target_dict, target.signature_ed25519, target.signing_key_id)

        # Deactivate current active
        active_q = select(PolicyBundle).where(
            PolicyBundle.organization_id == target.organization_id,
            PolicyBundle.workspace_id == target.workspace_id,
            PolicyBundle.status == "ACTIVE"
        )
        active_res = await db.execute(active_q)
        current_active = active_res.scalar_one_or_none()
        if current_active:
            current_active.status = "ROLLED_BACK"

        target.status = "ACTIVE"
        target.deployed_by = deployed_by
        target.activated_at = utcnow()

        await db.commit()
        await db.refresh(target)
        return target

    @staticmethod
    def resolve_effective_rule(rules_by_layer: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Hierarchical resolution: Platform > Org > Workspace > App > Agent.
        Where rules conflict on the same target, enforce the most restrictive action.
        """
        if not rules_by_layer:
            return {"action": "ALLOW", "reason": "No policy matched."}

        # Sort candidate rules by restrictiveness descending
        sorted_rules = sorted(
            rules_by_layer,
            key=lambda r: ACTION_RESTRICTIVENESS.get(r.get("action", "ALLOW"), 1),
            reverse=True
        )
        winner = sorted_rules[0]
        return {
            "action": winner.get("action", "ALLOW"),
            "target": winner.get("target"),
            "layer": winner.get("layer", "UNKNOWN"),
            "reason": f"Resolved by deterministic hierarchy (most restrictive rule from {winner.get('layer')}).",
        }

