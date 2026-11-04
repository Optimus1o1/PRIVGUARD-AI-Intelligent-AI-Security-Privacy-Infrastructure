"""Deterministic policy evaluation engine."""

from typing import Dict, List, Optional
from app.core.config import settings
from app.policies.schemas import PolicyAction, PolicyDecision


# Default system baseline policy rules
DEFAULT_POLICY_RULES: Dict[str, tuple[PolicyAction, str, str]] = {
    # category -> (action, risk_level, reason)
    "CRITICAL": (
        PolicyAction.BLOCK,
        "CRITICAL",
        "Sensitive credentials and secrets are strictly forbidden from model context.",
    ),
    "CONFIDENTIAL": (
        PolicyAction.REQUIRE_APPROVAL,
        "HIGH",
        "Confidential documents and resources require explicit authorization.",
    ),
    "PERSONAL": (
        PolicyAction.REDACT,
        "MEDIUM",
        "Personal Identifiable Information (PII) must be redacted before transmission.",
    ),
    "INTERNAL": (
        PolicyAction.ALLOW,
        "LOW",
        "Internal project metadata permitted by default policy.",
    ),
    "PUBLIC": (
        PolicyAction.ALLOW,
        "LOW",
        "Public content permitted.",
    ),
}


class PolicyEngine:
    """Evaluates privacy and security rules deterministically."""

    def __init__(self, custom_rules: Optional[Dict[str, tuple[PolicyAction, str, str]]] = None):
        self.rules = {**DEFAULT_POLICY_RULES, **(custom_rules or {})}

    def evaluate(
        self,
        category: str,
        has_secrets: bool = False,
        detected_entities: Optional[List[str]] = None,
    ) -> PolicyDecision:
        """
        Evaluates input against policy matrix and yields an actionable decision.
        """
        # Invariant 1: Secrets are NEVER allowed and cannot be merely redacted
        if has_secrets or category == "CRITICAL":
            return PolicyDecision(
                action=PolicyAction.BLOCK,
                risk_level="CRITICAL",
                reason="Credentials, API keys, or private keys detected in payload.",
                matched_rule="RULE_CRITICAL_SECRET_BLOCK",
                allow_execution=False,
            )

        # Lookup rule for category
        rule = self.rules.get(category)
        if not rule:
            # Fallback fail-closed or default to safe action
            return PolicyDecision(
                action=PolicyAction.BLOCK if settings.FAIL_CLOSED_MODE else PolicyAction.REDACT,
                risk_level="HIGH",
                reason=f"Unknown category '{category}'. Fail-closed enforcement applied.",
                matched_rule="RULE_UNKNOWN_CATEGORY_FALLBACK",
                allow_execution=False,
            )

        action, risk_level, reason = rule

        allow_exec = action in (PolicyAction.ALLOW, PolicyAction.REDACT)
        return PolicyDecision(
            action=action,
            risk_level=risk_level,
            reason=reason,
            matched_rule=f"RULE_{category}_{action.value}",
            allow_execution=allow_exec,
        )


# Shared policy engine instance
policy_engine = PolicyEngine()

