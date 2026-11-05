"""Data Exfiltration Detector & Taint Tracking Engine (MITRE ATT&CK T1700)."""

import urllib.parse
from typing import Dict, List, Optional, Set
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.threat_detection.schemas import (
    ThreatAction,
    ThreatAssessment,
    ThreatSeverity,
    ThreatSignal,
    ThreatType,
)
from app.threat_detection.rules.behavior_signatures import (
    CONFIDENTIAL_RESOURCE_PATTERNS,
    DEFAULT_ALLOWLISTED_DOMAINS,
    OUTBOUND_SINK_TOOLS,
    SENSITIVE_READ_TOOLS,
)
from app.privacy.secret_scanner import SecretScanner
from app.database.models import ActiveTaint
from app.infrastructure.taint_store import DistributedTaintStore


class ExfiltrationDetector:
    """Monitors taint propagation and intercepts covert data exfiltration attempts."""

    def __init__(
        self,
        secret_scanner: SecretScanner,
        allowlisted_destinations: Optional[Set[str]] = None,
        taint_store: Optional[DistributedTaintStore] = None,
    ) -> None:
        self.secret_scanner = secret_scanner
        self.allowlisted_destinations = allowlisted_destinations or set(DEFAULT_ALLOWLISTED_DOMAINS)
        # In-memory fast cache of tainted tasks: task_id -> set of tainted resources
        self._tainted_tasks: Dict[str, Set[str]] = {}
        self.taint_store = taint_store or DistributedTaintStore()

    def is_confidential_resource(self, resource: Optional[str]) -> bool:
        """Determines if a target resource path or identifier contains confidential patterns."""
        if not resource:
            return False
        res_lower = resource.lower()
        return any(pat in res_lower for pat in CONFIDENTIAL_RESOURCE_PATTERNS)

    def register_confidential_resource(self, resource: str) -> None:
        """Registers a resource pattern as explicitly confidential."""
        if resource.lower() not in CONFIDENTIAL_RESOURCE_PATTERNS:
            CONFIDENTIAL_RESOURCE_PATTERNS.append(resource.lower())

    def propagate_taint(self, task_id: str, resource: str) -> None:
        """Synchronously taints an in-memory task session with a confidential resource."""
        if task_id not in self._tainted_tasks:
            self._tainted_tasks[task_id] = set()
        self._tainted_tasks[task_id].add(resource)

    async def record_access(
        self,
        db: AsyncSession,
        task_id: str,
        tool_name: str,
        resource: Optional[str],
        tenant_id: str = "default_tenant",
    ) -> bool:
        """Evaluates whether tool access taints the task context with confidential data."""
        if tool_name in SENSITIVE_READ_TOOLS and self.is_confidential_resource(resource):
            if task_id not in self._tainted_tasks:
                self._tainted_tasks[task_id] = set()
            self._tainted_tasks[task_id].add(resource)

            # Persist and cache across distributed cluster
            await self.taint_store.add_taint(
                db=db,
                task_id=task_id,
                resource=resource,
                tenant_id=tenant_id,
                classification="CONFIDENTIAL",
            )
            return True
        return False

    def is_task_tainted(self, task_id: str) -> bool:
        """Checks if a task context currently carries confidential taint in local memory."""
        return task_id in self._tainted_tasks and len(self._tainted_tasks[task_id]) > 0

    async def is_task_tainted_async(
        self,
        db: AsyncSession,
        task_id: str,
        tenant_id: str = "default_tenant",
    ) -> bool:
        """Monotonically checks if a task context carries confidential taint across replicas."""
        if self.is_task_tainted(task_id):
            return True
        return await self.taint_store.is_task_tainted(db, task_id, tenant_id)

    def get_task_taints(self, task_id: str) -> List[str]:
        """Returns the list of tainted resources for a task from local cache."""
        return list(self._tainted_tasks.get(task_id, set()))

    async def get_task_taints_async(
        self,
        db: AsyncSession,
        task_id: str,
        tenant_id: str = "default_tenant",
    ) -> List[str]:
        """Returns the list of tainted resources across distributed cluster."""
        local_taints = self.get_task_taints(task_id)
        if local_taints:
            return local_taints
        return await self.taint_store.get_task_taints(db, task_id, tenant_id)

    def clear_task_taint(self, task_id: str) -> None:
        """Clears in-memory taint cache for a task."""
        if task_id in self._tainted_tasks:
            del self._tainted_tasks[task_id]

    async def clear_task_taint_async(
        self,
        db: AsyncSession,
        task_id: str,
        tenant_id: str = "default_tenant",
    ) -> None:
        """Clears in-memory and distributed taint records across cluster."""
        self.clear_task_taint(task_id)
        await self.taint_store.clear_task_taints(db, task_id, tenant_id)

    def _extract_destination_host(self, params: dict) -> Optional[str]:
        """Extracts destination host/domain from outbound tool parameters."""
        url_candidate = params.get("url") or params.get("endpoint") or params.get("to_address")
        if not url_candidate:
            return None
        # Handle email
        if "@" in str(url_candidate):
            return str(url_candidate).split("@")[-1].lower()
        # Handle URL
        try:
            parsed = urllib.parse.urlparse(str(url_candidate))
            return (parsed.hostname or "").lower()
        except Exception:
            return None

    def evaluate_outbound_tool(
        self,
        task_id: str,
        tool_name: str,
        params: dict,
    ) -> ThreatAssessment:
        """Validates outbound tool invocations against task taint status and destination allowlists."""
        if tool_name not in OUTBOUND_SINK_TOOLS:
            return ThreatAssessment(is_threat=False, signals=[], action=ThreatAction.ALLOW)

        signals: List[ThreatSignal] = []

        # 1. Inspect outgoing arguments for raw secrets or keys
        param_str = str(params)
        secret_findings = self.secret_scanner.scan(param_str)
        if secret_findings:
            signals.append(

                ThreatSignal(
                    threat_type=ThreatType.DATA_EXFILTRATION,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=1.0,
                    rule_id="EXFIL_SECRET_PAYLOAD_001",
                    description=f"Raw credential/secret detected in outbound tool payload: {secret_findings[0].secret_type}",
                    indicators=[secret_findings[0].secret_type],
                    recommended_action=ThreatAction.BLOCK,
                )
            )

        # 2. Check if the task context is tainted with confidential data
        if self.is_task_tainted(task_id):
            destination = self._extract_destination_host(params)
            tainted_sources = self.get_task_taints(task_id)

            # If destination is missing or not allowlisted, block the transfer
            if not destination or destination not in self.allowlisted_destinations:
                signals.append(
                    ThreatSignal(
                        threat_type=ThreatType.DATA_EXFILTRATION,
                        severity=ThreatSeverity.CRITICAL,
                        confidence=0.96,
                        rule_id="EXFIL_TAINT_SINK_001",
                        description=(
                            f"MITRE T1700 Exfiltration blocked: Task previously accessed confidential resource "
                            f"{tainted_sources} and attempted outbound transmission via '{tool_name}' to "
                            f"non-allowlisted destination '{destination or 'unknown'}'."
                        ),
                        indicators=[f"taint={','.join(tainted_sources)}", f"destination={destination}"],
                        recommended_action=ThreatAction.BLOCK,
                    )
                )

        if not signals:
            return ThreatAssessment(
                is_threat=False,
                max_severity=ThreatSeverity.LOW,
                overall_risk_score=0.0,
                signals=[],
                action=ThreatAction.ALLOW,
                reason="Outbound call verified clean.",
            )

        return ThreatAssessment(
            is_threat=True,
            max_severity=ThreatSeverity.CRITICAL,
            overall_risk_score=1.0,
            signals=signals,
            action=ThreatAction.BLOCK,
            reason="Exfiltration defense triggered.",
        )
