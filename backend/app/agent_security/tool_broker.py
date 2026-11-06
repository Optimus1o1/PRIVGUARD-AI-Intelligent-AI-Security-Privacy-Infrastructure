"""Central Agent Security Tool Execution Broker."""

import asyncio
import time
from typing import Any, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.agent_security.capability_manager import capability_manager
from app.agent_security.identity import agent_identity_manager
from app.agent_security.permission_engine import permission_engine
from app.agent_security.task_manager import task_manager
from app.agent_security.tool_registry import tool_registry
from app.approvals.approval_engine import approval_engine
from app.core.exceptions import (
    ApprovalRequiredError,
    PrivGuardException,
    ResponseSecurityViolationError,
)
from app.core.security import content_hash
from app.database.models import Application, ToolExecutionRecord, utcnow
from app.monitoring.audit import audit_logger
from app.privacy.secret_scanner import secret_scanner
from app.threat_detection import (
    behavior_analyzer,
    exfiltration_detector,
    threat_response_engine,
)
from app.threat_detection.schemas import (
    BehavioralEvent,
    ThreatAction,
)


class ToolBroker:
    """Mediates all tool execution requests, enforcing identity, capabilities, and human approvals."""

    def __init__(self):
        self.identity_mgr = agent_identity_manager
        self.task_mgr = task_manager
        self.registry = tool_registry
        self.perms = permission_engine
        self.caps = capability_manager
        self.approvals = approval_engine
        self.secrets = secret_scanner
        self.behavior_analyzer = behavior_analyzer
        self.exfiltration_detector = exfiltration_detector
        self.threat_response = threat_response_engine

    async def execute(
        self,
        db: AsyncSession,
        app: Application,
        agent_id: str,
        task_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        capability_token: str,
        approval_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Full mediated execution pipeline:
        Identity -> Tool -> Schema -> Capability -> Approval -> Sandbox -> Output Scan -> Audit.
        """
        start_time = time.perf_counter()

        # 1. Identity Validation (Never trust self-asserted identity)
        agent = await self.identity_mgr.validate_agent_active(db, agent_id, app.id)

        # 2. Task State Validation & Step Budget Tracking
        task = await self.task_mgr.validate_task_active(db, task_id, app.id, agent_id)
        await self.task_mgr.record_step(db, task_id, app.id)

        # 3. Tool Allowlist & Schema Validation
        tool = self.registry.get_tool(tool_name)
        self.registry.validate_parameters(tool_name, parameters)

        # 4. Agent Permission Check (Least privilege allowlist)
        self.perms.check_agent_tool_permission(agent, tool_name)

        # Extract target resource for scope checks
        target_resource = parameters.get("path") or parameters.get("domain") or parameters.get("recipient")

        # 5. Capability Token Verification (Validate bounds & quota before approval check)
        grant = await self.caps.validate_and_consume(
            db=db,
            raw_secret=capability_token,
            expected_tool=tool_name,
            expected_agent_id=agent_id,
            expected_task_id=task_id,
            expected_app_id=app.id,
            resource=target_resource,
            consume=False,
        )

        # 5b. Record Behavioral Event & Sequence Evaluation (Stage 4)
        params_fp = content_hash(str(parameters))
        self.behavior_analyzer.record_event(
            BehavioralEvent(
                agent_id=agent_id,
                task_id=task_id,
                tool_name=tool_name,
                target_resource=target_resource,
                status="ATTEMPTED",
                timestamp=utcnow(),
                parameters_fingerprint=params_fp,
            )
        )

        behavior_assessment = self.behavior_analyzer.evaluate_behavior(task_id)
        if behavior_assessment.is_threat:
            await self.threat_response.log_threat_event(
                db=db,
                application_id=app.id,
                assessment=behavior_assessment,
                task_id=task_id,
                agent_id=agent_id,
                content_for_hash=str(parameters),
            )
            if behavior_assessment.action == ThreatAction.TERMINATE_TASK:
                await self.task_mgr.cancel_task(db, task_id, app.id)
                raise PrivGuardException(
                    message=behavior_assessment.reason or "Task terminated due to anomalous runaway behavior.",
                    status_code=403,
                    error_code="TASK_TERMINATED_DUE_TO_THREAT",
                )
            elif behavior_assessment.action == ThreatAction.BLOCK:
                raise PrivGuardException(
                    message=behavior_assessment.reason or "Operation blocked due to anomalous tool sequence.",
                    status_code=403,
                    error_code="BEHAVIORAL_THREAT_BLOCKED",
                )

        # 5c. Outbound Sink & Exfiltration Defense (MITRE T1700)
        exfil_assessment = self.exfiltration_detector.evaluate_outbound_tool(
            task_id=task_id,
            tool_name=tool_name,
            params=parameters,
        )
        if exfil_assessment.is_threat and exfil_assessment.action == ThreatAction.BLOCK:
            await self.threat_response.log_threat_event(
                db=db,
                application_id=app.id,
                assessment=exfil_assessment,
                task_id=task_id,
                agent_id=agent_id,
                content_for_hash=str(parameters),
            )
            raise PrivGuardException(
                message=exfil_assessment.reason or "Outbound data exfiltration attempt blocked (MITRE T1700).",
                status_code=403,
                error_code="DATA_EXFILTRATION_BLOCKED",
            )

        # 6. Human-in-the-Loop Approval Check (for High/Critical risk actions)
        if tool.requires_approval:
            if not approval_id:
                # Create pending approval request and hold execution
                appr_req = await self.approvals.create_request(
                    db=db,
                    task_id=task_id,
                    agent_id=agent_id,
                    app_id=app.id,
                    tool_name=tool_name,
                    target_resource=target_resource,
                    parameters=parameters,
                    risk_level=tool.risk_level,
                )
                task.status = "WAITING_FOR_APPROVAL"
                await db.commit()

                # Audit approval creation event
                await audit_logger.log_event(
                    db=db,
                    request_id=f"appr_{appr_req.id}",
                    app_id=app.id,
                    event_type="APPROVAL_REQUESTED",
                    action_taken="REQUIRE_APPROVAL",
                    risk_level=tool.risk_level,
                    data_category="AGENT_TOOL_ACTION",
                    entity_counts={"PENDING_APPROVAL": 1},
                    content_fingerprint=appr_req.action_hash,
                    status="WAITING",
                )

                raise ApprovalRequiredError(
                    approval_id=appr_req.id,
                    tool_name=tool_name,
                    message=f"Operation requires human authorization. Approval ID: '{appr_req.id}'",
                )
            else:
                # Verify and atomically consume approval (recomputes action_hash against tampering!)
                await self.approvals.verify_and_consume(
                    db=db,
                    approval_id=approval_id,
                    tool_name=tool_name,
                    target_resource=target_resource,
                    parameters=parameters,
                    app_id=app.id,
                )
                task.status = "RUNNING"
                await db.commit()

        # 7. Consume Capability Use (Quota deduction upon approved execution)
        await self.caps.consume_use(db, grant)

        # 8. Sandboxed Execution with Enforced Timeout
        handler = self.registry.get_handler(tool_name)
        try:
            exec_params = dict(parameters)
            exec_params["_app_id"] = app.id
            raw_output = await asyncio.wait_for(
                handler(exec_params),
                timeout=tool.timeout_seconds,
            )
        except asyncio.TimeoutError:
            raise PrivGuardException(
                message=f"Execution of tool '{tool_name}' timed out after {tool.timeout_seconds} seconds.",
                status_code=504,
                error_code="TOOL_EXECUTION_TIMEOUT",
            )
        except Exception as e:
            if isinstance(e, PrivGuardException):
                raise
            raise PrivGuardException(
                message=f"Error executing tool '{tool_name}': {str(e)}",
                status_code=500,
                error_code="TOOL_EXECUTION_FAILED",
            )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        output_str = str(raw_output)

        # 8. Output Security Inspection
        secret_matches = self.secrets.scan(output_str)
        if secret_matches:
            first_match = secret_matches[0]
            await audit_logger.log_event(
                db=db,
                request_id=f"tool_{task_id}_{tool_name}",
                app_id=app.id,
                event_type="TOOL_OUTPUT_SECRET_BLOCKED",
                action_taken="BLOCK",
                risk_level="CRITICAL",
                data_category="CRITICAL",
                entity_counts={"OUTPUT_LEAKED_SECRET": 1},
                content_fingerprint=content_hash(output_str),
                status="BLOCKED",
            )
            raise ResponseSecurityViolationError(
                violation_type=first_match.secret_type,
                preview=first_match.preview,
                reason="Sensitive credential or secret detected in tool execution output.",
            )

        output_fp = content_hash(output_str)

        # 9. Record Tool Execution
        exec_record = ToolExecutionRecord(
            task_id=task_id,
            agent_id=agent_id,
            app_id=app.id,
            tool_name=tool_name,
            target_resource=target_resource,
            status="SUCCESS",
            execution_duration_ms=elapsed_ms,
            output_fingerprint=output_fp,
        )
        db.add(exec_record)

        # 10. Audit Logging (Zero content invariant: metadata only!)
        await audit_logger.log_event(
            db=db,
            request_id=f"exec_{exec_record.id}",
            app_id=app.id,
            event_type="TOOL_EXECUTED",
            action_taken="ALLOW",
            risk_level=tool.risk_level,
            data_category="TOOL_OPERATION",
            entity_counts={"TOOL_CALL": 1},
            content_fingerprint=output_fp,
            status="SUCCESS",
        )
        await db.commit()

        # 11. Taint Tracking for Sensitive Resource Access (Stage 4)
        await self.exfiltration_detector.record_access(
            db=db,
            task_id=task_id,
            tool_name=tool_name,
            resource=target_resource,
        )

        return {
            "execution_id": exec_record.id,
            "status": "SUCCESS",
            "tool": tool_name,
            "output": output_str,
            "duration_ms": elapsed_ms,
        }


# Shared tool broker instance
tool_broker = ToolBroker()
