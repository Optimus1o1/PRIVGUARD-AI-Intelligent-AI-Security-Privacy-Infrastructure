"""OpenAI-compatible AI Security Gateway.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import time
import uuid
from typing import Any, Dict, List, Optional
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.authentication import get_current_app
from app.core.config import settings
from app.core.exceptions import SecretDetectedError
from app.database.connection import get_db_session
from app.database.models import Application
from app.monitoring.audit import audit_logger
from app.privacy.pipeline import inspection_pipeline
from app.privacy.redactor import redactor

router = APIRouter(prefix="/v1", tags=["Model Gateway"])


class ChatMessage(BaseModel):
    role: str
    content: str
    name: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False
    tools: Optional[List[Dict[str, Any]]] = None
    tool_choice: Optional[Any] = None


class ChatChoice(BaseModel):
    index: int
    message: Dict[str, Any]
    finish_reason: Optional[str] = "stop"


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[ChatChoice]
    usage: Dict[str, int]
    privguard_meta: Dict[str, Any]


@router.post("/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(
    payload: ChatCompletionRequest,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> ChatCompletionResponse:
    """
    OpenAI-compatible chat completions gateway with automated security inspection,
    credential blocking, PII redaction, and zero-content audit logging.
    """
    request_id = f"pg_req_{uuid.uuid4().hex[:12]}"
    start_time = time.perf_counter()

    raw_messages = [msg.model_dump() for msg in payload.messages]

    # 1. Security Inspection Pipeline
    sanitized_messages, verdict, redaction_mapping = inspection_pipeline.inspect_messages(raw_messages)

    # 2. Invariant Check: Hard Fail-Closed on Secrets
    if verdict.is_blocked:
        # Audit the block event (Metadata only! No raw secret!)
        await audit_logger.log_event(
            db=db,
            request_id=request_id,
            app_id=current_app.id,
            event_type="SECRET_BLOCKED",
            action_taken="BLOCK",
            risk_level=verdict.risk_level.value,
            data_category=verdict.category.value,
            entity_counts=verdict.entity_counts,
            content_fingerprint=verdict.content_fingerprint,
            status="BLOCKED",
        )
        raise SecretDetectedError(
            secret_type=verdict.detected_secrets[0]["type"] if verdict.detected_secrets else "UNKNOWN",
            match_preview=verdict.detected_secrets[0]["preview"] if verdict.detected_secrets else "****",
            details={"request_id": request_id},
        )

    # 3. Audit PII Redaction or Clean Inspection
    event_type = "PII_REDACTED" if verdict.action.value == "REDACT" else "REQUEST_INSPECTED"
    await audit_logger.log_event(
        db=db,
        request_id=request_id,
        app_id=current_app.id,
        event_type=event_type,
        action_taken=verdict.action.value,
        risk_level=verdict.risk_level.value,
        data_category=verdict.category.value,
        entity_counts=verdict.entity_counts,
        content_fingerprint=verdict.content_fingerprint,
        status="SUCCESS",
    )

    # 4. Model Invocation / Upstream Proxying
    # If upstream API key is present, forward to real upstream provider
    if settings.UPSTREAM_LLM_API_KEY:
        upstream_payload = payload.model_dump()
        upstream_payload["messages"] = sanitized_messages
        headers = {
            "Authorization": f"Bearer {settings.UPSTREAM_LLM_API_KEY}",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=settings.UPSTREAM_TIMEOUT_SECONDS) as client:
                res = await client.post(
                    f"{settings.UPSTREAM_LLM_BASE_URL}/chat/completions",
                    json=upstream_payload,
                    headers=headers,
                )
                res.raise_for_status()
                model_data = res.json()
                assistant_content = model_data["choices"][0]["message"]["content"]
        except Exception as e:
            raise HTTPException(
                status_code=502,
                detail=f"Upstream model gateway error: {str(e)}",
            )
    else:
        # Local development / test mode: Generate compliant mock completion demonstrating sanitization
        last_sanitized_msg = sanitized_messages[-1]["content"] if sanitized_messages else ""
        assistant_content = (
            f"[PRIVGUARD PROTECTED COMPLETED] Successfully processed sanitized prompt: '{last_sanitized_msg}'"
        )

    # 5. Optional Reversible De-Redaction for Client
    restored_content = assistant_content
    if redaction_mapping:
        restored_content = redactor.restore(assistant_content, redaction_mapping)

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return ChatCompletionResponse(
        id=request_id,
        created=int(time.time()),
        model=payload.model,
        choices=[
            ChatChoice(
                index=0,
                message={
                    "role": "assistant",
                    "content": restored_content,
                },
                finish_reason="stop",
            )
        ],
        usage={
            "prompt_tokens": len(" ".join([m["content"] for m in sanitized_messages]).split()),
            "completion_tokens": len(restored_content.split()),
            "total_tokens": len(restored_content.split()) + 10,
        },
        privguard_meta={
            "request_id": request_id,
            "security_action": verdict.action.value,
            "data_category": verdict.category.value,
            "risk_level": verdict.risk_level.value,
            "entities_redacted": verdict.entity_counts,
            "latency_ms": elapsed_ms,
        },
    )
