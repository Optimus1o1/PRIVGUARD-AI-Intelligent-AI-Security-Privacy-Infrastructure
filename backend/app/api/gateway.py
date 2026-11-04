"""OpenAI-compatible AI Security Gateway with Live Upstream and Secure Streaming.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application
from app.gateway.upstream import upstream_coordinator

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


@router.post("/chat/completions", response_model=None)
async def chat_completions(
    payload: ChatCompletionRequest,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> Union[ChatCompletionResponse, StreamingResponse]:
    """
    OpenAI-compatible chat completions gateway with automated security inspection,
    credential blocking, PII redaction, upstream proxying, and secure buffered streaming.
    """
    payload_dict = payload.model_dump()

    if payload.stream:
        stream_iter = await upstream_coordinator.execute_stream(
            payload=payload_dict,
            current_app=current_app,
            db=db,
        )
        return StreamingResponse(
            stream_iter,
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    result = await upstream_coordinator.execute_completion(
        payload=payload_dict,
        current_app=current_app,
        db=db,
    )
    return ChatCompletionResponse(**result)
