from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_current_user
from database import get_db
from services.ai.chat import (
    create_or_append_user_message,
    delete_conversation_session,
    get_conversation_session,
    list_conversation_sessions,
    process_chat_message,
)

router = APIRouter(prefix="/chat", tags=["Chat"])


class ChatMessageRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=4000)
    session_id: Optional[str] = None
    related_incident_id: Optional[str] = None


class ChatMessageAccepted(BaseModel):
    session_id: str
    status: str
    title: str
    queued: bool = True
    message: str


@router.post("/message", response_model=ChatMessageAccepted, status_code=status.HTTP_202_ACCEPTED)
async def send_chat_message(
    body: ChatMessageRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    try:
        result = await create_or_append_user_message(
            db,
            analyst_id=current_user["id"],
            query=body.query,
            session_id=body.session_id,
            related_incident_id=body.related_incident_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    source_ip = request.client.host if request.client else None
    background_tasks.add_task(
        process_chat_message,
        session_id=result["session_id"],
        analyst_id=current_user["id"],
        query=body.query,
        source_ip=source_ip,
    )

    return ChatMessageAccepted(
        session_id=result["session_id"],
        status="processing",
        title=result["title"],
        message="Chat request accepted. Connect to /ws/chat/{session_id} to receive tokens.",
    )


@router.get("/sessions")
async def list_chat_sessions(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    return await list_conversation_sessions(
        db,
        analyst_id=current_user["id"],
        limit=limit,
        offset=offset,
    )


@router.get("/sessions/{session_id}")
async def get_chat_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    try:
        return await get_conversation_session(
            db,
            analyst_id=current_user["id"],
            session_id=session_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/sessions/{session_id}")
async def delete_chat_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    try:
        await delete_conversation_session(
            db,
            analyst_id=current_user["id"],
            session_id=session_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return {"status": "deleted", "session_id": session_id}