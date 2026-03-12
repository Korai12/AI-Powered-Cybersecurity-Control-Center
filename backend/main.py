"""
ACCC Backend — main.py
Phase 2.1 Update: Auth router, 4 WebSocket endpoints, Redis bridge

Entry point for the FastAPI application. Manages:
    - CORS middleware (reads ENVIRONMENT var)
    - All API router registrations
    - Lifespan: APScheduler, Redis bridge, WebSocket heartbeat
    - Health endpoint with dependency status
    - 4 WebSocket endpoints (G-02)
"""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from config import settings
from database import get_db, engine
from scheduler import start_scheduler, stop_scheduler, get_registered_jobs
from websocket.manager import manager as ws_manager
from websocket.redis_bridge import start_redis_bridge

# --- API Routers ---
from api.auth import router as auth_router
from api.events import router as events_router
from api.simulate import router as simulate_router
from api.chat import router as chat_router

# Optional: import for WS auth
from api.dependencies import get_current_user_ws
from database import async_session_factory

logger = logging.getLogger("accc")

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)


# ══════════════════════════════════════════════════════════
# Lifespan — startup / shutdown
# ══════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages startup and shutdown of background services:
        1. APScheduler (background jobs)
        2. Redis→WebSocket bridge (event streaming)
        3. WebSocket heartbeat (30s ping)
    """
    # --- Startup ---
    logger.info("ACCC Backend starting up...")

    # Start APScheduler
    await start_scheduler()

    # Start Redis→WebSocket bridge as background task
    redis_bridge_task = asyncio.create_task(start_redis_bridge())
    logger.info("Redis→WebSocket bridge task created")

    # Start WebSocket heartbeat
    await ws_manager.start_heartbeat()

    logger.info("ACCC Backend startup complete")

    yield

    # --- Shutdown ---
    logger.info("ACCC Backend shutting down...")

    # Stop heartbeat
    await ws_manager.stop_heartbeat()

    # Cancel Redis bridge
    redis_bridge_task.cancel()
    try:
        await redis_bridge_task
    except asyncio.CancelledError:
        pass

    # Stop scheduler
    await stop_scheduler()

    logger.info("ACCC Backend shutdown complete")


# ══════════════════════════════════════════════════════════
# FastAPI App
# ══════════════════════════════════════════════════════════

app = FastAPI(
    title="ACCC — AI-Powered Cybersecurity Control Center",
    description="Real-time AI-driven SOC platform",
    version="2.4.0",
    lifespan=lifespan,
)

# ══════════════════════════════════════════════════════════
# CORS Middleware (G-10)
# ══════════════════════════════════════════════════════════

if settings.is_development:
    origins = ["*"]
else:
    origins = [
        "http://localhost:3000",
        "http://frontend:3000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════
# Router Registration
# ══════════════════════════════════════════════════════════

# Auth routes — no /api/v1 prefix (per architecture spec)
app.include_router(auth_router, prefix="")

# API routes — /api/v1 prefix
app.include_router(events_router, prefix="/api/v1")
app.include_router(simulate_router, prefix="/api/v1")

# Phase 2.4 chat_router
app.include_router(events_router, prefix="/api/v1")
app.include_router(simulate_router, prefix="/api/v1")
app.include_router(chat_router, prefix="/api/v1")
# Phase 3+ will add: incidents_router, hunt_router, actions_router, etc.


# ══════════════════════════════════════════════════════════
# Health Endpoint
# ══════════════════════════════════════════════════════════

@app.get("/health", tags=["System"])
async def health_check():
    """
    Returns service status for each dependency.
    Used by Docker health checks and monitoring.
    """
    import redis.asyncio as aioredis
    import httpx

    statuses = {}

    # PostgreSQL
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        statuses["postgres"] = "ok"
    except Exception as e:
        statuses["postgres"] = f"error: {str(e)[:100]}"

    # Redis
    try:
        r = aioredis.from_url(settings.REDIS_URL)
        await r.ping()
        await r.aclose()
        statuses["redis"] = "ok"
    except Exception as e:
        statuses["redis"] = f"error: {str(e)[:100]}"

    # ChromaDB
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{settings.CHROMADB_URL}/api/v1/heartbeat",
                timeout=5.0,
            )
            statuses["chromadb"] = "ok" if resp.status_code == 200 else f"status: {resp.status_code}"
    except Exception as e:
        statuses["chromadb"] = f"error: {str(e)[:100]}"

    statuses["websocket_connections"] = ws_manager.get_connection_count()

    overall = "ok" if all(
        v == "ok" for k, v in statuses.items() if k != "websocket_connections"
    ) else "degraded"

    scheduler_jobs = get_registered_jobs()

    return {
        "status": overall,
        "services": statuses,
        "scheduler": {
            "running": len(scheduler_jobs) > 0,
            "job_count": len(scheduler_jobs),
            "jobs": scheduler_jobs,
        },
    }

# ══════════════════════════════════════════════════════════
# WebSocket Endpoints (G-02) — All 4 channels
# ══════════════════════════════════════════════════════════

@app.websocket("/ws/events")
async def ws_events(
    websocket: WebSocket,
    token: str = Query(default=""),
):
    """
    Live event feed — all connected analyst browsers subscribe.
    Redis bridge broadcasts new events here in real-time.
    Auth: JWT token passed as ?token=<jwt> query parameter.
    """
    # Validate JWT
    async with async_session_factory() as session:
        user = await get_current_user_ws(token, session)

    if user is None:
        await websocket.close(code=4001, reason="Authentication required")
        return

    await ws_manager.connect(websocket, "events")
    try:
        # Send welcome message
        await ws_manager.send_personal(websocket, {
            "type": "connected",
            "channel": "events",
            "user": user["username"],
        })
        # Keep connection alive — listen for client messages (ping/pong)
        while True:
            data = await websocket.receive_text()
            # Client can send ping, we respond with pong
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws_manager.send_personal(websocket, {"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "events")
    except Exception as e:
        logger.error(f"WS events error: {e}")
        ws_manager.disconnect(websocket, "events")


@app.websocket("/ws/chat/{session_id}")
async def ws_chat(
    websocket: WebSocket,
    session_id: str,
    token: str = Query(default=""),
):
    """
    Per-session AI response token streaming.
    Streams tokens as {type:'token', content:'...'} then
    {type:'complete', confidence:N, evidence:[...]}.
    Auth: JWT token as ?token=<jwt> query parameter.
    """
    # Validate JWT
    async with async_session_factory() as session:
        user = await get_current_user_ws(token, session)

    if user is None:
        await websocket.close(code=4001, reason="Authentication required")
        return

    channel = f"chat:{session_id}"
    await ws_manager.connect(websocket, channel)
    try:
        await ws_manager.send_personal(websocket, {
            "type": "connected",
            "channel": channel,
            "session_id": session_id,
        })
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws_manager.send_personal(websocket, {"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, channel)
    except Exception:
        ws_manager.disconnect(websocket, channel)


@app.websocket("/ws/agent/{run_id}")
async def ws_agent(
    websocket: WebSocket,
    run_id: str,
    token: str = Query(default=""),
):
    """
    Per-investigation ReAct agent step streaming (Phase 6).
    Streams each think/act/observe step live.
    STUB — accepts connections but only sends connected message.
    """
    async with async_session_factory() as session:
        user = await get_current_user_ws(token, session)

    if user is None:
        await websocket.close(code=4001, reason="Authentication required")
        return

    channel = f"agent:{run_id}"
    await ws_manager.connect(websocket, channel)
    try:
        await ws_manager.send_personal(websocket, {
            "type": "connected",
            "channel": channel,
            "run_id": run_id,
            "status": "stub — full implementation in Phase 6",
        })
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws_manager.send_personal(websocket, {"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, channel)
    except Exception:
        ws_manager.disconnect(websocket, channel)


@app.websocket("/ws/hunt/{hunt_id}")
async def ws_hunt(
    websocket: WebSocket,
    hunt_id: str,
    token: str = Query(default=""),
):
    """
    Per-hunt progress streaming (Phase 6).
    Streams hunt progress steps as they complete.
    STUB — accepts connections but only sends connected message.
    """
    async with async_session_factory() as session:
        user = await get_current_user_ws(token, session)

    if user is None:
        await websocket.close(code=4001, reason="Authentication required")
        return

    channel = f"hunt:{hunt_id}"
    await ws_manager.connect(websocket, channel)
    try:
        await ws_manager.send_personal(websocket, {
            "type": "connected",
            "channel": channel,
            "hunt_id": hunt_id,
            "status": "stub — full implementation in Phase 6",
        })
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws_manager.send_personal(websocket, {"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, channel)
    except Exception:
        ws_manager.disconnect(websocket, channel)