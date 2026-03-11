"""
main.py — FastAPI application entry point.
Handles: lifespan (startup/shutdown), CORS, router registration, /health endpoint.
"""
import logging
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from database import wait_for_database, check_database_health
from chromadb_client import wait_for_chromadb, check_chromadb_health

# ── Settings ──────────────────────────────────────────────────────────────────
settings = get_settings()

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Redis client (module-level, re-used across requests) ─────────────────────
redis_client: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    return redis_client


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: validate required connections before accepting traffic.
    Shutdown: clean up connection pools.
    """
    global redis_client

    logger.info("ACCC backend starting up…")

    # 1. Wait for PostgreSQL
    logger.info("Connecting to PostgreSQL…")
    await wait_for_database()

    # 2. Connect to Redis (retry pattern mirrors DB)
    logger.info("Connecting to Redis…")
    for attempt in range(1, 16):
        try:
            redis_client = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5,
            )
            await redis_client.ping()
            logger.info("Redis connection established ✓")
            break
        except Exception as exc:
            if attempt < 15:
                import asyncio
                logger.info("Waiting for redis… attempt %d/15 (%s)", attempt, str(exc)[:60])
                await asyncio.sleep(2)
            else:
                raise RuntimeError(f"Cannot connect to Redis: {exc}") from exc

    # 3. Wait for ChromaDB
    logger.info("Connecting to ChromaDB…")
    await wait_for_chromadb()

    # 4. Start scheduler (imported here to avoid circular import)
    from scheduler import start_scheduler, stop_scheduler
    await start_scheduler()

    logger.info("ACCC backend ready ✓")
    yield

    # Shutdown
    logger.info("ACCC backend shutting down…")
    from scheduler import stop_scheduler
    await stop_scheduler()
    if redis_client:
        await redis_client.aclose()
    logger.info("Shutdown complete.")


# ── Application ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="ACCC — AI-Powered Cybersecurity Control Center",
    version="2.1.0",
    description="AI-driven SOC platform with agentic investigation, real-time threat intel, and multi-role access.",
    docs_url="/docs" if settings.is_development else None,
    redoc_url="/redoc" if settings.is_development else None,
    lifespan=lifespan,
)

# ── CORS (G-10) ───────────────────────────────────────────────────────────────
# development: wildcard  |  production: localhost:3000 only
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
# Imported here after app is created to avoid circular imports.
# Each router is implemented in its respective phase.
from api.auth import router as auth_router
from api.events import router as events_router
from api.incidents import router as incidents_router
from api.chat import router as chat_router
from api.hunt import router as hunt_router
from api.actions import router as actions_router
from api.intel import router as intel_router
from api.dashboard import router as dashboard_router
from api.assets import router as assets_router
from api.feedback import router as feedback_router
from api.entities import router as entities_router
from api.websocket import router as ws_router
from api.events import router as events_router
from api.simulate import router as simulate_router

app.include_router(auth_router,       prefix="/auth",           tags=["auth"])
app.include_router(events_router,     prefix="/api/v1/events",  tags=["events"])
app.include_router(incidents_router,  prefix="/api/v1/incidents", tags=["incidents"])
app.include_router(chat_router,       prefix="/api/v1/chat",    tags=["chat"])
app.include_router(hunt_router,       prefix="/api/v1/hunt",    tags=["hunt"])
app.include_router(actions_router,    prefix="/api/v1/actions", tags=["actions"])
app.include_router(intel_router,      prefix="/api/v1/intel",   tags=["intel"])
app.include_router(dashboard_router,  prefix="/api/v1/dashboard", tags=["dashboard"])
app.include_router(assets_router,     prefix="/api/v1/assets",  tags=["assets"])
app.include_router(feedback_router,   prefix="/api/v1/feedback", tags=["feedback"])
app.include_router(entities_router,   prefix="/api/v1/entities", tags=["entities"])
app.include_router(ws_router,         prefix="/ws",             tags=["websocket"])
app.include_router(events_router, prefix="/api/v1")
app.include_router(simulate_router, prefix="/api/v1")

# ── Health Endpoint ───────────────────────────────────────────────────────────
@app.get("/health", tags=["health"])
async def health_check():
    """
    Docker health check endpoint.
    Returns 200 with service status when all dependencies are connected.
    """
    db_health = await check_database_health()
    chroma_health = check_chromadb_health()

    redis_status = "healthy"
    try:
        if redis_client:
            await redis_client.ping()
    except Exception as exc:
        redis_status = f"unhealthy: {exc}"

    return {
        "status": "ok",
        "version": "2.1.0",
        "services": {
            "database": db_health["status"],
            "redis": redis_status,
            "chromadb": chroma_health["status"],
        },
    }


@app.get("/", include_in_schema=False)
async def root():
    return {"message": "ACCC API — see /docs for endpoint reference"}
