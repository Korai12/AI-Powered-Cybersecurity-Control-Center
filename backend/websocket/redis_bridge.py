"""
ACCC Redis → WebSocket Bridge — backend/websocket/redis_bridge.py
Phase 2.1: Async Redis subscriber that bridges events to WebSocket (G-02)

Flow:
    1. Ingestion service writes event to PostgreSQL
    2. Ingestion service publishes to Redis channel 'accc:events:new'
    3. This subscriber receives the message from Redis
    4. Subscriber calls ConnectionManager.broadcast('events', event)
    5. All connected analyst browsers receive the event via WebSocket
    6. React frontend updates Zustand store → UI re-renders

CRITICAL: Uses aioredis (async) — NOT synchronous redis-py — to avoid
blocking the FastAPI event loop.
"""

import asyncio
import json
import logging

import redis.asyncio as aioredis

from config import settings
from websocket.manager import manager

logger = logging.getLogger("accc.redis_bridge")

# Redis pub/sub channel name (must match events.py publisher)
EVENTS_CHANNEL = "accc:events:new"


async def start_redis_bridge() -> None:
    """
    Subscribe to Redis 'accc:events:new' channel and forward messages
    to all WebSocket clients on the 'events' channel.

    This coroutine runs as an asyncio background task started in
    FastAPI lifespan. It reconnects automatically on Redis failures.
    """
    logger.info(f"Redis bridge starting — subscribing to '{EVENTS_CHANNEL}'")

    while True:
        try:
            r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            pubsub = r.pubsub()
            await pubsub.subscribe(EVENTS_CHANNEL)

            logger.info(f"Redis bridge connected and subscribed to '{EVENTS_CHANNEL}'")

            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        event_data = json.loads(message["data"])
                        await manager.broadcast("events", event_data)
                    except json.JSONDecodeError:
                        # If it's not JSON, broadcast as-is
                        await manager.broadcast("events", {"raw": message["data"]})
                    except Exception as e:
                        logger.error(f"Error broadcasting event: {e}")

        except asyncio.CancelledError:
            logger.info("Redis bridge shutting down")
            break
        except Exception as e:
            logger.error(f"Redis bridge connection error: {e} — reconnecting in 5s")
            await asyncio.sleep(5)
        finally:
            try:
                await pubsub.unsubscribe(EVENTS_CHANNEL)
                await r.aclose()
            except Exception:
                pass