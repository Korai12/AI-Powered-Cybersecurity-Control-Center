"""
ACCC WebSocket Connection Manager — backend/websocket/manager.py
Phase 2.1: Full implementation per G-02 specification.

Channels:
    'events'              — All connected analyst browsers (live alert feed)
    'chat:{session_id}'   — Per-session AI response token streaming
    'agent:{run_id}'      — Per-investigation ReAct step streaming (Phase 6)
    'hunt:{hunt_id}'      — Per-hunt progress streaming (Phase 6)

Features:
    - Channel-based connection tracking
    - broadcast(channel, message) → sends JSON to all subscribers
    - 30-second heartbeat ping to detect dead connections
    - Automatic cleanup of disconnected clients
"""

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("accc.websocket")


class ConnectionManager:
    """
    Manages all WebSocket connections organized by channel.
    Singleton instance shared across the application.
    """

    def __init__(self):
        # {channel_name: [WebSocket, ...]}
        self._connections: dict[str, list[WebSocket]] = {}
        self._heartbeat_task: asyncio.Task | None = None
        self._running = False

    async def connect(self, websocket: WebSocket, channel: str) -> None:
        """Accept a WebSocket connection and register it to a channel."""
        await websocket.accept()
        if channel not in self._connections:
            self._connections[channel] = []
        self._connections[channel].append(websocket)
        logger.info(
            f"WebSocket connected: channel='{channel}' "
            f"(total on channel: {len(self._connections[channel])})"
        )

    def disconnect(self, websocket: WebSocket, channel: str) -> None:
        """Remove a WebSocket connection from a channel."""
        if channel in self._connections:
            try:
                self._connections[channel].remove(websocket)
            except ValueError:
                pass
            # Clean up empty channels
            if not self._connections[channel]:
                del self._connections[channel]
            logger.info(f"WebSocket disconnected: channel='{channel}'")

    async def broadcast(self, channel: str, message: Any) -> None:
        """
        Send a JSON message to ALL connections on a channel.
        Automatically removes dead connections.
        """
        if channel not in self._connections:
            return

        payload = json.dumps(message) if not isinstance(message, str) else message
        dead_connections = []

        for ws in self._connections[channel]:
            try:
                await ws.send_text(payload)
            except Exception:
                dead_connections.append(ws)

        # Clean up dead connections
        for ws in dead_connections:
            self.disconnect(ws, channel)

    async def send_personal(self, websocket: WebSocket, message: Any) -> None:
        """Send a JSON message to a single WebSocket connection."""
        try:
            payload = json.dumps(message) if not isinstance(message, str) else message
            await websocket.send_text(payload)
        except Exception as e:
            logger.warning(f"Failed to send personal message: {e}")

    def get_connection_count(self, channel: str | None = None) -> int:
        """Get number of active connections, optionally filtered by channel."""
        if channel:
            return len(self._connections.get(channel, []))
        return sum(len(conns) for conns in self._connections.values())

    def get_active_channels(self) -> list[str]:
        """Return list of channels that have at least one connection."""
        return list(self._connections.keys())

    # ──────────────────────────────────────────────────────
    # Heartbeat System (30-second ping per G-02)
    # ──────────────────────────────────────────────────────

    async def start_heartbeat(self) -> None:
        """Start the background heartbeat task. Called during app lifespan startup."""
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("WebSocket heartbeat started (interval: 30s)")

    async def stop_heartbeat(self) -> None:
        """Stop the heartbeat task. Called during app lifespan shutdown."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        logger.info("WebSocket heartbeat stopped")

    async def _heartbeat_loop(self) -> None:
        """Ping all connections every 30 seconds; remove dead ones."""
        while self._running:
            try:
                await asyncio.sleep(30)
                await self._ping_all()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

    async def _ping_all(self) -> None:
        """Send a ping to every connected WebSocket, prune failures."""
        all_channels = list(self._connections.keys())
        for channel in all_channels:
            if channel not in self._connections:
                continue
            dead = []
            for ws in self._connections[channel]:
                try:
                    await ws.send_json({"type": "ping"})
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.disconnect(ws, channel)
        total = self.get_connection_count()
        if total > 0:
            logger.debug(f"Heartbeat: {total} active connections across {len(self._connections)} channels")


# ──────────────────────────────────────────────────────────
# Singleton Instance
# ──────────────────────────────────────────────────────────

manager = ConnectionManager()