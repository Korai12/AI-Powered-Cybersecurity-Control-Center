"""
ACCC OpenAI Helper — backend/services/ai/openai_helper.py
Phase 2.2: Shared utility for OpenAI API calls.

Uses httpx for HTTP calls (already a backend dependency).
Avoids the openai SDK to prevent ChromaDB compatibility issues
(Phase 1.1 finding: chromadb>=0.6.0 OpenAIEmbeddingFunction conflicts).

Provides:
    - get_embedding(text) → list[float] (1536-dim via text-embedding-3-small)
    - chat_completion(messages, model, ...) → dict (full API response)
    - chat_completion_stream(messages, model, ...) → async generator of tokens
"""

import json
import logging
from typing import AsyncGenerator

import httpx

from config import settings

logger = logging.getLogger("accc.openai")

OPENAI_BASE_URL = "https://api.openai.com/v1"
EMBEDDING_MODEL = settings.OPENAI_EMBEDDING_MODEL
PRIMARY_MODEL = settings.OPENAI_PRIMARY_MODEL
FAST_MODEL = settings.OPENAI_FAST_MODEL


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }


# ──────────────────────────────────────────────────────────
# Embeddings
# ──────────────────────────────────────────────────────────

async def get_embedding(text: str) -> list[float]:
    """
    Get a 1536-dim embedding vector for the given text.
    Uses text-embedding-3-small via direct HTTP call.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{OPENAI_BASE_URL}/embeddings",
            headers=_headers(),
            json={
                "model": EMBEDDING_MODEL,
                "input": text,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["data"][0]["embedding"]


async def get_embeddings_batch(texts: list[str]) -> list[list[float]]:
    """
    Get embeddings for multiple texts in a single API call.
    More efficient than calling get_embedding() in a loop.
    """
    if not texts:
        return []

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{OPENAI_BASE_URL}/embeddings",
            headers=_headers(),
            json={
                "model": EMBEDDING_MODEL,
                "input": texts,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        # Sort by index to ensure correct ordering
        sorted_data = sorted(data["data"], key=lambda x: x["index"])
        return [item["embedding"] for item in sorted_data]


# ──────────────────────────────────────────────────────────
# Chat Completions (non-streaming)
# ──────────────────────────────────────────────────────────

async def chat_completion(
    messages: list[dict],
    model: str = PRIMARY_MODEL,
    temperature: float = 0.3,
    max_tokens: int = 2000,
    response_format: dict | None = None,
) -> dict:
    """
    Call OpenAI chat completions API (non-streaming).
    Returns the full API response dict.

    Args:
        messages: List of {role, content} dicts
        model: Model ID (default: gpt-4.1)
        temperature: Sampling temperature
        max_tokens: Max response tokens
        response_format: Optional {"type": "json_object"} for JSON mode
    """
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if response_format:
        payload["response_format"] = response_format

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            f"{OPENAI_BASE_URL}/chat/completions",
            headers=_headers(),
            json=payload,
        )
        resp.raise_for_status()
        return resp.json()


async def chat_completion_text(
    messages: list[dict],
    model: str = PRIMARY_MODEL,
    temperature: float = 0.3,
    max_tokens: int = 2000,
) -> str:
    """Convenience: returns just the text content from chat completion."""
    data = await chat_completion(messages, model, temperature, max_tokens)
    return data["choices"][0]["message"]["content"]


async def chat_completion_json(
    messages: list[dict],
    model: str = PRIMARY_MODEL,
    temperature: float = 0.2,
    max_tokens: int = 2000,
) -> dict:
    """
    Convenience: returns parsed JSON from chat completion.
    Uses JSON mode to guarantee valid JSON output.
    """
    data = await chat_completion(
        messages, model, temperature, max_tokens,
        response_format={"type": "json_object"},
    )
    content = data["choices"][0]["message"]["content"]
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON from OpenAI response: {content[:200]}")
        return {"error": "Failed to parse AI response", "raw": content[:500]}


# ──────────────────────────────────────────────────────────
# Chat Completions (streaming)
# ──────────────────────────────────────────────────────────

async def chat_completion_stream(
    messages: list[dict],
    model: str = PRIMARY_MODEL,
    temperature: float = 0.3,
    max_tokens: int = 2000,
) -> AsyncGenerator[str, None]:
    """
    Stream chat completion tokens as they arrive from OpenAI.
    Yields individual text chunks (delta content).

    Usage:
        async for token in chat_completion_stream(messages):
            # send token to WebSocket
            await ws.send_json({"type": "token", "content": token})
    """
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": True,
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        async with client.stream(
            "POST",
            f"{OPENAI_BASE_URL}/chat/completions",
            headers=_headers(),
            json=payload,
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0].get("delta", {})
                    content = delta.get("content")
                    if content:
                        yield content
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue