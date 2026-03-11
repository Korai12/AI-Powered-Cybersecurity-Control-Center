"""
chromadb_client.py — ChromaDB HTTP client with retry on connect and collection helpers.
Retries 3 times with 5-second delay between attempts.
"""
import asyncio
import logging
from typing import Optional
import chromadb
from chromadb.config import Settings as ChromaSettings

from config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Collection names — must match seed data in init_db
COLLECTION_MITRE = "mitre_techniques"
COLLECTION_THREAT_INTEL = "threat_intel"
COLLECTION_CVE = "cve_highlights"
COLLECTION_INCIDENTS = "past_incidents"

ALL_COLLECTIONS = [COLLECTION_MITRE, COLLECTION_THREAT_INTEL, COLLECTION_CVE, COLLECTION_INCIDENTS]

_client: Optional[chromadb.HttpClient] = None


def get_chroma_client() -> chromadb.HttpClient:
    """Returns the singleton ChromaDB client. Creates it on first call."""
    global _client
    if _client is None:
        _client = chromadb.HttpClient(
            host=settings.chromadb_host,
            port=settings.chromadb_port,
            settings=ChromaSettings(anonymized_telemetry=False),
        )
    return _client


async def wait_for_chromadb(max_attempts: int = 3, delay: float = 5.0) -> None:
    """
    Retry loop for ChromaDB connection.
    Attempts connection every `delay` seconds.
    """
    for attempt in range(1, max_attempts + 1):
        try:
            client = get_chroma_client()
            client.heartbeat()
            logger.info("ChromaDB connection established ✓")
            return
        except Exception as exc:
            if attempt < max_attempts:
                logger.info(
                    "Waiting for chromadb... attempt %d/%d (%s)",
                    attempt, max_attempts, str(exc)[:60],
                )
                await asyncio.sleep(delay)
            else:
                logger.error("ChromaDB unreachable after %d attempts — giving up", max_attempts)
                raise RuntimeError(f"Cannot connect to ChromaDB: {exc}") from exc


def get_collection(name: str) -> chromadb.Collection:
    """Returns a ChromaDB collection, creating it if it doesn't exist."""
    client = get_chroma_client()
    return client.get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
    )


def check_chromadb_health() -> dict:
    """Returns health status dict for /health endpoint."""
    try:
        client = get_chroma_client()
        client.heartbeat()
        # Check all collections exist
        collections = [c.name for c in client.list_collections()]
        return {
            "status": "healthy",
            "collections": collections,
        }
    except Exception as exc:
        return {"status": "unhealthy", "error": str(exc)}
