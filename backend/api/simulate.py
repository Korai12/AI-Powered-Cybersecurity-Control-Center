"""Simulate endpoint — triggers attack scenarios on the log_generator.

POST /api/v1/simulate/{scenario}
Scenarios: ransomware | credential_stuffing | insider_threat | exploit | noise
"""
from __future__ import annotations
import logging, os
import httpx
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()

GENERATOR_URL = os.environ.get("GENERATOR_URL", "http://log_generator:8080")

VALID_SCENARIOS = {
    "ransomware":          "S-01: Ransomware Deployment (~90s, CRITICAL)",
    "credential_stuffing": "S-02: Credential Stuffing (~3min, HIGH)",
    "insider_threat":      "S-03: Insider Threat (~2min, HIGH)",
    "exploit":             "S-04: Log4Shell Exploit (~60s, CRITICAL)",
    "noise":               "S-05: Background Noise (continuous, LOW/MEDIUM)",
}


class SimulateResponse(BaseModel):
    scenario: str
    description: str
    status: str
    message: str


@router.post("/simulate/{scenario}", response_model=SimulateResponse, tags=["simulate"])
async def trigger_scenario(scenario: str, background_tasks: BackgroundTasks):
    """Trigger an attack scenario on the log generator."""
    if scenario not in VALID_SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{scenario}'. Valid: {list(VALID_SCENARIOS.keys())}",
        )

    description = VALID_SCENARIOS[scenario]

    # Forward to log_generator's internal trigger endpoint
    background_tasks.add_task(_trigger_generator, scenario)

    return SimulateResponse(
        scenario=scenario,
        description=description,
        status="triggered",
        message=f"Scenario '{scenario}' triggered. Events will appear in the feed shortly.",
    )


@router.get("/simulate/scenarios", tags=["simulate"])
async def list_scenarios():
    """List all available attack scenarios."""
    return {
        "scenarios": [
            {"id": k, "description": v}
            for k, v in VALID_SCENARIOS.items()
        ]
    }


async def _trigger_generator(scenario: str):
    """Background task — POST to log_generator trigger endpoint."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(f"{GENERATOR_URL}/trigger/{scenario}")
    except Exception as exc:
        logger.warning("Could not reach log_generator to trigger '%s': %s", scenario, exc)