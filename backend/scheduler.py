"""
scheduler.py — APScheduler AsyncIOScheduler embedded in FastAPI lifespan.
All 8 scheduled jobs defined here. Analyst-triggered hunts run as asyncio.create_task.
"""
import logging
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)
_scheduler = AsyncIOScheduler()


# ── Job Functions (stubs — implemented in their respective phases) ─────────────

async def job_alert_triage():
    """Job 1: Triage any pending events (runs every 30s)."""
    try:
        from services.ai.triage import triage_pending_events
        await triage_pending_events()
    except Exception as exc:
        logger.error("Triage job error: %s", exc)


async def job_correlation_engine():
    """Job 2: Run multi-source correlation on recent events (every 2 min)."""
    try:
        from services.ai.correlation import run_correlation_pass
        await run_correlation_pass()
    except Exception as exc:
        logger.error("Correlation job error: %s", exc)


async def job_behavioral_baseline():
    """Job 3: Update behavioral baselines (every 10 min)."""
    try:
        from services.scoring import update_behavioral_baselines
        await update_behavioral_baselines()
    except Exception as exc:
        logger.error("Baseline job error: %s", exc)


async def job_threat_hunting():
    """Job 4: Scheduled proactive threat hunt (every 30 min)."""
    try:
        from services.ai.hunt import run_scheduled_hunt
        await run_scheduled_hunt()
    except Exception as exc:
        logger.error("Scheduled hunt job error: %s", exc)


async def job_security_posture():
    """Job 5: Recompute Security Posture Score for CISO dashboard (every 15 min)."""
    try:
        from services.posture_score import compute_and_cache_posture_score
        await compute_and_cache_posture_score()
    except Exception as exc:
        logger.error("Posture score job error: %s", exc)


async def job_entity_graph_update():
    """Job 6: Refresh entity relationship graph from recent events (every 5 min)."""
    try:
        from services.entity_service import refresh_entity_graph
        await refresh_entity_graph()
    except Exception as exc:
        logger.error("Entity graph job error: %s", exc)


async def job_abuseipdb_cache_cleanup():
    """Job 7: Clean up stale AbuseIPDB cache entries and reset daily counter at midnight."""
    try:
        from services.intel.abuseipdb import reset_daily_counter
        await reset_daily_counter()
    except Exception as exc:
        logger.error("AbuseIPDB cache cleanup error: %s", exc)


async def job_close_stale_incidents():
    """Job 8: Auto-close incidents with no activity for > 7 days (daily at 02:00)."""
    try:
        from services.incident_service import close_stale_incidents
        await close_stale_incidents()
    except Exception as exc:
        logger.error("Stale incident cleanup error: %s", exc)


# ── Analyst-triggered hunts (not a scheduled job — runs as asyncio task) ──────

async def trigger_analyst_hunt(analyst_id: str, hypothesis: str) -> str:
    """
    Analyst-triggered hunt: runs as asyncio.create_task, returns hunt_id immediately.
    Frontend subscribes to /ws/hunt/{hunt_id} for live progress.
    """
    import uuid
    hunt_id = str(uuid.uuid4())
    asyncio.create_task(_run_analyst_hunt(hunt_id, analyst_id, hypothesis))
    return hunt_id


async def _run_analyst_hunt(hunt_id: str, analyst_id: str, hypothesis: str):
    try:
        from services.ai.hunt import run_analyst_triggered_hunt
        await run_analyst_triggered_hunt(hunt_id, analyst_id, hypothesis)
    except Exception as exc:
        logger.error("Analyst hunt %s error: %s", hunt_id, exc)


# ── Scheduler lifecycle ───────────────────────────────────────────────────────

async def start_scheduler():
    """Register all 8 jobs and start the scheduler."""
    _scheduler.add_job(
        job_alert_triage,
        trigger=IntervalTrigger(seconds=30),
        id="triage",
        replace_existing=True,
        misfire_grace_time=10,
    )
    _scheduler.add_job(
        job_correlation_engine,
        trigger=IntervalTrigger(minutes=2),
        id="correlation",
        replace_existing=True,
        misfire_grace_time=30,
    )
    _scheduler.add_job(
        job_behavioral_baseline,
        trigger=IntervalTrigger(minutes=10),
        id="baseline",
        replace_existing=True,
        misfire_grace_time=60,
    )
    _scheduler.add_job(
        job_threat_hunting,
        trigger=IntervalTrigger(minutes=30),
        id="threat_hunt",
        replace_existing=True,
        misfire_grace_time=120,
    )
    _scheduler.add_job(
        job_security_posture,
        trigger=IntervalTrigger(minutes=15),
        id="posture_score",
        replace_existing=True,
        misfire_grace_time=60,
    )
    _scheduler.add_job(
        job_entity_graph_update,
        trigger=IntervalTrigger(minutes=5),
        id="entity_graph",
        replace_existing=True,
        misfire_grace_time=30,
    )
    _scheduler.add_job(
        job_abuseipdb_cache_cleanup,
        trigger=CronTrigger(hour=0, minute=0),  # midnight
        id="abuseipdb_cleanup",
        replace_existing=True,
    )
    _scheduler.add_job(
        job_close_stale_incidents,
        trigger=CronTrigger(hour=2, minute=0),  # 02:00 daily
        id="stale_incidents",
        replace_existing=True,
    )

    _scheduler.start()
    logger.info("APScheduler started — 8 jobs registered ✓")


async def stop_scheduler():
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("APScheduler stopped.")
