# Stub — implemented in its respective phase
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session_factory
from models.incident import Incident
from models.response_action import ResponseAction

logger = logging.getLogger("accc.response_executor")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


ACTION_CATALOG: dict[str, dict[str, Any]] = {
    "block_ip": {
        "risk": "MEDIUM",
        "required_params": ["ip", "duration_hours"],
        "rollback_available": True,
        "execute_message": "Firewall rule ACL-BLOCK-{ip} created on perimeter FW. Traffic from {ip} dropped.",
        "rollback_message": "Firewall rule ACL-BLOCK-{ip} removed. Traffic from {ip} restored.",
    },
    "unblock_ip": {
        "risk": "LOW",
        "required_params": ["ip"],
        "rollback_available": False,
        "execute_message": "Firewall rule ACL-BLOCK-{ip} removed. Traffic from {ip} restored.",
    },
    "isolate_host": {
        "risk": "HIGH",
        "required_params": ["hostname", "reason"],
        "rollback_available": True,
        "execute_message": "Host {hostname} quarantined. Network access revoked except for management VLAN.",
        "rollback_message": "Host {hostname} removed from quarantine. Normal network access restored.",
    },
    "restore_host": {
        "risk": "MEDIUM",
        "required_params": ["hostname"],
        "rollback_available": False,
        "execute_message": "Host {hostname} removed from quarantine. Normal network access restored.",
    },
    "disable_user": {
        "risk": "HIGH",
        "required_params": ["username", "reason"],
        "rollback_available": True,
        "execute_message": "User account {username} disabled in directory. Active sessions terminated.",
        "rollback_message": "User account {username} re-enabled. Password reset required on next login.",
    },
    "enable_user": {
        "risk": "MEDIUM",
        "required_params": ["username"],
        "rollback_available": False,
        "execute_message": "User account {username} re-enabled. Password reset required on next login.",
    },
    "force_mfa": {
        "risk": "MEDIUM",
        "required_params": ["username"],
        "rollback_available": False,
        "execute_message": "MFA re-enrollment forced for {username}. Next login will require device registration.",
    },
    "reset_password": {
        "risk": "MEDIUM",
        "required_params": ["username"],
        "rollback_available": False,
        "execute_message": "Temporary password issued for {username}. User notified via registered email.",
    },
    "block_domain": {
        "risk": "MEDIUM",
        "required_params": ["domain", "duration_hours"],
        "rollback_available": True,
        "execute_message": "DNS sinkhole rule created for {domain}. Resolution redirected to 0.0.0.0.",
        "rollback_message": "DNS sinkhole rule removed for {domain}. Normal resolution restored.",
    },
    "kill_process": {
        "risk": "HIGH",
        "required_params": ["hostname", "pid", "process_name"],
        "rollback_available": False,
        "execute_message": "Process {process_name} (PID {pid}) terminated on {hostname}. Memory dump preserved.",
    },
    "collect_forensics": {
        "risk": "LOW",
        "required_params": ["hostname", "scope"],
        "rollback_available": False,
        "execute_message": "Forensic collection task dispatched to {hostname}. Results available in 3-5 minutes.",
    },
    "rate_limit_ip": {
        "risk": "LOW",
        "required_params": ["ip", "requests_per_min"],
        "rollback_available": True,
        "execute_message": "Rate limit of {requests_per_min} req/min applied to {ip} on edge load balancer.",
        "rollback_message": "Rate limit removed from {ip}. Normal request throughput restored.",
    },
    "notify_analyst": {
        "risk": "LOW",
        "required_params": ["analyst_id", "message", "severity"],
        "rollback_available": False,
        "execute_message": "Notification dispatched to analyst via dashboard alert and email.",
    },
    "create_ticket": {
        "risk": "LOW",
        "required_params": ["title", "severity", "incident_id"],
        "rollback_available": False,
        "execute_message": "Incident ticket #{ticket_id} created in ticketing system. Assigned to SOC queue.",
    },
}


class ResponseActionExecutor:
    def __init__(self) -> None:
        self.simulation_mode = True
        self._veto_tasks: dict[str, asyncio.Task] = {}

    def _validate_action(self, action_type: str, action_params: dict[str, Any]) -> dict[str, Any]:
        if action_type not in ACTION_CATALOG:
            raise ValueError(f"Unsupported action_type: {action_type}")

        definition = ACTION_CATALOG[action_type]
        missing = [key for key in definition["required_params"] if key not in action_params]
        if missing:
            raise ValueError(f"Missing required params for {action_type}: {', '.join(missing)}")

        return definition

    def _append_audit(
        self,
        action: ResponseAction,
        event: str,
        actor: str | None,
        details: dict[str, Any] | None = None,
    ) -> None:
        current = list(action.audit_log or [])
        current.append(
            {
                "timestamp": _utc_now().isoformat(),
                "event": event,
                "actor": actor,
                "details": details or {},
            }
        )
        action.audit_log = current

    def _format_execute_message(self, action: ResponseAction) -> str:
        definition = ACTION_CATALOG[action.action_type]
        params = dict(action.action_params or {})

        if action.action_type == "create_ticket":
            params["ticket_id"] = str(action.id).replace("-", "")[:8].upper()

        return definition["execute_message"].format(**params)

    def _format_rollback_message(self, action: ResponseAction) -> str:
        definition = ACTION_CATALOG[action.action_type]
        params = dict(action.action_params or {})
        template = definition.get("rollback_message")
        if not template:
            raise ValueError(f"Action {action.action_type} is not rollback-capable")
        return template.format(**params)

    async def _load_action(self, db: AsyncSession, action_id: UUID) -> ResponseAction | None:
        result = await db.execute(
            select(ResponseAction).where(ResponseAction.id == action_id).limit(1)
        )
        return result.scalars().first()

    async def _execute_action(
        self,
        action_id: UUID,
        actor_id: str | None = None,
        auto_trigger: bool = False,
    ) -> dict[str, Any]:
        async with async_session_factory() as db:
            action = await self._load_action(db, action_id)
            if action is None:
                raise ValueError("Action not found")

            if action.status in {"vetoed", "completed", "rolled_back", "failed"}:
                return action.to_dict()

            action.status = "executing"
            action.executed_at = _utc_now()
            self._append_audit(
                action,
                event="execution_started",
                actor=actor_id or "system",
                details={"auto_trigger": auto_trigger},
            )
            await db.commit()

            try:
                result_message = self._format_execute_message(action)
                action.status = "completed"
                action.completed_at = _utc_now()
                action.result = result_message
                self._append_audit(
                    action,
                    event="execution_completed",
                    actor=actor_id or "system",
                    details={"result": result_message, "simulation_mode": self.simulation_mode},
                )
                await db.commit()
                await db.refresh(action)
                return action.to_dict()
            except Exception as exc:
                action.status = "failed"
                action.completed_at = _utc_now()
                action.result = f"Execution failed: {str(exc)}"
                self._append_audit(
                    action,
                    event="execution_failed",
                    actor=actor_id or "system",
                    details={"error": str(exc)},
                )
                await db.commit()
                await db.refresh(action)
                return action.to_dict()

    async def _auto_execute_after_veto_window(self, action_id: UUID) -> None:
        try:
            async with async_session_factory() as db:
                action = await self._load_action(db, action_id)
                if action is None or action.veto_deadline is None:
                    return

                seconds = max(
                    0.0,
                    (action.veto_deadline - _utc_now()).total_seconds(),
                )

            await asyncio.sleep(seconds)

            async with async_session_factory() as db:
                action = await self._load_action(db, action_id)
                if action is None:
                    return
                if action.status != "pending":
                    return
                if action.veto_deadline and _utc_now() < action.veto_deadline:
                    return

            await self._execute_action(action_id=action_id, actor_id="system", auto_trigger=True)
        except Exception as exc:
            logger.exception("Auto-execution failed for action %s: %s", action_id, exc)
        finally:
            self._veto_tasks.pop(str(action_id), None)

    async def create_action(
        self,
        incident_id: UUID,
        action_type: str,
        action_params: dict[str, Any],
        created_by: str,
        requested_by: str | None,
    ) -> dict[str, Any]:
        definition = self._validate_action(action_type, action_params)
        risk_level = definition["risk"]

        async with async_session_factory() as db:
            incident = await db.get(Incident, incident_id)
            if incident is None:
                raise ValueError("Incident not found")

            action = ResponseAction(
                incident_id=incident_id,
                action_type=action_type,
                action_params=action_params,
                risk_level=risk_level,
                status="pending",
                created_by=created_by,
                requested_by=UUID(str(requested_by)) if requested_by else None,
                rollback_available=bool(definition.get("rollback_available", False)),
                simulation_mode=True,
                audit_log=[],
            )

            if risk_level == "MEDIUM":
                action.veto_deadline = _utc_now() + timedelta(seconds=60)

            self._append_audit(
                action,
                event="created",
                actor=requested_by or created_by,
                details={
                    "risk_level": risk_level,
                    "created_by": created_by,
                    "simulation_mode": True,
                },
            )

            db.add(action)
            await db.commit()
            await db.refresh(action)

        if risk_level == "LOW":
            return await self._execute_action(
                action_id=action.id,
                actor_id=requested_by or "system",
                auto_trigger=True,
            )

        if risk_level == "MEDIUM":
            task = asyncio.create_task(self._auto_execute_after_veto_window(action.id))
            self._veto_tasks[str(action.id)] = task

        return action.to_dict()

    async def approve_action(
        self,
        action_id: UUID,
        approved_by: str,
    ) -> dict[str, Any]:
        async with async_session_factory() as db:
            action = await self._load_action(db, action_id)
            if action is None:
                raise ValueError("Action not found")

            if action.status in {"completed", "vetoed", "rolled_back", "failed"}:
                return action.to_dict()

            if action.risk_level not in {"MEDIUM", "HIGH"}:
                return action.to_dict()

            action.status = "approved"
            action.approved_by = UUID(str(approved_by))
            action.approved_at = _utc_now()
            self._append_audit(
                action,
                event="approved",
                actor=approved_by,
                details={"risk_level": action.risk_level},
            )
            await db.commit()
            await db.refresh(action)

        task = self._veto_tasks.pop(str(action_id), None)
        if task:
            task.cancel()

        return await self._execute_action(
            action_id=action_id,
            actor_id=approved_by,
            auto_trigger=False,
        )

    async def veto_action(
        self,
        action_id: UUID,
        vetoed_by: str,
    ) -> dict[str, Any]:
        async with async_session_factory() as db:
            action = await self._load_action(db, action_id)
            if action is None:
                raise ValueError("Action not found")

            if action.risk_level != "MEDIUM":
                raise ValueError("Only MEDIUM-risk actions can be vetoed")

            if action.status != "pending":
                raise ValueError("Only pending MEDIUM-risk actions can be vetoed")

            if action.veto_deadline and _utc_now() > action.veto_deadline:
                raise ValueError("Veto window has expired")

            action.status = "vetoed"
            action.result = "Action vetoed by analyst before auto-execution."
            self._append_audit(
                action,
                event="vetoed",
                actor=vetoed_by,
                details={},
            )
            await db.commit()
            await db.refresh(action)

        task = self._veto_tasks.pop(str(action_id), None)
        if task:
            task.cancel()

        return action.to_dict()

    async def rollback_action(
        self,
        action_id: UUID,
        rolled_back_by: str,
    ) -> dict[str, Any]:
        async with async_session_factory() as db:
            action = await self._load_action(db, action_id)
            if action is None:
                raise ValueError("Action not found")

            if action.status != "completed":
                raise ValueError("Only completed actions can be rolled back")

            if not action.rollback_available:
                raise ValueError("This action is not rollback-capable")

            rollback_message = self._format_rollback_message(action)
            action.status = "rolled_back"
            action.rolled_back_at = _utc_now()
            action.result = rollback_message
            self._append_audit(
                action,
                event="rolled_back",
                actor=rolled_back_by,
                details={"result": rollback_message},
            )
            await db.commit()
            await db.refresh(action)
            return action.to_dict()


response_action_executor = ResponseActionExecutor()