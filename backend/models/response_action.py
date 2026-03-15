"""ResponseAction ORM model — F-15 / G-05 schema."""
from sqlalchemy import Column, String, Text, DateTime, Boolean, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID, JSONB

from database import Base


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    action_type = Column(String(50), nullable=False)
    action_params = Column(JSONB, nullable=False, default=dict)
    risk_level = Column(String(10), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    created_by = Column(String(20), nullable=False)  # ai | analyst
    requested_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    approved_at = Column(DateTime(timezone=True))
    executed_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    veto_deadline = Column(DateTime(timezone=True))
    result = Column(Text)
    rollback_available = Column(Boolean, nullable=False, default=True)
    rolled_back_at = Column(DateTime(timezone=True))
    simulation_mode = Column(Boolean, nullable=False, default=True)
    audit_log = Column(JSONB, nullable=False, default=list)

    def to_dict(self):
        return {
            "id": str(self.id) if self.id else None,
            "incident_id": str(self.incident_id) if self.incident_id else None,
            "action_type": self.action_type,
            "action_params": self.action_params or {},
            "risk_level": self.risk_level,
            "status": self.status,
            "created_by": self.created_by,
            "requested_by": str(self.requested_by) if self.requested_by else None,
            "approved_by": str(self.approved_by) if self.approved_by else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "veto_deadline": self.veto_deadline.isoformat() if self.veto_deadline else None,
            "result": self.result,
            "rollback_available": self.rollback_available,
            "rolled_back_at": self.rolled_back_at.isoformat() if self.rolled_back_at else None,
            "simulation_mode": self.simulation_mode,
            "audit_log": self.audit_log or [],
        }