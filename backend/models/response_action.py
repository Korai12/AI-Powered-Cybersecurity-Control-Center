"""ResponseAction ORM model — G-01 / G-05 (19 columns)."""
from sqlalchemy import Column, String, Boolean, Text, DateTime, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from database import Base


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id                 = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    incident_id        = Column(UUID(as_uuid=True), nullable=False)
    action_type        = Column(String(50), nullable=False)
    action_params      = Column(JSONB, nullable=False, default=dict)
    risk_level         = Column(String(10), nullable=False)
    status             = Column(String(20), nullable=False, default="pending")
    created_by         = Column(String(20), nullable=False, default="ai")
    requested_by       = Column(UUID(as_uuid=True))
    approved_by        = Column(UUID(as_uuid=True))
    created_at         = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    approved_at        = Column(DateTime(timezone=True))
    executed_at        = Column(DateTime(timezone=True))
    completed_at       = Column(DateTime(timezone=True))
    veto_deadline      = Column(DateTime(timezone=True))
    result             = Column(Text)
    rollback_available = Column(Boolean, nullable=False, default=True)
    rolled_back_at     = Column(DateTime(timezone=True))
    simulation_mode    = Column(Boolean, nullable=False, default=True)
    audit_log          = Column(JSONB, nullable=False, default=list)

    def to_dict(self):
        return {
            "id": str(self.id),
            "incident_id": str(self.incident_id),
            "action_type": self.action_type,
            "action_params": self.action_params or {},
            "risk_level": self.risk_level,
            "status": self.status,
            "created_by": self.created_by,
            "simulation_mode": self.simulation_mode,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "veto_deadline": self.veto_deadline.isoformat() if self.veto_deadline else None,
            "result": self.result,
            "rollback_available": self.rollback_available,
            "audit_log": self.audit_log or [],
        }
