"""HuntResult ORM model — G-01 (14 columns)."""
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, text
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from database import Base


class HuntResult(Base):
    __tablename__ = "hunt_results"

    id                = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    hunt_id           = Column(UUID(as_uuid=True), nullable=False)
    hypothesis        = Column(Text, nullable=False)
    triggered_by      = Column(String(20), nullable=False, default="scheduled")
    findings          = Column(JSONB, nullable=False, default=list)
    react_transcript  = Column(JSONB, nullable=False, default=list)
    severity          = Column(String(10))
    confidence        = Column(Float)
    event_count       = Column(Integer, nullable=False, default=0)
    matched_event_ids = Column(ARRAY(UUID(as_uuid=True)), nullable=False, default=list)
    mitre_techniques  = Column(ARRAY(String), nullable=False, default=list)
    status            = Column(String(20), nullable=False, default="active")
    created_at        = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    completed_at      = Column(DateTime(timezone=True))

    def to_dict(self):
        return {
            "id": str(self.id),
            "hunt_id": str(self.hunt_id),
            "hypothesis": self.hypothesis,
            "triggered_by": self.triggered_by,
            "findings": self.findings or [],
            "severity": self.severity,
            "confidence": self.confidence,
            "event_count": self.event_count,
            "mitre_techniques": self.mitre_techniques or [],
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
