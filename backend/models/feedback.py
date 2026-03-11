"""AnalystFeedback ORM model — F-21 learning loop."""
from sqlalchemy import Column, String, Float, Text, DateTime, text
from sqlalchemy.dialects.postgresql import UUID
from database import Base


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id              = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    analyst_id      = Column(UUID(as_uuid=True))
    event_id        = Column(UUID(as_uuid=True))
    incident_id     = Column(UUID(as_uuid=True))
    ai_verdict      = Column(String(20))
    analyst_verdict = Column(String(20), nullable=False)
    ai_confidence   = Column(Float)
    notes           = Column(Text)
    created_at      = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)

    def to_dict(self):
        return {
            "id": str(self.id),
            "analyst_id": str(self.analyst_id) if self.analyst_id else None,
            "event_id": str(self.event_id) if self.event_id else None,
            "incident_id": str(self.incident_id) if self.incident_id else None,
            "ai_verdict": self.ai_verdict,
            "analyst_verdict": self.analyst_verdict,
            "ai_confidence": self.ai_confidence,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
