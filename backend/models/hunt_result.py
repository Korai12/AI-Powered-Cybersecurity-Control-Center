"""HuntResult ORM model — F-14 / G-03 patched schema."""
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB

from database import Base


class HuntResult(Base):
    __tablename__ = "hunt_results"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    hunt_id = Column(UUID(as_uuid=True), nullable=False)
    hypothesis = Column(Text, nullable=False)
    triggered_by = Column(String(20), nullable=False, default="scheduled")
    analyst_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    started_at = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    completed_at = Column(DateTime(timezone=True))
    status = Column(String(20), nullable=False, default="running")
    events_examined = Column(Integer, nullable=False, default=0)
    findings_count = Column(Integer, nullable=False, default=0)
    findings = Column(JSONB, nullable=False, default=list)
    ai_narrative = Column(Text)
    technique_coverage = Column(ARRAY(String), nullable=False, default=list)
    react_transcript = Column(JSONB, nullable=False, default=list)

    def to_dict(self):
        return {
            "id": str(self.id) if self.id else None,
            "hunt_id": str(self.hunt_id) if self.hunt_id else None,
            "hypothesis": self.hypothesis,
            "triggered_by": self.triggered_by,
            "analyst_id": str(self.analyst_id) if self.analyst_id else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "events_examined": self.events_examined,
            "findings_count": self.findings_count,
            "findings": self.findings or [],
            "ai_narrative": self.ai_narrative,
            "technique_coverage": self.technique_coverage or [],
            "react_transcript": self.react_transcript or [],
        }