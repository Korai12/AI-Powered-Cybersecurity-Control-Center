"""Conversation ORM model — F-03 persistent chat sessions."""
from sqlalchemy import Column, String, DateTime, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from database import Base


class Conversation(Base):
    __tablename__ = "conversations"

    id                  = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    analyst_id          = Column(UUID(as_uuid=True))
    created_at          = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    updated_at          = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    title               = Column(String(255))
    messages            = Column(JSONB, nullable=False, default=list)
    related_incident_id = Column(UUID(as_uuid=True))

    def to_dict(self):
        return {
            "id": str(self.id),
            "analyst_id": str(self.analyst_id) if self.analyst_id else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "title": self.title,
            "messages": self.messages or [],
            "related_incident_id": str(self.related_incident_id) if self.related_incident_id else None,
        }
