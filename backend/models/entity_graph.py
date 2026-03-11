"""EntityGraph ORM model — F-19 entity relationship data."""
from sqlalchemy import Column, String, Integer, Float, DateTime, text
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from database import Base


class EntityGraph(Base):
    __tablename__ = "entity_graph"

    id                  = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    source_entity_type  = Column(String(30), nullable=False)
    source_entity_value = Column(String(255), nullable=False)
    target_entity_type  = Column(String(30), nullable=False)
    target_entity_value = Column(String(255), nullable=False)
    relationship_type   = Column(String(50), nullable=False)
    interaction_count   = Column(Integer, nullable=False, default=1)
    risk_score          = Column(Float)
    evidence_event_ids  = Column(ARRAY(UUID(as_uuid=True)), nullable=False, default=list)
    first_seen          = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    last_seen           = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)

    def to_dict(self):
        return {
            "id": str(self.id),
            "source": {"type": self.source_entity_type, "value": self.source_entity_value},
            "target": {"type": self.target_entity_type, "value": self.target_entity_value},
            "relationship_type": self.relationship_type,
            "interaction_count": self.interaction_count,
            "risk_score": self.risk_score,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }
