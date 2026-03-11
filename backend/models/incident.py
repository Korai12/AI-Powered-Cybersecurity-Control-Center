"""Incident ORM model — correlated incident groups (27 columns, G-01)."""
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, text
from sqlalchemy.dialects.postgresql import UUID, INET, ARRAY, JSONB
from database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id                         = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    title                      = Column(String(500), nullable=False)
    description                = Column(Text)
    severity                   = Column(String(10), nullable=False)
    status                     = Column(String(20), nullable=False, default="open")
    created_at                 = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    updated_at                 = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    resolved_at                = Column(DateTime(timezone=True))
    assigned_to                = Column(UUID(as_uuid=True))
    event_count                = Column(Integer, nullable=False, default=0)
    affected_assets            = Column(ARRAY(String), nullable=False, default=list)
    affected_users             = Column(ARRAY(String), nullable=False, default=list)
    ioc_ips                    = Column(ARRAY(INET), nullable=False, default=list)
    ioc_domains                = Column(ARRAY(String), nullable=False, default=list)
    ioc_hashes                 = Column(ARRAY(String), nullable=False, default=list)
    mitre_tactics              = Column(ARRAY(String), nullable=False, default=list)
    mitre_techniques           = Column(ARRAY(String), nullable=False, default=list)
    kill_chain_stage           = Column(String(50))
    attack_type                = Column(String(100))
    ai_summary                 = Column(Text)
    ai_recommendations         = Column(JSONB, nullable=False, default=list)
    confidence_score           = Column(Float)
    false_positive_probability = Column(Float)
    is_campaign                = Column(Boolean, nullable=False, default=False)
    campaign_id                = Column(UUID(as_uuid=True))
    stix_bundle                = Column(JSONB)
    report_generated_at        = Column(DateTime(timezone=True))

    def to_dict(self):
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "assigned_to": str(self.assigned_to) if self.assigned_to else None,
            "event_count": self.event_count,
            "affected_assets": self.affected_assets or [],
            "affected_users": self.affected_users or [],
            "ioc_ips": [str(ip) for ip in (self.ioc_ips or [])],
            "ioc_domains": self.ioc_domains or [],
            "ioc_hashes": self.ioc_hashes or [],
            "mitre_tactics": self.mitre_tactics or [],
            "mitre_techniques": self.mitre_techniques or [],
            "kill_chain_stage": self.kill_chain_stage,
            "attack_type": self.attack_type,
            "ai_summary": self.ai_summary,
            "ai_recommendations": self.ai_recommendations or [],
            "confidence_score": self.confidence_score,
            "false_positive_probability": self.false_positive_probability,
            "is_campaign": self.is_campaign,
        }
