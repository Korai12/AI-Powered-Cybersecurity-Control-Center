"""Event ORM model — primary security event store (33 columns, G-01)."""
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, text
from sqlalchemy.dialects.postgresql import UUID, INET, ARRAY, JSONB
from database import Base


class Event(Base):
    __tablename__ = "events"

    id                = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    timestamp         = Column(DateTime(timezone=True), nullable=False)
    ingested_at       = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    source_format     = Column(String(20))
    source_identifier = Column(String(255))
    event_type        = Column(String(100))
    severity          = Column(String(10), nullable=False, default="MEDIUM")
    raw_log           = Column(Text)
    src_ip            = Column(INET)
    dst_ip            = Column(INET)
    src_port          = Column(Integer)
    dst_port          = Column(Integer)
    protocol          = Column(String(10))
    username          = Column(String(255))
    hostname          = Column(String(255))
    process_name      = Column(String(255))
    file_hash         = Column(String(128))
    action            = Column(String(50))
    rule_id           = Column(String(100))
    geo_country       = Column(String(2))
    geo_city          = Column(String(100))
    geo_lat           = Column(Float)
    geo_lon           = Column(Float)
    abuse_score       = Column(Integer)
    relevant_cves     = Column(ARRAY(String), nullable=False, default=list)
    mitre_tactic      = Column(String(100))
    mitre_technique   = Column(String(20))
    severity_score    = Column(Float)
    is_false_positive = Column(Boolean, nullable=False, default=False)
    incident_id       = Column(UUID(as_uuid=True))
    triage_status     = Column(String(20), nullable=False, default="pending")
    ai_triage_notes   = Column(Text)
    tags              = Column(ARRAY(String), nullable=False, default=list)

    def to_dict(self):
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "source_format": self.source_format,
            "source_identifier": self.source_identifier,
            "event_type": self.event_type,
            "severity": self.severity,
            "src_ip": str(self.src_ip) if self.src_ip else None,
            "dst_ip": str(self.dst_ip) if self.dst_ip else None,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "username": self.username,
            "hostname": self.hostname,
            "process_name": self.process_name,
            "file_hash": self.file_hash,
            "action": self.action,
            "rule_id": self.rule_id,
            "geo_country": self.geo_country,
            "geo_city": self.geo_city,
            "geo_lat": self.geo_lat,
            "geo_lon": self.geo_lon,
            "abuse_score": self.abuse_score,
            "relevant_cves": self.relevant_cves or [],
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "severity_score": self.severity_score,
            "is_false_positive": self.is_false_positive,
            "incident_id": str(self.incident_id) if self.incident_id else None,
            "triage_status": self.triage_status,
            "ai_triage_notes": self.ai_triage_notes,
            "tags": self.tags or [],
        }
