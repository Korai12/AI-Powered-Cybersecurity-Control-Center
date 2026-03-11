"""Cache and audit tables — security_audit, ip_reputation_cache, cve_cache."""
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, Date, text
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from database import Base


class SecurityAudit(Base):
    __tablename__ = "security_audit"

    id         = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    timestamp  = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    event_type = Column(String(50), nullable=False)
    analyst_id = Column(UUID(as_uuid=True))
    source_ip  = Column(INET)
    details    = Column(JSONB, nullable=False, default=dict)


class IpReputationCache(Base):
    __tablename__ = "ip_reputation_cache"

    ip          = Column(INET, primary_key=True)
    abuse_score = Column(Integer)
    is_tor      = Column(Boolean, nullable=False, default=False)
    is_vpn      = Column(Boolean, nullable=False, default=False)
    country     = Column(String(50))
    isp         = Column(String(255))
    cached_at   = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)


class CveCache(Base):
    __tablename__ = "cve_cache"

    cve_id            = Column(String(20), primary_key=True)
    cvss_score        = Column(Float)
    cvss_v3_score     = Column(Float)
    severity          = Column(String(10))
    is_exploited      = Column(Boolean, nullable=False, default=False)
    affected_products = Column(JSONB, nullable=False, default=list)
    description       = Column(Text)
    published_date    = Column(Date)
    cached_at         = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
