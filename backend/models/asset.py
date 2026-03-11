"""Asset ORM model — infrastructure inventory (12 columns, G-01)."""
from sqlalchemy import Column, String, Boolean, Text, DateTime, text
from sqlalchemy.dialects.postgresql import UUID, INET, ARRAY
from database import Base


class Asset(Base):
    __tablename__ = "assets"

    id                 = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    hostname           = Column(String(255), unique=True, nullable=False)
    ip_address         = Column(INET)
    asset_type         = Column(String(50), nullable=False, default="server")
    criticality        = Column(String(10), nullable=False, default="medium")
    owner              = Column(String(255))
    os                 = Column(String(100))
    tags               = Column(ARRAY(String), nullable=False, default=list)
    is_internet_facing = Column(Boolean, nullable=False, default=False)
    last_seen          = Column(DateTime(timezone=True))
    notes              = Column(Text)
    created_at         = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)

    def to_dict(self):
        return {
            "id": str(self.id),
            "hostname": self.hostname,
            "ip_address": str(self.ip_address) if self.ip_address else None,
            "asset_type": self.asset_type,
            "criticality": self.criticality,
            "owner": self.owner,
            "os": self.os,
            "tags": self.tags or [],
            "is_internet_facing": self.is_internet_facing,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
