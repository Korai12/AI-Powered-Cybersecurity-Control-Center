"""User ORM model — F-22 multi-role access."""
from sqlalchemy import Column, String, Boolean, DateTime, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from database import Base


class User(Base):
    __tablename__ = "users"

    id           = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    username     = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role         = Column(String(20), nullable=False, default="analyst")
    display_name = Column(String(255))
    created_at   = Column(DateTime(timezone=True), server_default=text("NOW()"), nullable=False)
    last_login   = Column(DateTime(timezone=True))
    preferences  = Column(JSONB, nullable=False, default=dict)

    def to_dict(self):
        return {
            "id": str(self.id),
            "username": self.username,
            "role": self.role,
            "display_name": self.display_name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "preferences": self.preferences or {},
        }
