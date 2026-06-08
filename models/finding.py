import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, Enum
from database import Base


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class Finding(Base):
    __tablename__ = "findings"

    id          = Column(Integer, primary_key=True, index=True)
    session_id  = Column(Integer, ForeignKey("test_sessions.id"), nullable=False)
    module      = Column(String(32), nullable=False)
    # fuzzing | scanner | credential | firmware | traffic | devscan | webscan
    host        = Column(String(128))
    severity    = Column(Enum(Severity), nullable=False)
    title       = Column(String(256), nullable=False)
    detail      = Column(Text)
    path        = Column(String(512))
    cvss_score  = Column(Float)
    cve_id      = Column(String(32))
    remediation = Column(Text)
    raw_output  = Column(Text)
    created_at  = Column(DateTime, default=datetime.utcnow)
