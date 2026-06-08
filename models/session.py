from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime
from database import Base


class TestSession(Base):
    __tablename__ = "test_sessions"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(128))
    target_ip   = Column(String(128))
    target_desc = Column(String(256))
    started_at  = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    status      = Column(String(32), default="running")  # running | done | stopped
