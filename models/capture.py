from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from database import Base


class CaptureSession(Base):
    __tablename__ = "capture_sessions"

    id          = Column(Integer, primary_key=True, index=True)
    session_id  = Column(Integer, ForeignKey("test_sessions.id"))
    pcap_path   = Column(String(512))
    iface       = Column(String(32))
    bpf_filter  = Column(String(256))
    total_pkts  = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    started_at  = Column(DateTime, default=datetime.utcnow)
    stopped_at  = Column(DateTime, nullable=True)
