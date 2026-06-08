from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id         = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("test_sessions.id"))
    host       = Column(String(128))
    port       = Column(Integer)
    protocol   = Column(String(16))   # tcp | udp
    service    = Column(String(64))   # http | mqtt | ssh | modbus ...
    version    = Column(String(256))
    banner     = Column(Text)
    os_guess   = Column(String(128))
    is_iot     = Column(Integer, default=0)  # 1 = IoT characteristic service
    created_at = Column(DateTime, default=datetime.utcnow)
