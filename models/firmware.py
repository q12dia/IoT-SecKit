from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from database import Base


class FirmwareAnalysis(Base):
    __tablename__ = "firmware_analyses"

    id           = Column(Integer, primary_key=True, index=True)
    session_id   = Column(Integer, ForeignKey("test_sessions.id"))
    filename     = Column(String(256))
    file_size    = Column(Integer)
    arch         = Column(String(32))    # MIPS | ARM | x86
    endian       = Column(String(4))     # LE | BE
    filesystem   = Column(String(32))   # SquashFS | JFFS2 | UBIFS | CRAMFS
    os_version   = Column(String(128))
    file_count   = Column(Integer)
    elf_count    = Column(Integer)
    extract_path = Column(String(512))
    created_at   = Column(DateTime, default=datetime.utcnow)
