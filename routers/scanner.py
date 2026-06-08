import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models.scan_result import ScanResult
from runners.nmap_runner import NmapRunner

router = APIRouter(prefix="/scanner", tags=["scanner"])

# Active runners keyed by session_id
_active: dict[int, NmapRunner] = {}

# WebSocket connection store keyed by session_id
_ws_connections: dict[int, list[WebSocket]] = {}


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ScanStartRequest(BaseModel):
    session_id: int
    target: str
    depth: str = "standard"      # quick | standard | deep
    ports: str | None = None     # defaults to IOT_DEFAULT_PORTS


class ScanStopRequest(BaseModel):
    session_id: int


# ── REST endpoints ────────────────────────────────────────────────────────────

@router.post("/start")
async def start_scan(req: ScanStartRequest, db: Session = Depends(get_db)):
    if req.session_id in _active and _active[req.session_id].running:
        raise HTTPException(status_code=409, detail="Scan already running for this session")

    async def ws_send(msg: dict):
        msg.setdefault("ts", datetime.now(timezone.utc).isoformat())
        conns = _ws_connections.get(req.session_id, [])
        dead  = []
        for ws in conns:
            try:
                await ws.send_text(json.dumps(msg, ensure_ascii=False))
            except Exception:
                dead.append(ws)
        for ws in dead:
            conns.remove(ws)

    from runners.nmap_runner import IOT_DEFAULT_PORTS

    runner = NmapRunner(
        session_id=req.session_id,
        ws_send=ws_send,
        db=db,
        on_complete=_on_scan_complete,
    )
    _active[req.session_id] = runner

    asyncio.create_task(
        runner.start(
            target=req.target,
            depth=req.depth,
            ports=req.ports or IOT_DEFAULT_PORTS,
        )
    )
    return {"status": "started", "session_id": req.session_id}


@router.post("/stop")
async def stop_scan(req: ScanStopRequest):
    runner = _active.get(req.session_id)
    if not runner or not runner.running:
        raise HTTPException(status_code=404, detail="No active scan for this session")
    await runner.stop()
    return {"status": "stopped", "session_id": req.session_id}


@router.get("/{session_id}/services")
def get_services(session_id: int, db: Session = Depends(get_db)):
    rows = db.query(ScanResult).filter_by(session_id=session_id).all()
    return [
        {
            "id": r.id,
            "host": r.host,
            "port": r.port,
            "protocol": r.protocol,
            "service": r.service,
            "version": r.version,
            "banner": r.banner,
            "os_guess": r.os_guess,
            "is_iot": r.is_iot,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


# ── Cross-module hook ─────────────────────────────────────────────────────────

async def _on_scan_complete(session_id: int):
    from database import SessionLocal
    from models.scan_result import ScanResult as SR

    db = SessionLocal()
    try:
        services    = db.query(SR).filter_by(session_id=session_id).all()
        suggestions: list[str] = []

        if any(s.service in ("http", "https") for s in services):
            suggestions += ["credential", "webscan"]

        if any(s.port == 1883 for s in services):
            suggestions.append("fuzzing")

        if any(s.service == "modbus" for s in services):
            suggestions.append("devscan")

        msg: dict[str, Any] = {
            "type": "suggestions",
            "ts":   datetime.now(timezone.utc).isoformat(),
            "data": suggestions,
        }
        conns = _ws_connections.get(session_id, [])
        for ws in conns:
            try:
                await ws.send_text(json.dumps(msg, ensure_ascii=False))
            except Exception:
                pass
    finally:
        db.close()
