import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, WebSocket
from pydantic import BaseModel
from sqlalchemy.orm import Session

import config
from database import get_db

router = APIRouter(prefix="/firmware", tags=["firmware"])

_active: dict[int, object] = {}
_ws_connections: dict[int, list[WebSocket]] = {}
_uploaded: dict[int, str] = {}   # session_id → absolute path on disk


class FirmwareStartRequest(BaseModel):
    session_id: int


class FirmwareStopRequest(BaseModel):
    session_id: int


@router.post("/upload")
async def upload_firmware(session_id: int, file: UploadFile = File(...)):
    fw_dir = Path(config.FIRMWARE_DIR)
    fw_dir.mkdir(parents=True, exist_ok=True)
    # Use a safe filename: strip path components, keep extension
    safe_name = Path(file.filename or "firmware.bin").name
    dest = fw_dir / f"fw_{session_id}_{safe_name}"
    content = await file.read()
    dest.write_bytes(content)
    _uploaded[session_id] = str(dest)
    return {
        "status":   "uploaded",
        "filename": safe_name,
        "size":     len(content),
        "path":     str(dest),
    }


@router.post("/start")
async def start_firmware(req: FirmwareStartRequest, db: Session = Depends(get_db)):
    fw_path = _uploaded.get(req.session_id)
    if not fw_path:
        raise HTTPException(400, "No firmware uploaded for this session — call /upload first")

    runner = _active.get(req.session_id)
    if runner and getattr(runner, "running", False):
        raise HTTPException(409, "Firmware analysis already running")

    async def ws_send(msg: dict):
        msg.setdefault("ts", datetime.now(timezone.utc).isoformat())
        conns = _ws_connections.get(req.session_id, [])
        dead: list[WebSocket] = []
        for ws in conns:
            try:
                await ws.send_text(json.dumps(msg, ensure_ascii=False))
            except Exception:
                dead.append(ws)
        for ws in dead:
            conns.remove(ws)

    from runners.firmware_runner import FirmwareRunner

    work_dir = str(Path(config.FIRMWARE_DIR) / f"session_{req.session_id}")
    runner = FirmwareRunner(session_id=req.session_id, ws_send=ws_send, db=db)
    _active[req.session_id] = runner

    asyncio.create_task(runner.start(fw_path=fw_path, work_dir=work_dir))
    return {"status": "started", "session_id": req.session_id}


@router.post("/stop")
async def stop_firmware(req: FirmwareStopRequest):
    runner = _active.get(req.session_id)
    if not runner or not getattr(runner, "running", False):
        raise HTTPException(404, "No active firmware analysis for this session")
    await runner.stop()
    return {"status": "stopped", "session_id": req.session_id}
