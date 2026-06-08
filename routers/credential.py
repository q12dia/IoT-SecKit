import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, WebSocket
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db

router = APIRouter(prefix="/credential", tags=["credential"])

_active_tls: dict[int, object] = {}
_active_pwd: dict[int, object] = {}
_ws_connections: dict[int, list[WebSocket]] = {}


class CredStartRequest(BaseModel):
    session_id:     int
    host:           str
    port:           int = 443
    brand:          str = ""
    check_tls:      bool = True
    check_password: bool = True
    password_ports: list[int] = [22, 80, 443, 23, 1883]


class CredStopRequest(BaseModel):
    session_id: int


@router.post("/start")
async def start_credential(req: CredStartRequest, db: Session = Depends(get_db)):
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

    asyncio.create_task(
        _run_credential(req, ws_send, db)
    )
    return {"status": "started", "session_id": req.session_id}


async def _run_credential(req: CredStartRequest, ws_send, db):
    from runners.tls_runner import TLSRunner
    from runners.password_runner import PasswordRunner

    try:
        if req.check_tls:
            tls = TLSRunner(session_id=req.session_id, ws_send=ws_send, db=db)
            _active_tls[req.session_id] = tls
            await tls.start(host=req.host, port=req.port)

        if req.check_password:
            pwd = PasswordRunner(session_id=req.session_id, ws_send=ws_send, db=db)
            _active_pwd[req.session_id] = pwd
            await pwd.start(
                host=req.host,
                ports=req.password_ports,
                brand=req.brand,
            )

    except Exception as exc:
        ts = datetime.now(timezone.utc).isoformat()
        await ws_send({"type": "error", "data": {"msg": str(exc)}, "ts": ts})
    finally:
        _active_tls.pop(req.session_id, None)
        _active_pwd.pop(req.session_id, None)


@router.post("/stop")
async def stop_credential(req: CredStopRequest):
    stopped = False
    for store in (_active_tls, _active_pwd):
        runner = store.get(req.session_id)
        if runner and getattr(runner, "running", False):
            await runner.stop()
            stopped = True
    if not stopped:
        raise HTTPException(404, "No active credential scan for this session")
    return {"status": "stopped", "session_id": req.session_id}
