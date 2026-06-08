from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from database import init_db
from routers import scanner as scanner_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="IoT SecKit",
    version="1.0.0",
    description="IoT Security Assessment Platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── REST API routes ───────────────────────────────────────────────────────────
app.include_router(scanner_router.router, prefix="/api")

# ── WebSocket routes (scanner) ────────────────────────────────────────────────
# /ws/scanner/{session_id}  — registered on the scanner router with prefix /ws
from routers.scanner import router as _scanner_ws_router
from fastapi import APIRouter

_ws_router = APIRouter()

@_ws_router.websocket("/scanner/{session_id}")
async def _ws_scanner_proxy(websocket, session_id: int):
    # Delegate to scanner router's WebSocket handler
    from routers.scanner import ws_scanner
    await ws_scanner(websocket, session_id)

app.include_router(_ws_router, prefix="/ws")

# ── Session management (lightweight, no dedicated router yet) ─────────────────
from fastapi import Depends
from sqlalchemy.orm import Session as DBSession
from datetime import datetime
from pydantic import BaseModel

from database import get_db
from models.session import TestSession


class SessionCreate(BaseModel):
    name: str
    target_ip: str
    target_desc: str = ""


@app.post("/api/sessions", tags=["sessions"])
def create_session(body: SessionCreate, db: DBSession = Depends(get_db)):
    sess = TestSession(
        name=body.name,
        target_ip=body.target_ip,
        target_desc=body.target_desc,
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)
    return _session_dict(sess)


@app.get("/api/sessions", tags=["sessions"])
def list_sessions(db: DBSession = Depends(get_db)):
    rows = db.query(TestSession).order_by(TestSession.started_at.desc()).all()
    return [_session_dict(r) for r in rows]


@app.get("/api/sessions/{session_id}", tags=["sessions"])
def get_session(session_id: int, db: DBSession = Depends(get_db)):
    row = db.get(TestSession, session_id)
    if not row:
        from fastapi import HTTPException
        raise HTTPException(404, "Session not found")
    return _session_dict(row)


@app.get("/api/sessions/{session_id}/findings", tags=["sessions"])
def get_findings(session_id: int, db: DBSession = Depends(get_db)):
    from models.finding import Finding
    rows = db.query(Finding).filter_by(session_id=session_id).all()
    return [
        {
            "id": f.id,
            "module": f.module,
            "host": f.host,
            "severity": f.severity.value if f.severity else None,
            "title": f.title,
            "detail": f.detail,
            "path": f.path,
            "cvss_score": f.cvss_score,
            "cve_id": f.cve_id,
            "remediation": f.remediation,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in rows
    ]


@app.delete("/api/sessions/{session_id}", tags=["sessions"])
def delete_session(session_id: int, db: DBSession = Depends(get_db)):
    row = db.get(TestSession, session_id)
    if not row:
        from fastapi import HTTPException
        raise HTTPException(404, "Session not found")
    db.delete(row)
    db.commit()
    return {"status": "deleted"}


def _session_dict(s: TestSession) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "target_ip": s.target_ip,
        "target_desc": s.target_desc,
        "status": s.status,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
    }


# ── Static files (SPA) ────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", include_in_schema=False)
async def serve_spa():
    return FileResponse("static/index.html")
