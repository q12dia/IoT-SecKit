from abc import ABC, abstractmethod
from datetime import datetime, timezone


class BaseRunner(ABC):
    def __init__(self, session_id: int, ws_send):
        self.session_id = session_id
        self.ws_send    = ws_send   # async callable: push message to frontend
        self.process    = None      # asyncio.subprocess instance
        self.running    = False

    @abstractmethod
    async def start(self, **kwargs): ...

    async def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                await self.process.wait()
            except ProcessLookupError:
                pass

    # ── internal helpers ──────────────────────────────────────────────────────

    async def _send(self, msg: dict):
        msg.setdefault("ts", datetime.now(timezone.utc).isoformat())
        await self.ws_send(msg)

    async def _log(self, level: str, msg: str):
        await self._send({"type": "log", "data": {"level": level, "msg": msg}})

    async def _result(self, data: dict):
        await self._send({"type": "result", "data": data})

    async def _alert(self, severity: str, title: str, detail: str, **kwargs):
        await self._send({
            "type": "alert",
            "data": {"severity": severity, "title": title, "detail": detail, **kwargs},
        })

    async def _progress(self, phase: int, phase_name: str, pct: int):
        await self._send({
            "type": "progress",
            "data": {"phase": phase, "phase_name": phase_name, "pct": pct},
        })

    async def _done(self, summary: dict | None = None):
        await self._send({"type": "done", "data": summary or {}})

    async def _error(self, msg: str):
        await self._send({"type": "error", "data": {"msg": msg}})
