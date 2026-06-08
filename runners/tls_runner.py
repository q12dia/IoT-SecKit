import asyncio
import json
from pathlib import Path

from runners.base_runner import BaseRunner
import config

CVSS_MAP: dict[str, tuple[float, str, str | None]] = {
    "heartbleed": (9.8, "critical", "CVE-2014-0160"),
    "poodle":     (3.4, "low",      "CVE-2014-3566"),
    "beast":      (3.4, "low",      "CVE-2011-3389"),
    "drown":      (5.9, "medium",   "CVE-2016-0800"),
    "freak":      (7.5, "high",     "CVE-2015-0204"),
    "sweet32":    (5.9, "medium",   "CVE-2016-2183"),
    "robot":      (7.5, "high",     "CVE-2017-13099"),
    "crime":      (6.9, "medium",   "CVE-2012-4929"),
    "breach":     (5.9, "medium",   "CVE-2013-3587"),
    "lucky13":    (4.3, "medium",   "CVE-2013-0169"),
    "logjam":     (5.9, "medium",   "CVE-2015-4000"),
    "tls10":      (5.3, "medium",   None),
    "tls11":      (5.3, "medium",   None),
    "ssl2":       (9.8, "critical", None),
    "ssl3":       (7.5, "high",     None),
    "self_signed":(4.3, "medium",   None),
    "rsa1024":    (5.9, "medium",   None),
    "rsa2048":    (0.0, "info",     None),
    "sha1":       (4.0, "medium",   None),
    "hsts":       (2.6, "low",      None),
    "rc4":        (5.9, "medium",   None),
}

TESTSSL_SEV_MAP = {
    "CRITICAL": "critical", "HIGH": "high",
    "MEDIUM": "medium",     "LOW": "low",
    "WARN": "medium",       "OK": "info",
    "INFO": "info",         "NOT_TESTED": None,
    "DEBUG": None,
}

SKIP_IDS = {
    "service", "start_time", "scanTime", "overall_grade",
}


class TLSRunner(BaseRunner):
    def __init__(self, session_id: int, ws_send, db=None):
        super().__init__(session_id, ws_send)
        self.db = db

    async def start(self, host: str, port: int = 443):
        self.running = True
        testssl = config.TESTSSL_BIN
        out_file = f"/tmp/testssl_{self.session_id}.json"

        if not Path(testssl).exists():
            await self._log("warn", f"[TLS] testssl.sh not found at {testssl} — skipping")
            await self._done({"total_findings": 0, "skipped": True})
            self.running = False
            return

        cmd = (
            f"{testssl} --jsonfile {out_file} "
            f"--severity LOW --fast --quiet --color 0 "
            f"{host}:{port}"
        )
        await self._log("info", f"[TLS] 啟動 testssl.sh → {host}:{port}")

        try:
            self.process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            async for line in self.process.stdout:
                if not self.running:
                    break
                text = line.decode(errors="replace").rstrip()
                if text:
                    await self._log("info", text)
            await self.process.wait()

            if self.running:
                count = await self._parse_json(out_file, host, port)
                await self._done({"total_findings": count})

        except Exception as exc:
            await self._error(str(exc))
        finally:
            self.running = False

    async def _parse_json(self, json_path: str, host: str, port: int) -> int:
        try:
            with open(json_path, "r", errors="replace") as f:
                raw = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            await self._error(f"[TLS] JSON parse error: {exc}")
            return 0

        # testssl JSON structure: list of finding objects or {"scanResult": [...]}
        items: list[dict] = []
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            for key in ("scanResult", "findings", "results"):
                if key in raw and isinstance(raw[key], list):
                    items = raw[key]
                    break
            if not items:
                items = list(raw.values())[0] if raw else []

        count = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            finding_id = item.get("id", "")
            if finding_id.lower() in SKIP_IDS:
                continue
            finding_text = item.get("finding", "") or item.get("output", "")
            severity_raw = item.get("severity", "INFO").upper()

            db_sev = TESTSSL_SEV_MAP.get(severity_raw)
            if db_sev is None:
                continue  # NOT_TESTED / DEBUG

            # Check known vuln keywords for CVSS override
            cvss_score, cve_id = None, None
            id_lower = finding_id.lower()
            for key, (score, sev_override, cve) in CVSS_MAP.items():
                if key in id_lower:
                    cvss_score = score
                    db_sev     = sev_override
                    cve_id     = cve
                    break

            if db_sev == "info" and not cvss_score:
                continue  # Skip pure info without CVSS

            title = f"[TLS] {finding_id}: {finding_text[:80]}"
            data = {
                "host":     f"{host}:{port}",
                "severity": db_sev,
                "title":    title,
                "detail":   finding_text,
                "cvss":     cvss_score,
                "cve_id":   cve_id,
            }
            await self._result(data)
            self._save_finding(host, port, data)
            count += 1

        await self._log("ok", f"[TLS] 分析完成，共 {count} 個發現")
        return count

    def _save_finding(self, host: str, port: int, data: dict):
        if self.db is None:
            return
        from models.finding import Finding, Severity

        sev_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
        }
        row = Finding(
            session_id=self.session_id,
            module="credential",
            host=f"{host}:{port}",
            severity=sev_map.get(data["severity"], Severity.INFO),
            title=data["title"],
            detail=data.get("detail"),
            cvss_score=data.get("cvss"),
            cve_id=data.get("cve_id"),
        )
        self.db.add(row)
        self.db.commit()
