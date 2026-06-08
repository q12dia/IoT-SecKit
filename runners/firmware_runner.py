import asyncio
import json
import re
import subprocess
from pathlib import Path

from runners.base_runner import BaseRunner
import config

DANGEROUS_PATTERNS: dict[str, str] = {
    "private_key":   r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "hardcoded_pw":  r'(?i)(?:password|passwd|secret)\s*[=:]\s*["\']?(?P<val>[^\s"\']{4,})',
    "api_token":     r'(?i)(?:api[_-]?key|bearer|token)\s*[=:]\s*[A-Za-z0-9+/._\-]{20,}',
    "aws_key":       r"AKIA[0-9A-Z]{16}",
    "backdoor_uid0": r":\$\w+\$[^:]+:0:0:",
}

FINDING_TITLES: dict[str, str] = {
    "private_key":   "硬編碼私鑰",
    "hardcoded_pw":  "硬編碼密碼",
    "api_token":     "硬編碼 API Token",
    "aws_key":       "硬編碼 AWS 金鑰",
    "backdoor_uid0": "後門帳號 (UID=0)",
}

SKIP_EXTENSIONS = {".pyc", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
                   ".ttf", ".woff", ".woff2", ".mp3", ".mp4", ".avi"}


class FirmwareRunner(BaseRunner):
    def __init__(self, session_id: int, ws_send, db=None):
        super().__init__(session_id, ws_send)
        self.db = db

    async def start(self, fw_path: str, work_dir: str):
        self.running = True
        fw = Path(fw_path)
        wd = Path(work_dir)
        wd.mkdir(parents=True, exist_ok=True)

        total = 0

        # Phase 1 — Binwalk extraction
        await self._progress(1, "Binwalk 解包", 5)
        extracted_dir = wd / "extracted"
        arch, fs_type = await self._phase1_binwalk(fw, extracted_dir)
        if not self.running:
            return
        await self._progress(1, "Binwalk 解包", 100)

        # Phase 2 — Sensitive file scan
        await self._progress(2, "Firmwalker 敏感掃描", 5)
        count2 = await self._phase2_sensitive_scan(extracted_dir)
        total += count2
        if not self.running:
            return
        await self._progress(2, "Firmwalker 敏感掃描", 100)

        # Phase 3 — checksec on ELFs
        await self._progress(3, "checksec ELF 分析", 5)
        count3 = await self._phase3_checksec(extracted_dir)
        total += count3
        if not self.running:
            return
        await self._progress(3, "checksec ELF 分析", 100)

        # Phase 4 — Summary
        await self._progress(4, "彙整報告", 50)
        await self._log("ok", f"[firmware] 分析完成 | 架構: {arch} | 檔案系統: {fs_type} | 發現: {total}")
        await self._progress(4, "彙整報告", 100)
        await self._done({"total_findings": total})
        self.running = False

    # ── Phase 1 ───────────────────────────────────────────────────────────────

    async def _phase1_binwalk(self, fw_path: Path, out_dir: Path) -> tuple[str, str]:
        await self._log("info", f"[Phase 1] binwalk 解包: {fw_path.name}")

        binwalk = config.BINWALK_BIN
        if not Path(binwalk).exists():
            await self._log("warn", f"[Phase 1] binwalk 未找到於 {binwalk}，嘗試 PATH")
            binwalk = "binwalk"

        cmd = f"{binwalk} --extract --matryoshka --directory {out_dir} {fw_path}"
        arch, fs_type = "unknown", "unknown"

        try:
            self.process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            async for line in self.process.stdout:
                if not self.running:
                    self.process.terminate()
                    break
                text = line.decode(errors="replace").rstrip()
                if not text:
                    continue
                await self._log("info", text)
                tl = text.lower()
                for a in ("mips", "arm", "aarch64", "x86", "powerpc", "sh4"):
                    if a in tl:
                        arch = a.upper()
                for fs in ("squashfs", "jffs2", "ubifs", "cramfs", "ext2", "yaffs"):
                    if fs in tl:
                        fs_type = fs
            await self.process.wait()
        except Exception as exc:
            await self._error(f"[Phase 1] binwalk error: {exc}")

        await self._log("ok", f"[Phase 1] 完成 — 架構: {arch}, 檔案系統: {fs_type}")
        return arch, fs_type

    # ── Phase 2 ───────────────────────────────────────────────────────────────

    async def _phase2_sensitive_scan(self, root_dir: Path) -> int:
        await self._log("info", f"[Phase 2] 敏感檔案掃描")
        if not root_dir.exists():
            await self._log("warn", "[Phase 2] 解包目錄不存在，跳過")
            return 0

        count = 0
        files = [f for f in root_dir.rglob("*") if f.is_file()]
        await self._log("info", f"[Phase 2] 掃描 {len(files)} 個檔案")

        for filepath in files:
            if not self.running:
                break
            if filepath.suffix.lower() in SKIP_EXTENSIONS:
                continue
            try:
                if filepath.stat().st_size > 5_000_000:
                    continue
                content = filepath.read_text(errors="replace")
            except Exception:
                continue

            for pat_name, pattern in DANGEROUS_PATTERNS.items():
                match = re.search(pattern, content, re.MULTILINE)
                if not match:
                    continue
                line_no = content[: match.start()].count("\n") + 1
                snippet = match.group(0)[:120]
                severity = "critical" if pat_name in ("private_key", "backdoor_uid0") else "high"
                title = FINDING_TITLES.get(pat_name, pat_name)
                rel = str(filepath.relative_to(root_dir))

                await self._alert(
                    severity,
                    f"[韌體] {title}",
                    f"{rel}:{line_no} — {snippet[:80]}",
                )
                self._save_finding(
                    severity=severity,
                    title=f"[韌體] {title}",
                    detail=snippet,
                    path=f"{rel}:{line_no}",
                )
                count += 1
                break  # One finding per pattern per file to avoid explosion

        await self._log("ok", f"[Phase 2] 完成，共 {count} 個敏感發現")
        return count

    # ── Phase 3 ───────────────────────────────────────────────────────────────

    async def _phase3_checksec(self, root_dir: Path) -> int:
        await self._log("info", "[Phase 3] checksec ELF 分析")
        if not root_dir.exists():
            await self._log("warn", "[Phase 3] 解包目錄不存在，跳過")
            return 0

        # Find ELF files by magic bytes
        elfs: list[Path] = []
        for fp in root_dir.rglob("*"):
            if not fp.is_file() or fp.stat().st_size < 4:
                continue
            try:
                with open(fp, "rb") as f:
                    if f.read(4) == b"\x7fELF":
                        elfs.append(fp)
            except Exception:
                continue

        await self._log("info", f"[Phase 3] 找到 {len(elfs)} 個 ELF")
        count = 0

        for elf in elfs:
            if not self.running:
                break
            issues = await asyncio.get_event_loop().run_in_executor(
                None, self._run_checksec, elf
            )
            if issues:
                rel = str(elf.relative_to(root_dir))
                severity = "critical" if "NX disabled" in issues else "high"
                await self._result({
                    "severity": severity,
                    "title":    f"[韌體] 二進位安全屬性缺失",
                    "detail":   f"{rel} — {', '.join(issues)}",
                    "path":     rel,
                })
                self._save_finding(
                    severity=severity,
                    title="[韌體] 二進位安全屬性缺失",
                    detail=f"{rel} — {', '.join(issues)}",
                    path=rel,
                )
                count += 1

        await self._log("ok", f"[Phase 3] 完成，{count} 個不安全 ELF")
        return count

    def _run_checksec(self, elf: Path) -> list[str]:
        checksec = config.CHECKSEC_BIN
        try:
            res = subprocess.run(
                [checksec, "--file", str(elf), "--format=json"],
                capture_output=True, text=True, timeout=10,
            )
            data = json.loads(res.stdout)
            elf_data = next(iter(data.values()), {}) if isinstance(data, dict) else {}
        except Exception:
            return []

        issues = []
        nx      = elf_data.get("nx", {})
        canary  = elf_data.get("canary", {})
        relro   = elf_data.get("relro", {})
        pie     = elf_data.get("pie", {})

        def desc(d): return (d.get("description") or "").lower() if isinstance(d, dict) else ""

        if "disabled" in desc(nx) or "no nx" in desc(nx):
            issues.append("NX disabled")
        if "no canary" in desc(canary):
            issues.append("No stack canary")
        if "no relro" in desc(relro):
            issues.append("No RELRO")
        if "no pie" in desc(pie) or "disabled" in desc(pie):
            issues.append("No PIE")
        return issues

    # ── DB helper ─────────────────────────────────────────────────────────────

    def _save_finding(self, severity: str, title: str,
                      detail: str | None = None, path: str | None = None):
        if self.db is None:
            return
        from models.finding import Finding, Severity

        sev_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
        }
        row = Finding(
            session_id=self.session_id,
            module="firmware",
            host="N/A",
            severity=sev_map.get(severity, Severity.INFO),
            title=title,
            detail=detail,
            path=path,
        )
        self.db.add(row)
        self.db.commit()
