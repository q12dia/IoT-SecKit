import asyncio
import xml.etree.ElementTree as ET
from typing import Callable, Awaitable

from runners.base_runner import BaseRunner

IOT_DEFAULT_PORTS = "22,23,80,443,1883,5683,8080,8883,502,4840,47808,161"

DEPTH_FLAGS: dict[str, str] = {
    "quick":    "-sn -T4",
    "standard": "-sV -T3 --open",
    "deep":     "-sV -O -A -T2 --open",
    "all_tcp":  "-p 1-65535 -T4 -A -v",
    "all_udp":  "-sS -sU -T4 -A -v",
}

NSE_SCRIPTS: dict[str, str] = {
    "banner": "banner",
    "vulners": "vulners",
    "mqtt": "mqtt-subscribe",
    "http": "http-title,http-headers",
    "snmp": "snmp-info",
}

# Port → IoT service metadata + optional auto-check
IOT_SERVICE_RULES: dict[int, dict] = {
    1883:  {"service": "mqtt",   "auto_check": "anon_login"},
    5683:  {"service": "coap",   "auto_check": None},
    502:   {"service": "modbus", "auto_check": "unauth_read"},
    47808: {"service": "bacnet", "auto_check": None},
    4840:  {"service": "opc-ua", "auto_check": None},
}


class NmapRunner(BaseRunner):
    def __init__(
        self,
        session_id: int,
        ws_send: Callable[[dict], Awaitable[None]],
        db,
        on_complete: Callable[[int], Awaitable[None]] | None = None,
    ):
        super().__init__(session_id, ws_send)
        self.db          = db
        self.on_complete = on_complete   # cross-module hook

    # ── public API ────────────────────────────────────────────────────────────

    async def start(
        self,
        target: str,
        depth: str = "standard",
        ports: str = IOT_DEFAULT_PORTS,
        extra_scripts: list[str] | None = None,
        extra_flags: str | None = None,
    ):
        self.running = True
        flags   = DEPTH_FLAGS.get(depth, DEPTH_FLAGS["standard"])
        scripts = ",".join(
            [NSE_SCRIPTS["banner"], NSE_SCRIPTS["vulners"]]
            + (extra_scripts or [])
        )
        xml_out = f"/tmp/nmap_{self.session_id}.xml"

        # Don't add -p when flags already contain a port range (e.g. all_tcp/all_udp)
        port_arg = "" if "-p" in flags else f"-p {ports}"

        user_flags = extra_flags.strip() if extra_flags else ""
        cmd = (
            f"nmap {flags} {port_arg} "
            f"--script {scripts} "
            f"{user_flags} "
            f"-oX {xml_out} {target}"
        )
        await self._log("info", f"Starting nmap: {cmd}")

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
                findings_count = await self._parse_xml(xml_out, target)
                await self._done({"total_findings": findings_count})
                if self.on_complete:
                    await self.on_complete(self.session_id)

        except Exception as exc:
            await self._error(str(exc))
        finally:
            self.running = False

    # ── XML parsing ──────────────────────────────────────────────────────────

    async def _parse_xml(self, xml_path: str, target: str) -> int:
        try:
            tree = ET.parse(xml_path)
        except (FileNotFoundError, ET.ParseError) as exc:
            await self._error(f"XML parse error: {exc}")
            return 0

        root        = tree.getroot()
        saved_count = 0

        for host_el in root.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            host_ip = addr_el.get("addr", target)

            os_guess = self._extract_os(host_el)

            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port     = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")
                svc_el   = port_el.find("service")
                service  = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                version  = self._extract_version(svc_el) if svc_el is not None else ""
                banner   = self._extract_banner(port_el)
                is_iot   = 1 if port in IOT_SERVICE_RULES else 0

                # Override service name for known IoT ports
                if port in IOT_SERVICE_RULES:
                    service = IOT_SERVICE_RULES[port]["service"]

                scripts_out = self._extract_scripts(port_el)
                cves        = self._extract_cves(port_el)

                result = {
                    "host":        host_ip,
                    "port":        port,
                    "protocol":    protocol,
                    "service":     service,
                    "version":     version,
                    "banner":      banner,
                    "os_guess":    os_guess,
                    "is_iot":      is_iot,
                    "scripts":     scripts_out,   # [{"id": ..., "output": ...}]
                    "cves":        cves,           # [{"id": ..., "cvss": ...}]
                }
                await self._result(result)
                self._save_scan_result(result)
                saved_count += 1

                if is_iot:
                    await self._check_iot_service(host_ip, port, service)

        return saved_count

    # ── helpers ──────────────────────────────────────────────────────────────

    def _extract_os(self, host_el: ET.Element) -> str:
        osmatch = host_el.find(".//osmatch")
        if osmatch is not None:
            return osmatch.get("name", "")
        return ""

    def _extract_version(self, svc_el: ET.Element) -> str:
        parts = [
            svc_el.get("product", ""),
            svc_el.get("version", ""),
            svc_el.get("extrainfo", ""),
        ]
        return " ".join(p for p in parts if p).strip()

    def _extract_banner(self, port_el: ET.Element) -> str:
        for script in port_el.findall("script"):
            if script.get("id") == "banner":
                return script.get("output", "")
        return ""

    def _extract_scripts(self, port_el: ET.Element) -> list[dict]:
        results = []
        for script in port_el.findall("script"):
            sid = script.get("id", "")
            out = script.get("output", "").strip()
            if sid and out and sid != "banner":
                results.append({"id": sid, "output": out})
        return results

    def _extract_cves(self, port_el: ET.Element) -> list[dict]:
        cves = []
        for script in port_el.findall("script"):
            if script.get("id") != "vulners":
                continue
            # vulners outputs nested <table> elements per CVE
            for tbl in script.findall(".//table"):
                cve_id = ""
                cvss   = ""
                for elem in tbl.findall("elem"):
                    key = elem.get("key", "")
                    if key == "id":
                        cve_id = elem.text or ""
                    elif key == "cvss":
                        cvss = elem.text or ""
                if cve_id:
                    cves.append({"id": cve_id, "cvss": cvss})
        return cves[:10]  # cap at 10 per port

    def _save_scan_result(self, data: dict):
        if self.db is None:
            return
        from models.scan_result import ScanResult

        row = ScanResult(
            session_id=self.session_id,
            host=data["host"],
            port=data["port"],
            protocol=data["protocol"],
            service=data["service"],
            version=data["version"],
            banner=data.get("banner"),
            os_guess=data.get("os_guess"),
            is_iot=data.get("is_iot", 0),
        )
        self.db.add(row)
        self.db.commit()

    async def _check_iot_service(self, host: str, port: int, service: str):
        rule = IOT_SERVICE_RULES.get(port, {})
        check = rule.get("auto_check")
        if check == "anon_login":
            await self._log("warn", f"MQTT port {port} detected on {host} — checking anonymous login...")
            # Placeholder: actual MQTT anon check implemented in credential runner
        elif check == "unauth_read":
            await self._log("warn", f"Modbus port {port} detected on {host} — unauth read possible")
