import asyncio
from runners.base_runner import BaseRunner

BRAND_DEFAULTS: dict[str, list[tuple[str, str]]] = {
    "hikvision": [("admin", "12345"), ("admin", "admin123"), ("admin", "")],
    "dahua":     [("admin", "admin"), ("888888", "888888"), ("666666", "666666")],
    "dlink":     [("admin", ""), ("admin", "admin"), ("admin", "1234")],
    "tplink":    [("admin", "admin"), ("admin", ""), ("admin", "tplink")],
    "asus":      [("admin", "admin"), ("admin", "password")],
    "netgear":   [("admin", "password"), ("admin", "1234")],
    "axis":      [("root", "pass"), ("root", "root")],
}

COMMON_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"), ("admin", ""), ("root", "root"),
    ("admin", "1234"), ("admin", "password"), ("user", "user"),
    ("admin", "admin123"), ("admin", "12345"), ("root", ""),
    ("administrator", ""), ("guest", "guest"), ("admin", "123456"),
]

PORT_SERVICE: dict[int, str] = {
    22: "ssh", 23: "telnet", 80: "http", 443: "https",
    8080: "http", 8443: "https", 1883: "mqtt", 8883: "mqtt",
}


class PasswordRunner(BaseRunner):
    def __init__(self, session_id: int, ws_send, db=None):
        super().__init__(session_id, ws_send)
        self.db = db

    async def start(
        self,
        host: str,
        ports: list[int],
        brand: str = "",
        services: list[str] | None = None,
    ):
        self.running = True

        # Build deduped credential list: brand-specific first, then common
        creds: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for c in (BRAND_DEFAULTS.get(brand, []) + COMMON_CREDS):
            if c not in seen:
                seen.add(c)
                creds.append(c)

        sem = asyncio.Semaphore(3)
        tasks = []

        for port in ports:
            service = PORT_SERVICE.get(port)
            if service:
                tasks.append(
                    self._check_service(host, port, service, creds, sem)
                )

        if not tasks:
            await self._log("warn", "[密碼] 無可測試的服務（不支援的 port）")
            await self._done({"total_findings": 0})
            self.running = False
            return

        brand_label = f" [{brand}]" if brand else ""
        await self._log(
            "info",
            f"[密碼]{brand_label} 開始測試 {host}，{len(tasks)} 個服務，{len(creds)} 組帳密",
        )

        await asyncio.gather(*tasks, return_exceptions=True)

        if self.running:
            await self._done({"total_findings": 0})
        self.running = False

    async def _check_service(
        self,
        host: str, port: int, service: str,
        creds: list[tuple[str, str]], sem: asyncio.Semaphore,
    ):
        await self._log("info", f"[密碼] 測試 {service.upper()}:{port}")
        for user, passwd in creds:
            if not self.running:
                return
            try:
                ok = await asyncio.wait_for(
                    self._try_cred(host, port, service, user, passwd),
                    timeout=9,
                )
                if ok:
                    display = passwd if passwd else "(空白)"
                    await self._alert(
                        "critical",
                        f"預設密碼登入成功 [{service.upper()}:{port}]",
                        f"帳號: {user}  密碼: {display}",
                        host=host, port=port, service=service,
                    )
                    self._save_finding(host, port, service, user, passwd)
                    return  # Stop after first hit per service
            except asyncio.TimeoutError:
                pass
            except Exception as exc:
                await self._log("warn", f"[密碼] {service}:{port} {user}: {exc}")
            await asyncio.sleep(0.4)

    async def _try_cred(
        self, host: str, port: int, service: str, user: str, passwd: str
    ) -> bool:
        if service in ("http", "https"):
            return await self._try_http(host, port, service, user, passwd)
        if service == "ssh":
            return await self._try_ssh(host, port, user, passwd)
        if service == "mqtt":
            return await self._try_mqtt(host, port, user, passwd)
        return False

    async def _try_http(
        self, host: str, port: int, scheme: str, user: str, passwd: str
    ) -> bool:
        try:
            import aiohttp
            url = f"{scheme}://{host}:{port}/"
            ssl_verify = scheme == "https"
            connector = aiohttp.TCPConnector(ssl=False) if scheme == "https" else None
            auth = aiohttp.BasicAuth(user, passwd)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    url, auth=auth,
                    timeout=aiohttp.ClientTimeout(total=7),
                    allow_redirects=False,
                ) as resp:
                    # 200/201 = success; 302 without WWW-Authenticate = redirect after login
                    if resp.status in (200, 201, 204):
                        return True
                    if resp.status in (301, 302):
                        # Distinguish redirect-on-login from "always redirects unauth"
                        return "www-authenticate" not in resp.headers
                    return False
        except ImportError:
            await self._log("warn", "[密碼] aiohttp 未安裝，跳過 HTTP 測試")
            return False
        except Exception:
            return False

    async def _try_ssh(self, host: str, port: int, user: str, passwd: str) -> bool:
        try:
            import asyncssh
            conn = await asyncssh.connect(
                host, port=port, username=user, password=passwd,
                known_hosts=None, connect_timeout=7,
            )
            conn.close()
            return True
        except ImportError:
            await self._log("warn", "[密碼] asyncssh 未安裝，跳過 SSH 測試")
            return False
        except asyncssh.PermissionDenied:
            return False
        except Exception:
            return False

    async def _try_mqtt(self, host: str, port: int, user: str, passwd: str) -> bool:
        try:
            import aiomqtt
            async with aiomqtt.Client(
                hostname=host, port=port,
                username=user, password=passwd,
                timeout=7,
            ):
                return True
        except ImportError:
            await self._log("warn", "[密碼] aiomqtt 未安裝，跳過 MQTT 測試")
            return False
        except Exception:
            return False

    def _save_finding(
        self, host: str, port: int, service: str, user: str, passwd: str
    ):
        if self.db is None:
            return
        from models.finding import Finding, Severity

        row = Finding(
            session_id=self.session_id,
            module="credential",
            host=f"{host}:{port}",
            severity=Severity.CRITICAL,
            title=f"預設密碼登入成功 [{service.upper()}:{port}]",
            detail=f"帳號: {user}  密碼: {passwd if passwd else '(空白)'}",
            cvss_score=9.8,
            remediation="立即更改預設密碼，並啟用帳號鎖定機制",
        )
        self.db.add(row)
        self.db.commit()
