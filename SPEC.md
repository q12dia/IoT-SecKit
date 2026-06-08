# IoT SecKit — 完整開發規格文件

> 執行環境：Kali Linux 2024.x  
> 後端：Python 3.11+ / FastAPI  
> 前端：Vanilla HTML + CSS + JS（沿用原型設計）  
> 資料庫：SQLite 3 + SQLAlchemy 2.0  
> 文件版本：v1.0 · 2025-06-08 · 機密

\---

## 目錄

1. [專案總覽](#1-專案總覽)
2. [Kali Linux 環境設定](#2-kali-linux-環境設定)
3. [目錄結構](#3-目錄結構)
4. [資料庫 Schema](#4-資料庫-schema)
5. [API 路由設計](#5-api-路由設計)
6. [各模組 Runner 規格](#6-各模組-runner-規格)
7. [模組間整合介面](#7-模組間整合介面)
8. [前端設計規範](#8-前端設計規範)
9. [報告產生規格](#9-報告產生規格)
10. [Claude Code 開發優先順序](#10-claude-code-開發優先順序)

\---

## 1\. 專案總覽

### 1.1 平台定位

IoT SecKit 是一個執行於 Kali Linux 的 IoT 資安檢測平台，以 Web UI 為統一操作介面，整合七個測試模組，讓資安人員可以對 IoT 設備執行全面性的安全評估，並於完成後一鍵產出 PDF 評估報告。

### 1.2 七大模組一覽

|#|模組名稱|核心工具|主要能力|
|-|-|-|-|
|01|模糊測試|Boofuzz + Scapy|協定畸形封包、crash 觸發、邊界值測試|
|02|掃描器|nmap 7.94 + NSE Scripts|服務發現、CVE 比對、IoT 設備指紋|
|03|憑證分析|testssl.sh + Hydra + sslyze|弱加密偵測、預設密碼、憑證鏈問題|
|04|韌體分析|Binwalk + Firmwalker + checksec|硬編碼金鑰、後門帳號、二進位安全屬性|
|05|流量攔截|tcpdump + PyShark + Scapy|明文傳輸、異常行為、MITM 攔截|
|06|設備弱點掃描|OpenVAS + RouterSploit + Metasploit|已知 CVE 主動驗證、廠牌專屬漏洞|
|07|網頁弱點掃描|Nikto + OWASP ZAP + Gobuster + SQLMap|OWASP Top 10、指令注入、敏感路徑|

### 1.3 技術棧

|層級|技術|說明|
|-|-|-|
|前端|Vanilla HTML + CSS + JS|單頁應用，沿用原型視覺設計|
|後端 API|FastAPI 0.110+|REST endpoints + WebSocket 即時串流|
|資料庫|SQLite 3 + SQLAlchemy 2.0|本機儲存，七模組共用 findings 表|
|任務執行|asyncio + subprocess|工具以子進程呼叫，非同步控制|
|即時推送|WebSocket (FastAPI)|封包串流、掃描進度、日誌串流|
|報告輸出|Jinja2 + WeasyPrint|HTML 模板轉 PDF 報告|
|執行環境|Kali Linux 2024.x|大多數工具已預裝|

\---

## 2\. Kali Linux 環境設定

### 2.1 一鍵安裝腳本

將以下內容儲存為 `setup\_kali.sh`，以 root 身分執行：

```bash
#!/bin/bash
set -e
echo "\[\*] IoT SecKit — Kali Linux 環境設定"

# 系統工具確認與安裝
for tool in nmap binwalk tcpdump tshark hydra checksec nikto gobuster sqlmap; do
  if ! command -v $tool \&>/dev/null; then
    echo "\[!] $tool 未安裝，執行安裝..."
    apt-get install -y $tool
  fi
done

# OpenVAS / GVM
apt-get install -y openvas gvm
gvm-setup \&\& gvm-start

# Metasploit
apt-get install -y metasploit-framework

# OWASP ZAP
apt-get install -y zaproxy

# 外部工具
\[ -d /opt/firmwalker ] || git clone https://github.com/craigz28/firmwalker /opt/firmwalker
\[ -d /opt/testssl ]    || git clone https://github.com/drwetter/testssl.sh /opt/testssl
chmod +x /opt/testssl/testssl.sh

# Python 套件
pip install -r requirements.txt --break-system-packages

# RouterSploit
pip install routersploit --break-system-packages

# 工作目錄
mkdir -p workspace/{firmware,captures,reports}

# 資料庫初始化
python -c "from database import engine; from models import Base; Base.metadata.create\_all(engine)"

echo "\[+] 完成！執行: sudo uvicorn main:app --host 0.0.0.0 --port 8000"
```

### 2.2 requirements.txt

```
fastapi>=0.110.0
uvicorn\[standard]>=0.27.0
sqlalchemy>=2.0.0
python-multipart>=0.0.9
websockets>=12.0
python-nmap>=0.7.1
pyshark>=0.6.0
scapy>=2.5.0
boofuzz>=0.4.2
sslyze>=5.2.0
cryptography>=41.0.0
asyncssh>=2.14.0
aiomqtt>=1.2.0
aiohttp>=3.9.0
python-owasp-zap-v2.4>=0.0.21
jinja2>=3.1.0
weasyprint>=60.0
trufflehog3>=3.0.0
```

### 2.3 Root 權限說明

下列操作需要 root 或特定 Linux capabilities：

|操作|工具|建議做法|
|-|-|-|
|封包擷取|tcpdump / Scapy|`sudo uvicorn` 或 `setcap cap\_net\_raw`|
|OS 指紋識別|nmap -O|同上|
|ARP 毒化 (MITM)|arpspoof / Scapy|需明確書面授權，再以 sudo 執行|
|原始封包注入|Scapy sendp()|`setcap cap\_net\_raw,cap\_net\_admin+eip`|
|OpenVAS 掃描|gvm-cli|以 root 或 \_gvm 群組執行|

```bash
# 建議做法（避免整個 uvicorn 跑 root）
sudo setcap cap\_net\_raw,cap\_net\_admin+eip $(which python3)
uvicorn main:app --host 0.0.0.0 --port 8000
```

\---

## 3\. 目錄結構

```
iot-seckit/
├── main.py                          # FastAPI 進入點，掛載所有 router
├── config.py                        # 全域常數、路徑、工具位置
├── database.py                      # SQLAlchemy engine + Session
├── requirements.txt
├── setup\_kali.sh                    # 一鍵環境安裝腳本
│
├── models/                          # ORM 資料模型
│   ├── \_\_init\_\_.py
│   ├── session.py                   # TestSession
│   ├── finding.py                   # Finding（七模組共用）
│   ├── scan\_result.py               # ScanResult（掃描器服務清單）
│   ├── capture.py                   # CaptureSession（流量攔截）
│   └── firmware.py                  # FirmwareAnalysis（韌體）
│
├── routers/                         # FastAPI 路由（每模組一檔）
│   ├── fuzzing.py
│   ├── scanner.py
│   ├── credential.py
│   ├── firmware.py
│   ├── traffic.py
│   ├── devscan.py                   # 設備弱點掃描
│   ├── webscan.py                   # 網頁弱點掃描
│   └── reports.py
│
├── runners/                         # 工具執行器（核心邏輯）
│   ├── base\_runner.py               # 共用抽象介面
│   ├── boofuzz\_runner.py
│   ├── scapy\_runner.py
│   ├── nmap\_runner.py
│   ├── tls\_runner.py
│   ├── password\_runner.py
│   ├── firmware\_runner.py
│   ├── traffic\_runner.py
│   ├── openvas\_runner.py
│   ├── routersploit\_runner.py
│   ├── metasploit\_runner.py
│   ├── nikto\_runner.py
│   ├── zap\_runner.py
│   └── gobuster\_runner.py
│
├── analyzers/                       # 結果解析器
│   ├── firmwalker\_parser.py
│   ├── checksec\_parser.py
│   ├── pcap\_analyzer.py
│   └── cve\_lookup.py
│
├── static/                          # 前端（沿用原型設計）
│   ├── index.html                   # 主介面 SPA
│   ├── css/
│   │   └── main.css
│   └── js/
│       ├── app.js                   # 模組切換、全域狀態
│       ├── ws-client.js             # WebSocket 管理
│       └── modules/                 # 各模組 UI 邏輯
│           ├── fuzzing.js
│           ├── scanner.js
│           ├── credential.js
│           ├── firmware.js
│           ├── traffic.js
│           ├── devscan.js
│           └── webscan.js
│
├── wordlists/                       # 密碼字典
│   ├── iot\_brands/
│   │   ├── dlink.txt
│   │   ├── hikvision.txt
│   │   ├── dahua.txt
│   │   ├── tplink.txt
│   │   ├── asus.txt
│   │   └── netgear.txt
│   └── common\_100.txt
│
├── workspace/                       # 執行期暫存（加入 .gitignore）
│   ├── firmware/
│   ├── captures/
│   └── reports/
│
├── reports/                         # 報告產生器
│   ├── template.html.j2
│   └── report\_generator.py
│
└── tests/
    └── test\_runners.py
```

\---

## 4\. 資料庫 Schema

### 4.1 TestSession — 測試會話

```python
# models/session.py
class TestSession(Base):
    \_\_tablename\_\_ = "test\_sessions"

    id          = Column(Integer, primary\_key=True)
    name        = Column(String(128))          # 使用者自定義名稱
    target\_ip   = Column(String(128))
    target\_desc = Column(String(256))          # 設備描述，e.g. "D-Link DIR-825 路由器"
    started\_at  = Column(DateTime, default=datetime.utcnow)
    finished\_at = Column(DateTime, nullable=True)
    status      = Column(String(32), default="running")  # running | done | stopped
```

### 4.2 Finding — 七模組共用發現記錄

```python
# models/finding.py
class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

class Finding(Base):
    \_\_tablename\_\_ = "findings"

    id          = Column(Integer, primary\_key=True, index=True)
    session\_id  = Column(Integer, ForeignKey("test\_sessions.id"), nullable=False)
    module      = Column(String(32), nullable=False)
    # 可填值: fuzzing | scanner | credential | firmware | traffic | devscan | webscan
    host        = Column(String(128))           # IP:port 或 N/A（韌體分析時）
    severity    = Column(Enum(Severity), nullable=False)
    title       = Column(String(256), nullable=False)
    detail      = Column(Text)
    path        = Column(String(512))           # 檔案路徑 / URL / 封包序號
    cvss\_score  = Column(Float)                 # 0.0 – 10.0
    cve\_id      = Column(String(32))            # e.g. CVE-2021-36260
    remediation = Column(Text)
    raw\_output  = Column(Text)                  # 工具原始輸出
    created\_at  = Column(DateTime, default=datetime.utcnow)
```

### 4.3 ScanResult — 掃描器服務清單（供其他模組複用）

```python
# models/scan\_result.py
class ScanResult(Base):
    \_\_tablename\_\_ = "scan\_results"

    id         = Column(Integer, primary\_key=True)
    session\_id = Column(Integer, ForeignKey("test\_sessions.id"))
    host       = Column(String(128))
    port       = Column(Integer)
    protocol   = Column(String(16))             # tcp | udp
    service    = Column(String(64))             # http | mqtt | ssh | modbus ...
    version    = Column(String(256))            # 服務版本字串
    banner     = Column(Text)
    os\_guess   = Column(String(128))
    is\_iot     = Column(Integer, default=0)     # 1 = 確認為 IoT 特徵服務
    created\_at = Column(DateTime, default=datetime.utcnow)
```

### 4.4 CaptureSession 與 FirmwareAnalysis

```python
# models/capture.py
class CaptureSession(Base):
    \_\_tablename\_\_ = "capture\_sessions"

    id          = Column(Integer, primary\_key=True)
    session\_id  = Column(Integer, ForeignKey("test\_sessions.id"))
    pcap\_path   = Column(String(512))
    iface       = Column(String(32))
    bpf\_filter  = Column(String(256))
    total\_pkts  = Column(Integer, default=0)
    total\_bytes = Column(Integer, default=0)
    started\_at  = Column(DateTime, default=datetime.utcnow)
    stopped\_at  = Column(DateTime, nullable=True)

# models/firmware.py
class FirmwareAnalysis(Base):
    \_\_tablename\_\_ = "firmware\_analyses"

    id           = Column(Integer, primary\_key=True)
    session\_id   = Column(Integer, ForeignKey("test\_sessions.id"))
    filename     = Column(String(256))
    file\_size    = Column(Integer)
    arch         = Column(String(32))           # MIPS | ARM | x86
    endian       = Column(String(4))            # LE | BE
    filesystem   = Column(String(32))           # SquashFS | JFFS2 | UBIFS | CRAMFS
    os\_version   = Column(String(128))
    file\_count   = Column(Integer)
    elf\_count    = Column(Integer)
    extract\_path = Column(String(512))
    created\_at   = Column(DateTime, default=datetime.utcnow)
```

\---

## 5\. API 路由設計

### 5.1 REST 端點總覽

```
# 會話管理
POST   /api/sessions                         建立新測試會話
GET    /api/sessions                         列出歷史會話
GET    /api/sessions/{id}                    取得會話詳情
GET    /api/sessions/{id}/findings           取得所有發現（七模組合併）
DELETE /api/sessions/{id}                    刪除會話

# 01 模糊測試
POST   /api/fuzzing/start                    啟動模糊測試
POST   /api/fuzzing/stop                     停止
WS     /ws/fuzzing/{session\_id}              即時日誌 + crash 告警串流

# 02 掃描器
POST   /api/scanner/start                    啟動 nmap 掃描
POST   /api/scanner/stop                     停止
GET    /api/scanner/{id}/services            取得發現的服務（供其他模組引用）
WS     /ws/scanner/{session\_id}              即時掃描結果串流

# 03 憑證分析
POST   /api/credential/start                 啟動 TLS + 密碼掃描
POST   /api/credential/stop
WS     /ws/credential/{session\_id}           即時分析結果串流

# 04 韌體分析
POST   /api/firmware/upload                  上傳韌體檔案（multipart/form-data）
POST   /api/firmware/start                   啟動 Binwalk + Firmwalker
POST   /api/firmware/stop
WS     /ws/firmware/{session\_id}             四階段進度 + 發現串流

# 05 流量攔截
GET    /api/traffic/interfaces               列出可用網路介面
POST   /api/traffic/start                    啟動 tcpdump 擷取
POST   /api/traffic/stop                     停止擷取並存 pcap
GET    /api/traffic/{id}/pcap                下載 .pcap 檔案
WS     /ws/traffic/{session\_id}              即時封包 + 告警串流

# 06 設備弱點掃描
POST   /api/devscan/start                    啟動 OpenVAS + RouterSploit + Metasploit
POST   /api/devscan/stop
WS     /ws/devscan/{session\_id}              即時漏洞發現串流

# 07 網頁弱點掃描
POST   /api/webscan/start                    啟動 Nikto + ZAP + Gobuster
POST   /api/webscan/stop
WS     /ws/webscan/{session\_id}              即時 Web 弱點串流

# 報告
POST   /api/reports/generate/{session\_id}    產生完整 PDF 報告
GET    /api/reports/{id}/download            下載 PDF
```

### 5.2 WebSocket 訊息格式（七模組統一）

```json
{
  "type": "log | result | alert | progress | done | error",
  "ts":   "2025-06-08T10:23:45.123Z",
  "data": {}
}
```

**範例 — 掃描器發現服務：**

```json
{
  "type": "result",
  "ts": "2025-06-08T10:23:45.123Z",
  "data": {
    "host": "192.168.1.1",
    "port": 1883,
    "service": "mqtt",
    "version": "Mosquitto 1.4.8",
    "cve": "CVE-2017-7650",
    "severity": "high"
  }
}
```

**範例 — 安全告警：**

```json
{
  "type": "alert",
  "ts": "2025-06-08T10:23:46.001Z",
  "data": {
    "severity": "critical",
    "title": "MQTT 明文密碼",
    "detail": "CONNECT user=admin pass=admin123",
    "src\_ip": "192.168.1.15",
    "dst\_ip": "192.168.1.5",
    "proto": "MQTT"
  }
}
```

**範例 — 韌體分析階段進度：**

```json
{
  "type": "progress",
  "data": {
    "phase": 2,
    "phase\_name": "Firmwalker 敏感掃描",
    "pct": 45
  }
}
```

\---

## 6\. 各模組 Runner 規格

### 6.1 BaseRunner — 共用抽象介面

```python
# runners/base\_runner.py
from abc import ABC, abstractmethod

class BaseRunner(ABC):
    def \_\_init\_\_(self, session\_id: int, ws\_send):
        self.session\_id = session\_id
        self.ws\_send    = ws\_send       # async callable：推送訊息到前端
        self.process    = None          # subprocess 實例
        self.running    = False

    @abstractmethod
    async def start(self, \*\*kwargs): ...

    async def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()
            await self.process.wait()

    async def \_log(self, level: str, msg: str):
        await self.ws\_send({"type": "log", "data": {"level": level, "msg": msg}})

    async def \_result(self, data: dict):
        await self.ws\_send({"type": "result", "data": data})

    async def \_alert(self, severity: str, title: str, detail: str, \*\*kwargs):
        await self.ws\_send({"type": "alert",
                            "data": {"severity": severity,
                                     "title": title,
                                     "detail": detail, \*\*kwargs}})

    async def \_progress(self, phase: int, phase\_name: str, pct: int):
        await self.ws\_send({"type": "progress",
                            "data": {"phase": phase,
                                     "phase\_name": phase\_name,
                                     "pct": pct}})
```

### 6.2 模糊測試 Runner

```python
# runners/boofuzz\_runner.py

PROTOCOL\_PROFILES = {
    "icmp":    {"tool": "scapy",   "script": "fuzz\_icmp.py"},
    "tcp\_udp": {"tool": "scapy",   "script": "fuzz\_tcp.py"},
    "http":    {"tool": "boofuzz", "target\_port": 80},
    "mqtt":    {"tool": "boofuzz", "target\_port": 1883},
    "coap":    {"tool": "scapy",   "script": "fuzz\_coap.py"},
    "modbus":  {"tool": "boofuzz", "target\_port": 502},
    "mdns":    {"tool": "scapy",   "script": "fuzz\_mdns.py"},
    "uart":    {"tool": "serial",  "script": "fuzz\_uart.py"},
}

MUTATION\_STRATEGIES = {
    "random":   "--strategy random",
    "boundary": "--strategy boundary",
    "bit\_flip": "--strategy bit-flip",
    "dict":     "--strategy dict",
}

# crash 偵測：目標無回應超過 timeout 秒 → 記錄 Finding(severity=CRITICAL)
# 每個協定跑完後推送 progress done
```

### 6.3 掃描器 Runner

```python
# runners/nmap\_runner.py

IOT\_DEFAULT\_PORTS = "22,23,80,443,1883,5683,8080,8883,502,4840,47808,161"

DEPTH\_FLAGS = {
    "quick":    "-sn -T4",
    "standard": "-sV -T3 --open",
    "deep":     "-sV -O -A -T2 --open",
}

NSE\_SCRIPTS = {
    "banner":   "banner",
    "vulners":  "vulners",
    "mqtt":     "mqtt-subscribe",
    "http":     "http-title,http-headers",
    "snmp":     "snmp-info",
}

# IoT 特殊服務判斷規則
IOT\_SERVICE\_RULES = {
    1883:  {"service": "mqtt",    "auto\_check": "anon\_login"},
    5683:  {"service": "coap",    "auto\_check": None},
    502:   {"service": "modbus",  "auto\_check": "unauth\_read"},
    47808: {"service": "bacnet",  "auto\_check": None},
    4840:  {"service": "opc-ua",  "auto\_check": None},
}

# 實作要點：
# - nmap -oX 輸出 XML，用 python-nmap 解析
# - 每發現一個服務 → 推送 result，同時寫入 scan\_results 表
# - 發現 IoT\_SERVICE\_RULES 的埠 → 自動執行補充測試
# - 完成後呼叫 on\_scan\_complete() 觸發跨模組建議
```

### 6.4 憑證分析 Runner

```python
# runners/tls\_runner.py

WEAK\_PROTOS  = \["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
VULN\_CHECKS  = \["heartbleed", "poodle", "beast", "robot", "drown", "freak", "sweet32"]

CVSS\_MAP = {
    "heartbleed": 9.8,
    "poodle":     3.4,
    "beast":      3.4,
    "tls10":      5.3,
    "rc4":        5.9,
    "self\_signed":4.3,
    "rsa\_1024":   5.9,
    "sha1":       4.0,
    "hsts\_miss":  2.6,
}

# 實作：testssl.sh --jsonfile /tmp/result.json {host}:{port}
# 解析 JSON，對每個問題建立 Finding 並推送

# runners/password\_runner.py

BRAND\_DEFAULTS = {
    "hikvision": \[("admin", "12345"), ("admin", "admin123"), ("admin", "")],
    "dahua":     \[("admin", "admin"), ("888888", "888888"), ("666666", "666666")],
    "dlink":     \[("admin", ""), ("admin", "admin"), ("admin", "1234")],
    "tplink":    \[("admin", "admin"), ("admin", ""), ("admin", "tplink")],
    "asus":      \[("admin", "admin"), ("admin", "password")],
    "netgear":   \[("admin", "password"), ("admin", "1234")],
    "axis":      \[("root", "pass"), ("root", "root")],
}

# 支援的服務：HTTP Basic Auth / SSH (asyncssh) / Telnet / MQTT (aiomqtt) / SNMP
# 並發控制：asyncio.Semaphore，加入 delay 防帳號鎖定
# 命中 → 立即推送 alert(severity=CRITICAL)
```

### 6.5 韌體分析 Runner（四階段）

```python
# runners/firmware\_runner.py

# Phase 1 — Binwalk 解包
# binwalk --extract --matryoshka --directory {work\_dir} {fw\_path}
# 自動偵測：架構(MIPS/ARM/x86)、位元組序(LE/BE)、檔案系統、壓縮格式

# Phase 2 — Firmwalker + 自訂規則
DANGEROUS\_PATTERNS = {
    "private\_key":   r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "hardcoded\_pw":  r'(?i)(password|passwd|secret)\\s\*\[=:]\\s\*\["\\']?(?P<val>\[^\\s"\\']{4,})',
    "api\_token":     r"(?i)(api\[\_-]?key|bearer|token)\\s\*\[=:]\\s\*\[A-Za-z0-9+/.\_-]{20,}",
    "aws\_key":       r"AKIA\[0-9A-Z]{16}",
    "backdoor\_uid0": r":\\$\\w+\\$\[^:]+:0:0:",    # passwd UID=0 非 root
}
UNSAFE\_FUNCTIONS = \["strcpy", "sprintf", "gets", "strcat", "scanf", "memcpy"]

# Phase 3 — checksec 批次掃描所有 ELF
# checksec --file {elf} --format=json
# 記錄：NX / Stack Canary / RELRO(Full/Partial/No) / PIE / FORTIFY
# NX=False 且為網路服務 → severity=CRITICAL

# Phase 4 — 彙整，存入 findings，推送 done
```

### 6.6 流量攔截 Runner

```python
# runners/traffic\_runner.py

SENSITIVE\_PATTERNS = {
    "mqtt\_cred":     r"(?s)CONNECT.{0,50}(?:user|username)=(?P<u>\\S+).+?(?:pass|password)=(?P<p>\\S+)",
    "http\_basic":    r"Authorization: Basic (?P<b64>\[A-Za-z0-9+/=]+)",
    "mqtt\_wildcard": r"SUBSCRIBE\\s+#",
    "modbus\_write":  \[0x05, 0x06, 0x0F, 0x10, 0x16],   # 危險功能碼
    "api\_token":     r"(?i)(bearer|token)\[\\s:]+\[A-Za-z0-9.\_\\-]{20,}",
}

ANOMALY\_RULES = {
    "syn\_flood":      {"proto": "TCP", "flags": "S", "threshold": 200, "window\_sec": 1},
    "unexpected\_dst": {"whitelist\_cidrs": \["192.168.0.0/16", "10.0.0.0/8"]},
    "mqtt\_mass\_pub":  {"proto": "MQTT", "type": "PUBLISH", "threshold": 100, "window\_sec": 5},
}

# 實作要點：
# - tcpdump -i {iface} -w {pcap\_path} -U {bpf}  (-U = packet-buffered，降低延遲)
# - PyShark LiveCapture 同步解析（named pipe）
# - 每個封包：協定識別 → SENSITIVE\_PATTERNS 比對 → ANOMALY\_RULES 滑動視窗
# - MITM 模式需額外授權確認 flag 才可啟動 ARP 毒化
```

### 6.7 設備弱點掃描 Runner

```python
# runners/routersploit\_runner.py
# 執行：rsf.py -m scanners.autopwn --target {IP}
# 解析輸出：\[+] 開頭 = VULNERABLE
# 記錄 CVE 編號 + 模組名稱 + CVSS 評分
# 注意：僅執行 check()，絕不執行 exploit()

# runners/openvas\_runner.py
# 使用 gvm-cli 建立 target → task → 取得 report (XML)
# 解析 XML report，轉換為 Finding 物件

# runners/metasploit\_runner.py
# msfrpc 或 msfconsole 執行 auxiliary/scanner/\*/check
# 僅 check()，不 exploit()
# 支援：auxiliary/scanner/http/http\_login
#       auxiliary/scanner/mqtt/mqtt\_login
#       auxiliary/admin/scada/modbus\_findunitid
```

### 6.8 網頁弱點掃描 Runner

```python
# runners/nikto\_runner.py
# nikto -h {URL} -Format json -output /tmp/nikto\_{session\_id}.json
# 解析 JSON，轉換為 Finding

# runners/gobuster\_runner.py
# gobuster dir -u {URL} -w wordlists/iot\_web.txt -o /tmp/gobuster\_{session\_id}.txt
# IoT 專用字典包含：
#   /cgi-bin/, /admin/, /backup.cfg, /firmware.bin,
#   /api/, /shell, /debug, /config.bin, /passwd

# runners/zap\_runner.py
# from zapv2 import ZAPv2
# zap.spider.scan(url)   → 爬蟲
# zap.ascan.scan(url)    → 主動掃描（OWASP Top 10）
# zap.core.alerts()      → 轉換為 Finding
# OWASP 分類對應：A01 / A03 / A05 / A07 ...

# runners/gobuster\_runner.py + sqlmap\_runner.py 整合：
# Gobuster 找到帶參數 URL → 自動觸發 SQLMap
# sqlmap -u {URL} --batch --level 3 --risk 2
```

\---

## 7\. 模組間整合介面

### 7.1 資料流架構

```
掃描器（scan\_results 表）
   │
   ├─ 發現 HTTP/HTTPS ──────────→ 憑證分析（自動帶入 host:port）
   │                               網頁弱點掃描（自動帶入 URL）
   │
   ├─ 發現 MQTT port 1883 ───────→ 模糊測試（MQTT corpus seed）
   │                               憑證分析（MQTT 匿名登入測試）
   │
   └─ 發現 Modbus/S7comm ────────→ 設備弱點掃描（工控規則集）

流量攔截（alerts）
   ├─ 明文帳密解碼 ─────────────→ 憑證分析（加入 session wordlist）
   ├─ MQTT payload 結構 ─────────→ 模糊測試（payload corpus）
   └─ 非預期對外連線 ────────────→ 前端提示：建議執行韌體分析

韌體分析（findings）
   ├─ 硬編碼密碼 ───────────────→ 憑證分析（wordlist+）
   └─ ELF 無保護二進位 ──────────→ 模糊測試（標記優先目標）

全部模組 ───────────────────────→ findings 表 → PDF 報告
```

### 7.2 跨模組事件 API（後端內部）

```python
# 掃描完成後：通知前端可啟動哪些後續模組
async def on\_scan\_complete(session\_id: int, db: Session):
    services = db.query(ScanResult).filter\_by(session\_id=session\_id).all()
    suggestions = \[]

    if any(s.service in \["http", "https"] for s in services):
        suggestions.append("credential")   # TLS + 密碼掃描
        suggestions.append("webscan")      # Web 弱點掃描

    if any(s.port == 1883 for s in services):
        suggestions.append("fuzzing")      # MQTT fuzzing

    if any(s.service == "modbus" for s in services):
        suggestions.append("devscan")      # 工控漏洞驗證

    await notify\_frontend(session\_id, {
        "type": "suggestions",
        "data": suggestions
    })


# 韌體分析發現硬編碼密碼 → 加入憑證分析字典
async def on\_firmware\_finding(finding: Finding, session\_id: int):
    if "硬編碼" in finding.title and finding.detail:
        cred = extract\_cred(finding.detail)     # 解析 user:pass
        if cred:
            await append\_session\_wordlist(session\_id, cred)


# 流量攔截發現 C\&C 連線 → 建議韌體分析
async def on\_traffic\_alert(alert: dict, session\_id: int):
    if alert.get("severity") == "critical" and "對外連線" in alert.get("title", ""):
        await notify\_frontend(session\_id, {
            "type": "suggestion",
            "data": {"module": "firmware", "reason": "疑似 C\&C 通訊，建議執行韌體分析確認後門"}
        })
```

\---

## 8\. 前端設計規範

### 8.1 視覺設計原則（完全沿用原型）

|設計元素|規範|
|-|-|
|字體|標籤文字 `var(--font-sans)`，所有技術值（IP、指令、版本號）使用 `var(--font-mono)`|
|邊框|統一 `0.5px solid var(--color-border-tertiary)`，強調用 `-secondary`|
|圓角|卡片 `var(--border-radius-lg)` = 12px，元件 `var(--border-radius-md)` = 8px|
|側邊欄|寬 210px，深色背景，active 項目右側 2px info 色邊線|
|CRITICAL|`var(--color-background-danger)` 底 + `var(--color-text-danger)` 文字|
|HIGH|`#fef3c7` 底 + `#92400e` 文字|
|MEDIUM|`var(--color-background-warning)` 底 + `var(--color-text-warning)` 文字|
|LOW|`var(--color-background-success)` 底 + `var(--color-text-success)` 文字|
|即時日誌|黑底 `#0d1117`，綠=ok / 黃=warn / 紅=err / 藍=info，11px mono|
|狀態點|idle=灰、running=綠色閃爍、capturing=紅色閃爍|
|深色模式|所有顏色使用 CSS var()，禁止 hardcode hex，自動適應 dark mode|

### 8.2 側邊欄結構

```
測試工具 ─────────────────────────────
  01  模糊測試          ti-bug
  02  掃描器            ti-radar
  03  憑證分析          ti-certificate
  04  韌體分析          ti-cpu
  05  流量攔截          ti-network
───────────────────────────────────────
弱點驗證
  06  設備弱點掃描      ti-device-desktop-search   \[NEW]
  07  網頁弱點掃描      ti-world-search            \[NEW]
───────────────────────────────────────
系統
      測試報告          ti-report
      設定              ti-settings
```

### 8.3 WebSocket 客戶端（統一）

```javascript
// static/js/ws-client.js
class WSClient {
  constructor(module, sessionId, handlers) {
    this.url = `ws://localhost:8000/ws/${module}/${sessionId}`;
    this.handlers = handlers;   // { log, result, alert, progress, done, error }
    this.reconnectDelay = 1000;
  }

  connect() {
    this.ws = new WebSocket(this.url);
    this.ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      this.handlers\[msg.type]?.(msg.data, msg.ts);
    };
    this.ws.onclose = () =>
      setTimeout(() => this.connect(), this.reconnectDelay);
    this.ws.onerror = (err) =>
      console.error(`\[WSClient] ${this.url}`, err);
  }

  send(data) { this.ws?.send(JSON.stringify(data)); }
  disconnect() { this.ws?.close(); }
}
```

### 8.4 模組切換（SPA）

```javascript
// static/js/app.js
const MODULE\_META = {
  fuzzing:    { title: "模糊測試 (Fuzzing)",                meta: "Boofuzz + Scapy" },
  scanner:    { title: "掃描器 (Scanner)",                  meta: "nmap 7.94 + NSE Scripts" },
  credential: { title: "憑證分析 (Credential Analysis)",    meta: "testssl.sh · sslyze · Hydra" },
  firmware:   { title: "韌體分析 (Firmware Analysis)",      meta: "Binwalk · Firmwalker · checksec" },
  traffic:    { title: "流量攔截 (Traffic Interception)",   meta: "tcpdump · PyShark · Scapy" },
  devscan:    { title: "設備弱點掃描 (Device Vuln Scan)",   meta: "OpenVAS · RouterSploit · Metasploit" },
  webscan:    { title: "網頁弱點掃描 (Web Vuln Scan)",      meta: "Nikto · OWASP ZAP · Gobuster · SQLMap" },
};

function switchModule(name) {
  document.querySelectorAll(".ni").forEach(el => el.classList.remove("active"));
  document.querySelector(`\[data-m="${name}"]`)?.classList.add("active");
  document.querySelectorAll(".panel").forEach(el => el.classList.remove("active"));
  document.getElementById(`panel-${name}`)?.classList.add("active");

  const meta = MODULE\_META\[name];
  if (meta) {
    document.getElementById("tb-title").textContent = meta.title;
    document.getElementById("tb-meta").textContent  = meta.meta;
  }
}
```

\---

## 9\. 報告產生規格

### 9.1 PDF 報告章節

|#|章節|內容|
|-|-|-|
|1|執行摘要|CRITICAL/HIGH 數量、最高風險設備、建議立即處理項目|
|2|目標資訊|IP、設備類型、測試時間範圍、測試人員|
|3|掃描結果|開放服務表格、CVE 命中清單|
|4|TLS/SSL 分析|協定版本弱點、加密套件問題、憑證詳情|
|5|預設密碼|成功登入的帳密清單、受影響服務|
|6|韌體分析|硬編碼敏感資訊、二進位安全屬性表格|
|7|流量分析|明文傳輸告警清單、異常行為記錄|
|8|設備弱點|CVE 清單含 CVSS 評分、RouterSploit 命中|
|9|網頁弱點|OWASP Top 10 對應、弱點 URL 清單|
|10|CVSS 總表|所有發現按 CVSS 評分降序排列|
|11|修補建議|依優先順序排列，每項含具體步驟|

### 9.2 CVSS 評分對照表

|發現類型|CVSS|嚴重等級|
|-|-|-|
|預設密碼登入成功 / HEARTBLEED / RCE|9.8|CRITICAL|
|硬編碼私鑰 / 後門帳號 UID=0|8.6|CRITICAL|
|Modbus 未授權寫入|8.1|HIGH|
|SQL Injection / 指令注入 (Web)|8.0|HIGH|
|MQTT 明文密碼傳輸|7.5|HIGH|
|TLS 1.0 / 1.1 啟用|5.3|MEDIUM|
|自簽憑證|4.3|MEDIUM|
|RSA 1024 bit 弱金鑰|5.9|MEDIUM|
|SHA-1 憑證簽章|4.0|MEDIUM|
|CSRF Token 缺失|4.0|MEDIUM|
|缺少 HSTS / 安全標頭|2.6|LOW|
|憑證即將到期（< 30 天）|2.0|LOW|

### 9.3 報告產生器

```python
# reports/report\_generator.py
from jinja2 import Environment, FileSystemLoader
import weasyprint

REPORT\_TEMPLATE = "template.html.j2"

async def generate\_report(session\_id: int, db: Session) -> str:
    session  = db.query(TestSession).get(session\_id)
    findings = db.query(Finding).filter\_by(session\_id=session\_id)\\
                 .order\_by(Finding.cvss\_score.desc()).all()

    env      = Environment(loader=FileSystemLoader("reports/"))
    template = env.get\_template(REPORT\_TEMPLATE)
    html     = template.render(session=session, findings=findings,
                               cvss\_map=CVSS\_MAP, generated\_at=datetime.utcnow())

    output\_path = f"workspace/reports/report\_{session\_id}.pdf"
    weasyprint.HTML(string=html).write\_pdf(output\_path)
    return output\_path
```

\---

## 10\. Claude Code 開發優先順序

### Phase 1 — 核心骨架（最先實作）

1. `database.py` + 所有 `models/` — 資料庫骨架與 ORM
2. `routers/scanner.py` + `runners/nmap\_runner.py` — 掃描器（依賴最少，最穩定）
3. `main.py` — FastAPI 進入點，掛載 scanner router
4. `static/index.html` — 七模組側邊欄骨架（沿用原型視覺）
5. `static/js/ws-client.js` — WebSocket 基礎設施

### Phase 2 — 核心模組

6. `runners/tls\_runner.py` + `runners/password\_runner.py` — 憑證分析
7. `runners/firmware\_runner.py` — Binwalk + Firmwalker（四階段）
8. 跨模組資料流：`on\_scan\_complete()` 自動建議後續模組

### Phase 3 — 進階模組

9. `runners/boofuzz\_runner.py` + `runners/scapy\_runner.py` — 模糊測試
10. `runners/traffic\_runner.py` — tcpdump + PyShark（需 root）

### Phase 4 — 弱點驗證模組

11. `runners/routersploit\_runner.py` + `runners/openvas\_runner.py` — 設備弱點掃描
12. `runners/nikto\_runner.py` + `runners/zap\_runner.py` + `runners/gobuster\_runner.py` — 網頁弱點掃描

### Phase 5 — 收尾

13. `reports/report\_generator.py` — PDF 報告（Jinja2 + WeasyPrint）
14. `tests/test\_runners.py` — 整合測試

\---

## 啟動 Claude Code 的第一句話

將本文件放入專案根目錄後，對 Claude Code 說：

```
請依據 SPEC.md 開發規格文件，從 Phase 1 開始實作。
執行環境是 Kali Linux 2026.x。
前端設計沿用規格文件第 8 節的視覺規範（深色側邊欄、0.5px 邊框、mono 字體顯示技術值）。

請先建立以下檔案：
  1. database.py + models/ 下的四個資料模型
  2. routers/scanner.py + runners/nmap\_runner.py
  3. main.py（掛載 scanner router，提供 /api 與 /ws）
  4. static/index.html（七模組側邊欄骨架，沿用原型 CSS 變數）
  5. static/js/ws-client.js
```

\---

*IoT SecKit Dev Spec v1.0 · 2025-06-08 · 機密 — 僅供授權測試人員使用*

