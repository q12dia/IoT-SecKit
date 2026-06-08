from pathlib import Path

BASE_DIR      = Path(__file__).parent
WORKSPACE_DIR = BASE_DIR / "workspace"
FIRMWARE_DIR  = WORKSPACE_DIR / "firmware"
CAPTURES_DIR  = WORKSPACE_DIR / "captures"
REPORTS_DIR   = WORKSPACE_DIR / "reports"

# Tool paths (Kali defaults)
NMAP_BIN        = "/usr/bin/nmap"
TESTSSL_BIN     = "/opt/testssl/testssl.sh"
BINWALK_BIN     = "/usr/bin/binwalk"
FIRMWALKER_BIN  = "/opt/firmwalker/firmwalker.sh"
CHECKSEC_BIN    = "/usr/bin/checksec"
TCPDUMP_BIN     = "/usr/bin/tcpdump"
NIKTO_BIN       = "/usr/bin/nikto"
GOBUSTER_BIN    = "/usr/bin/gobuster"
HYDRA_BIN       = "/usr/bin/hydra"
SQLMAP_BIN      = "/usr/bin/sqlmap"

for d in (FIRMWARE_DIR, CAPTURES_DIR, REPORTS_DIR):
    d.mkdir(parents=True, exist_ok=True)
