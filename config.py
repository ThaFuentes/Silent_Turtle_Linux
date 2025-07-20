# config.py
import os
import hashlib

# ─── PATH HELPERS ───────────────────────────────────────────────
def get_real_home():
    su = os.environ.get("SUDO_USER")
    if su:
        import pwd
        return pwd.getpwnam(su).pw_dir
    return os.path.expanduser("~")

# ─── BASE PATHS & CONSTANTS ─────────────────────────────────────
BASE_DIR = os.path.join(get_real_home(), "handshakes")  # <-- changed here!
DB_PATH  = os.path.join(BASE_DIR, "handshakes.db")
HS_DIR   = BASE_DIR  # Save handshake .cap files directly here
os.makedirs(HS_DIR, exist_ok=True)

# Wi-Fi channels commonly used
ALL_CHANNELS = [
    1,2,3,4,5,6,7,8,9,10,11,12,13,
    36,40,44,48,
    149,153,157,161,165
]

# ─── COLORS ─────────────────────────────────────────────────────
INFO_COLOR = "#8EC6C5"
SCAN_COLOR = "#00B4D8"
ERROR_COLOR = "#E63946"
PARTIAL_COLOR = "#FFD166"
HS_COLOR = "#4D96FF"
SSID_COLOR = "#FF6F61"

BSSID_COLORS = [
    "#3A6EA5", "#3083DC", "#00A9E2", "#61B2D9", "#1B263B", "#274690",
    "#5587A2", "#6FA3BF", "#8FD3FE", "#46B1C9", "#2A9D8F", "#00B4D8",
    "#A682FF", "#8EC6C5", "#73D2DE", "#4D96FF", "#FFB703", "#F77F00", "#E63946"
]

# ─── COLOR HELPERS ──────────────────────────────────────────────
def bcolor(bssid: str) -> str:
    """Get a consistent color hex code from a BSSID string."""
    idx = int(hashlib.sha256(bssid.encode()).hexdigest(), 16)
    return BSSID_COLORS[idx % len(BSSID_COLORS)]

def html(msg: str, c: str) -> str:
    """Wrap a message string in an HTML span with the given color."""
    return f'<span style="color:{c}">{msg}</span>'
