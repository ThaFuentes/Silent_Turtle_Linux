#db_utils.py

import os
import datetime
import sqlite3
import glob
from scapy.all import wrpcap

from config import HS_DIR, DB_PATH

# Enable debug logging (set to False to disable debug output)
DEBUG = True

# Internal flag to ensure DB is initialized only once per run
_has_initialized = False

def ensure_db(path=DB_PATH):
    """
    Create the SQLite DB and handshakes table if not exists (runs only once).
    """
    global _has_initialized
    if _has_initialized:
        return
    if DEBUG:
        print(f"[DEBUG] ensure_db: Ensuring database at {path}")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS handshakes(
            id INTEGER PRIMARY KEY,
            ssid TEXT,
            bssid TEXT,
            timestamp TEXT,
            raw_packet BLOB
        )
    """)
    conn.commit()
    conn.close()
    if DEBUG:
        print(f"[DEBUG] ensure_db: Database initialized")
    _has_initialized = True


def save_cap(ssid, bssid, pkts, dir_path=HS_DIR, keep_last=3):
    """
    Save packets to a .cap file named by ssid and bssid.
    Keeps only the last 'keep_last' captures for that bssid.
    Returns full path of saved .cap file.
    """
    os.makedirs(dir_path, exist_ok=True)

    safe_ssid = (ssid or "Hidden").replace(" ", "_").replace("/", "_")
    safe_bssid = (bssid or "unknown").replace(":", "-")
    ts = datetime.datetime.now().isoformat().replace(":", "-")
    filename = f"{safe_ssid}_{safe_bssid}_{ts}.cap"
    path = os.path.join(dir_path, filename)

    if DEBUG:
        print(f"[DEBUG] save_cap: Saving {len(pkts)} packets for '{ssid}' ({bssid}) → {path}")

    wrpcap(path, pkts)

    # Cleanup old captures: keep only last 'keep_last'
    files = sorted(
        glob.glob(os.path.join(dir_path, f"*_{safe_bssid}_*.cap")),
        reverse=True
    )
    for old_file in files[keep_last:]:
        try:
            os.remove(old_file)
            if DEBUG:
                print(f"[DEBUG] save_cap: Removed old capture file {old_file}")
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] save_cap: Failed to remove {old_file}: {e}")

    if DEBUG:
        print(f"[DEBUG] save_cap: Completed, returning {path}")

    return path
