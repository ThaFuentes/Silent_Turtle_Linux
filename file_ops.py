#file_ops.py
import os
import re

# Regex for SSID and BSSID in capture filenames
_CAP_RE = re.compile(
    r'^(?P<ssid>.+?)_(?P<bssid>(?:[0-9a-f]{2}-){5}[0-9a-f]{2})_.*\.(?:cap|pcap)$',
    re.IGNORECASE
)

def parse_cap_filename(filename: str):
    """
    Extract (ssid, bssid) from a capture filename.
    Returns (None, None) if pattern doesn’t match.
    """
    m = _CAP_RE.match(filename)
    if not m:
        return None, None
    ssid  = m.group("ssid").replace("_", " ")
    bssid = m.group("bssid").lower()
    return ssid, bssid

def load_names(names_file: str) -> list[str]:
    """Load names from the given file. Return empty list if file missing or empty."""
    if not os.path.isfile(names_file):
        return []
    with open(names_file, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def load_adj(adj_file: str) -> list[str]:
    """Load adjectives from the given file. Return empty list if file missing or empty."""
    if not os.path.isfile(adj_file):
        return []
    with open(adj_file, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def load_noun(noun_file: str) -> list[str]:
    """Load nouns from the given file. Return empty list if file missing or empty."""
    if not os.path.isfile(noun_file):
        return []
    with open(noun_file, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def load_cracked_password(cap_path: str) -> str:
    """
    Loads cracked password from a .txt file next to the capture file.
    Returns empty string if not found or error.
    """
    txt_file = os.path.splitext(cap_path)[0] + ".txt"
    if not os.path.isfile(txt_file):
        return ""
    try:
        with open(txt_file, "r", encoding="utf-8") as f:
            return f.readline().strip()
    except Exception:
        return ""
