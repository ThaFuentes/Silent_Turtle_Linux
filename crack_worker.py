#crack_worker.py

import subprocess

from PyQt5.QtCore import QThread, pyqtSignal
import re

KEY_FOUND_REGEX = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", re.IGNORECASE)

class AircrackThread(QThread):
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)  # (found: bool, key: str)

    def __init__(self, cap, ssid, bssid, wordlist):
        super().__init__()
        self.cap = cap
        self.ssid = ssid
        self.bssid = bssid
        self.wordlist = wordlist

    def run(self):
        self.status.emit("Running aircrack-ng…")
        proc = subprocess.Popen(
            [
                "aircrack-ng",
                "-b", self.bssid,
                "-e", self.ssid,
                "-w", self.wordlist,
                self.cap,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        found = False
        key = ""

        for line in proc.stdout:
            self.status.emit(line.rstrip())
            match = KEY_FOUND_REGEX.search(line)
            if match:
                found = True
                key = match.group(1)

        proc.wait()
        self.finished.emit(found, key)
