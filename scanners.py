#scanners.py
import os
from PyQt5.QtCore import QThread, pyqtSignal

class FullScanThread(QThread):
    found = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()

    def run(self):
        self.status.emit("Starting full scan at / …")
        for root, _, files in os.walk("/"):
            for fn in files:
                if fn.lower().endswith((".cap", ".pcap")):
                    full_path = os.path.join(root, fn)
                    self.found.emit(full_path)
        self.status.emit("Full scan complete.")
        self.finished.emit()


class QuickScanThread(QThread):
    found = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, paths):
        super().__init__()
        self.paths = paths

    def run(self):
        self.status.emit("Starting quick scan…")
        for base in self.paths:
            for root, _, files in os.walk(base):
                for fn in files:
                    if fn.lower().endswith((".cap", ".pcap")):
                        full_path = os.path.join(root, fn)
                        self.found.emit(full_path)
        self.status.emit("Quick scan complete.")
        self.finished.emit()
