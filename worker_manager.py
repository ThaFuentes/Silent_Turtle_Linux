#!/usr/bin/env python3
# worker_manager.py — manages AllPassWorker instances with per‑worker chunk tracking, pause/resume, and full parameter support

from typing import List, Optional, Dict
from PyQt5.QtCore import QObject, pyqtSignal
from all_pass_worker import AllPassWorker

class WorkerManager(QObject):
    # — SIGNALS —
    status        = pyqtSignal(int, str)   # (worker_id, message)
    progress      = pyqtSignal(int, int)   # (worker_id, chunk_index)
    cracked       = pyqtSignal(int, str)   # (worker_id, key)
    finished      = pyqtSignal(bool, str)  # (found_flag, key)
    save_progress = pyqtSignal()           # trigger UI to save resume state

    def __init__(self, generator_order: Optional[List[str]] = None):
        super().__init__()
        self.num_workers     = 3
        self.generator_order = generator_order[:] if generator_order else []

        # These will be set by the UI before calling start()
        self.names_path: Optional[str] = None
        self.adj_path:   Optional[str] = None
        self.noun_path:  Optional[str] = None

        # Captured-attack parameters
        self.cap_path: str                = ""
        self.ssid:     Optional[str]      = None
        self.bssid:    Optional[str]      = None
        self.area_codes: List[str]        = []

        # Internal state
        self.workers:       List[AllPassWorker] = []
        self.worker_chunks: Dict[int, int]      = {}
        self.running:       bool                = False

    def start(
        self,
        cap_path: str,
        ssid: str,
        bssid: str,
        area_codes: Optional[List[str]] = None,
        resume_chunks: Optional[Dict[int, int]] = None
    ):
        """Launch all workers, skipping each to its own start index based on resume_chunks."""
        self.cap_path   = cap_path
        self.ssid       = ssid
        self.bssid      = bssid
        self.area_codes = area_codes[:] if area_codes else []

        # Initialize per‑worker chunk tracking
        self.worker_chunks = {wid: -1 for wid in range(self.num_workers)}
        if resume_chunks:
            for wid, idx in resume_chunks.items():
                if wid in self.worker_chunks:
                    self.worker_chunks[wid] = idx

        # Clear any existing workers
        self.stop()
        self.workers.clear()
        self.running = True

        # Create & start each AllPassWorker
        for wid in range(self.num_workers):
            start_idx = self.worker_chunks[wid] + 1
            w = AllPassWorker(
                worker_id      = wid,
                start_idx      = start_idx,
                cap_path       = self.cap_path,
                bssid          = self.bssid,
                ssid           = self.ssid,
                area_codes     = self.area_codes,
                generator_order= self.generator_order,
                names_path     = self.names_path,
                adj_path       = self.adj_path,
                noun_path      = self.noun_path
            )
            # Connect signals with proper worker_id binding
            w.status.connect( lambda msg, wid=wid: self.status.emit(wid, msg) )
            w.progress.connect(lambda idx, wid=wid: self._on_worker_progress(wid, idx))
            w.cracked.connect(self.cracked.emit)      # passes (worker_id, key)
            w.finished.connect(self._on_worker_finished)  # passes (worker_id, success, key)
            self.workers.append(w)
            w.start()

    def pause(self):
        """Alias for stop; UI can call pause() to halt workers without clearing state."""
        self.stop()

    def resume(self):
        """Resume from last saved per‑worker chunk indexes."""
        self.start(
            self.cap_path,
            self.ssid or "",
            self.bssid or "",
            self.area_codes,
            resume_chunks=self.worker_chunks
        )

    def stop(self):
        """Stop all workers immediately."""
        self.running = False
        for w in self.workers:
            try:
                w.stop()
            except Exception:
                pass

    def _on_worker_progress(self, worker_id: int, chunk_index: int):
        """Update per‑worker chunk index, emit progress, and trigger save."""
        self.worker_chunks[worker_id] = chunk_index
        self.progress.emit(worker_id, chunk_index)
        self.save_progress.emit()

    def _on_worker_finished(self, worker_id: int, success: bool, key: str):
        """
        Handle a worker’s finished signal:
        - If success, stop all and emit overall finished(True, key).
        - If all workers ended with no success, emit finished(False, "").
        """
        if success:
            # Key found — stop other workers
            self.running = False
            for w in self.workers:
                if w.isRunning():
                    w.stop()
            self.finished.emit(True, key)
        else:
            # No key from this worker; if none left running, emit no-key
            if all(not w.isRunning() for w in self.workers):
                self.running = False
                self.finished.emit(False, "")

    def get_resume_state(self) -> Dict[int, int]:
        """Return current per‑worker chunk indexes for UI to save to disk."""
        return self.worker_chunks.copy()
