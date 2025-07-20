# all_pass_worker.py
#!/usr/bin/env python3

from typing import List, Optional
from PyQt5.QtCore import QThread, pyqtSignal
import subprocess
import tempfile
import os

from file_ops import load_names, load_adj, load_noun
from password import PasswordGenerator

class AllPassWorker(QThread):
    # — SIGNALS —
    status  = pyqtSignal(str)               # Human‑readable status messages
    progress = pyqtSignal(int, int)         # (worker_id, chunk_index)
    cracked = pyqtSignal(int, str)          # (worker_id, found_key)
    finished = pyqtSignal(int, bool, str)   # (worker_id, success_flag, key)

    def __init__(
        self,
        worker_id: int,
        start_idx: int,
        cap_path: str,
        bssid: Optional[str] = None,
        ssid: Optional[str] = None,
        chunk_size: int = 500_000,
        area_codes: Optional[List[str]] = None,
        generator_order: Optional[List[str]] = None,
        names_path: Optional[str] = None,
        adj_path: Optional[str] = None,
        noun_path: Optional[str] = None,
        parent=None
    ):
        super().__init__(parent)

        # — IDENTIFIERS & CONFIG —
        self.worker_id       = worker_id
        self.num_workers     = 3                  # Total parallel workers; adjust if you ever change it
        self.cap_path        = cap_path
        self.bssid           = bssid
        self.ssid            = ssid
        self.chunk_size      = chunk_size
        self.start_idx       = max(0, start_idx)
        self.area_codes      = area_codes[:] if area_codes else []
        self.generator_order = generator_order[:] if generator_order else []
        self.names_path      = names_path
        self.adj_path        = adj_path
        self.noun_path       = noun_path

        self.running = True
        self.proc: Optional[subprocess.Popen] = None

    def stop(self):
        """Signal the worker to stop ASAP and terminate any running aircrack-ng process."""
        self.running = False
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass

    def run(self):
        """Main cracking loop. Skips chunks not assigned to this worker, writes temp wordlists,
           calls aircrack-ng, parses output, and emits signals."""
        def check_stop() -> bool:
            return not self.running

        # ---- 1) VERIFY WORDLIST FILES ----
        missing = []
        if not self.names_path or not os.path.isfile(self.names_path):
            missing.append("Names file")
        if not self.adj_path or not os.path.isfile(self.adj_path):
            missing.append("Adjectives file")
        if not self.noun_path or not os.path.isfile(self.noun_path):
            missing.append("Nouns file")
        if missing:
            self.status.emit(f"ERROR: Missing required files: {', '.join(missing)}")
            self.finished.emit(self.worker_id, False, "")
            return

        # ---- 2) LOAD WORDLISTS ----
        try:
            names      = load_names(self.names_path)
            adjectives = load_adj(self.adj_path)
            nouns      = load_noun(self.noun_path)
        except Exception as e:
            self.status.emit(f"ERROR loading wordlists: {e}")
            self.finished.emit(self.worker_id, False, "")
            return

        # ---- 3) SET UP PASSWORD GENERATOR ----
        gen = PasswordGenerator(
            chunk_size=self.chunk_size,
            check_stop=check_stop,
            area_codes=self.area_codes,
            generator_order=self.generator_order,
            names=names,
            adjectives=adjectives,
            nouns=nouns
        )
        chunk_iter = gen.chunked_passwords()

        # ---- 4) SKIP TO START_IDX ----
        skipped = 0
        while skipped < self.start_idx:
            try:
                next(chunk_iter)
                skipped += 1
                self.status.emit(f"[W{self.worker_id}] Skipping chunk {skipped}...")
            except StopIteration:
                self.status.emit(f"[W{self.worker_id}] No more chunks to skip.")
                self.finished.emit(self.worker_id, False, "")
                return

        chunk_index = self.start_idx
        self.status.emit(f"[W{self.worker_id}] Starting at chunk {chunk_index}…")

        # ---- 5) CRACKING LOOP ----
        while True:
            if not self.running:
                self.status.emit(f"[W{self.worker_id}] Stopping early.")
                self.finished.emit(self.worker_id, False, "")
                return

            try:
                chunk = next(chunk_iter)
            except StopIteration:
                self.status.emit(f"[W{self.worker_id}] All chunks tested, no key found.")
                self.finished.emit(self.worker_id, False, "")
                return

            # — PROCESS ONLY CHUNKS ASSIGNED TO THIS WORKER —
            if (chunk_index - self.start_idx) % self.num_workers != self.worker_id:
                self.status.emit(f"[W{self.worker_id}] Skipping chunk {chunk_index}")
                self.progress.emit(self.worker_id, chunk_index)
                chunk_index += 1
                continue

            self.status.emit(f"[W{self.worker_id}] Testing chunk {chunk_index} ({len(chunk)} pwds)…")

            # ---- 6) WRITE TEMP WORDLIST ----
            try:
                tmp = tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8")
                tmp.write("\n".join(chunk))
                tmp.flush()
                tmp_path = tmp.name
                tmp.close()
            except Exception as e:
                self.status.emit(f"[W{self.worker_id}] Error writing temp file: {e}")
                self.finished.emit(self.worker_id, False, "")
                return

            # ---- 7) RUN aircrack-ng ----
            cmd = ["aircrack-ng", "-w", tmp_path, self.cap_path]
            if self.bssid:
                cmd += ["-b", self.bssid]
            if self.ssid:
                cmd += ["-e", self.ssid]

            found_key = None
            try:
                self.proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=1
                )
                for line in self.proc.stdout:
                    if not self.running:
                        self.status.emit(f"[W{self.worker_id}] Aborting chunk…")
                        break
                    text = line.strip()
                    self.status.emit(text)
                    low = text.lower()
                    if "key found" in low or "key:" in low:
                        # parse key out of brackets or last token
                        if "[" in text and "]" in text:
                            candidate = text.split("[")[-1].split("]")[0]
                        else:
                            candidate = text.split()[-1]
                        found_key = candidate.strip()
                        self.cracked.emit(self.worker_id, found_key)
                        break

                if self.proc.poll() is None:
                    self.proc.terminate()
                self.proc.wait()
            except Exception as e:
                self.status.emit(f"[W{self.worker_id}] Error running aircrack-ng: {e}")
            finally:
                self.proc = None
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

            # ---- 8) HANDLE FOUND KEY ----
            if found_key:
                self.status.emit(f"[W{self.worker_id}] KEY FOUND: {found_key}")
                self.finished.emit(self.worker_id, True, found_key)
                return

            # ---- 9) REPORT PROGRESS & NEXT CHUNK ----
            self.progress.emit(self.worker_id, chunk_index)
            chunk_index += 1
