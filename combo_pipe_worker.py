# combo_pipe_worker.py
#!/usr/bin/env python3
import os
import tempfile
import subprocess
import itertools
import re
import calendar
from datetime import datetime
from PyQt5.QtCore import QThread, pyqtSignal

def product_chunks(sequences, chunk_size):
    """Yield lists of combos (tuples) chunk_size at a time."""
    it = itertools.product(*sequences)
    buffer = []
    for combo in it:
        buffer.append(combo)
        if len(buffer) >= chunk_size:
            yield buffer
            buffer = []
    if buffer:
        yield buffer

class ComboPipeWorker(QThread):
    """
    Generates password combos based on a dynamic pattern and config,
    streams them in batches to aircrack-ng, and emits status/results.
    """
    status   = pyqtSignal(str)
    finished = pyqtSignal(bool, str)   # (found, key)

    def __init__(self, cap_file, ssid, bssid, pattern, cfg,
                 batch_size: int = 500_000, parent=None):
        super().__init__(parent)
        self.cap_file   = cap_file
        self.ssid       = ssid
        self.bssid      = bssid
        self.pattern    = pattern
        self.cfg        = cfg
        self.batch_size = batch_size
        self._stop      = False
        self._proc      = None

    def stop(self):
        """Signal to stop and kill any running aircrack process."""
        self._stop = True
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.kill()
            except:
                pass

    def _cleanup_temp(self):
        """Remove any leftover .tmp files in the system temp dir."""
        tmp = tempfile.gettempdir()
        for fn in os.listdir(tmp):
            if fn.startswith("tmp") and fn.endswith(".tmp"):
                try:
                    os.remove(os.path.join(tmp, fn))
                except:
                    pass

    def run(self):
        try:
            self.status.emit(f"Started combo-pipe at {datetime.now():%Y-%m-%d %H:%M:%S}")
            self._cleanup_temp()

            # ----- PURE-DIGIT BRANCH -----
            if self.pattern == ["digit"]:
                # grab min/max lengths from cfg
                conf = self.cfg.get("digit", {})
                lo = int(conf.get("min", 8))
                hi = int(conf.get("max", 8))
                digits = "0123456789"
                total, batch_idx, found, key = 0, 0, False, ""

                for length in range(lo, hi + 1):
                    if self._stop:
                        break
                    self.status.emit(f"→ Trying digit length {length}")
                    sequences = [digits] * length

                    for batch in product_chunks(sequences, self.batch_size):
                        if self._stop:
                            break
                        batch_idx += 1
                        total += len(batch)

                        # write batch to temp wordlist
                        tf = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".tmp")
                        path = tf.name
                        for parts in batch:
                            tf.write("".join(parts) + "\n")
                        tf.close()

                        self.status.emit(f"Trying batch {batch_idx}: {len(batch)} combos (total {total})")
                        cmd = [
                            "nice","-n","19","ionice","-c3",
                            "aircrack-ng","-b", self.bssid, "-e", self.ssid,
                            "-w", path, self.cap_file
                        ]
                        self.status.emit(f"Running aircrack-ng on batch {batch_idx}…")
                        self._proc = subprocess.Popen(
                            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1
                        )

                        for line in self._proc.stdout or []:
                            if self._stop:
                                break
                            txt = line.rstrip()
                            self.status.emit(txt)
                            if "KEY FOUND" in txt.upper():
                                m = re.search(r"\[ *(.+?) *\]", txt)
                                if m:
                                    key, found = m.group(1), True
                                break

                        if self._proc:
                            self._proc.wait()
                        try:
                            os.remove(path)
                        except:
                            pass
                        if found or self._stop:
                            break

                    if found or self._stop:
                        break

                self._cleanup_temp()
                if found:
                    self.status.emit(f"KEY FOUND: {key}")
                    self.finished.emit(True, key)
                elif self._stop:
                    self.status.emit("Combo-pipe attack stopped by user.")
                    self.finished.emit(False, "")
                else:
                    self.status.emit(f"Finished—no key after {total} combos.")
                    self.finished.emit(False, "")
                return  # done with digit branch

            # ----- TOKEN-BASED BRANCH -----
            # Build sequences per pattern token
            sequences = []
            for token in self.pattern:
                conf = self.cfg.get(token, {})
                if token in ("name", "adj", "noun"):
                    path = conf.get("file", "")
                    with open(path, encoding="utf-8", errors="ignore") as f:
                        seq = [l.strip() for l in f if l.strip()]
                elif token == "year":
                    lo, hi = conf.get("min", 1970), conf.get("max", datetime.now().year)
                    seq = [str(y) for y in range(lo, hi + 1)]
                elif token == "month_num":
                    seq = [f"{m:02}" for m in range(1, 13)]
                elif token == "month_abbr":
                    seq = [calendar.month_abbr[m] for m in range(1, 13)]
                elif token == "month_name":
                    seq = [calendar.month_name[m] for m in range(1, 13)]
                elif token == "day":
                    seq = [f"{d:02}" for d in range(1, 32)]
                elif token == "symbol":
                    seq = list(conf.get("set", ""))
                elif token == "static":
                    seq = [conf.get("text", "")]
                else:
                    raise ValueError(f"Unsupported combo token: {token}")

                self.status.emit(f"Token '{token}': {len(seq)} entries")
                sequences.append(seq)

            # Now chunk through the Cartesian product
            found, key, total, batch_idx = False, "", 0, 0
            for batch in product_chunks(sequences, self.batch_size):
                if self._stop:
                    break
                batch_idx += 1
                total += len(batch)

                tf = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".tmp")
                path = tf.name
                for parts in batch:
                    tf.write("".join(parts) + "\n")
                tf.close()

                self.status.emit(f"Trying batch {batch_idx}: {len(batch)} combos (total {total})")
                cmd = [
                    "nice","-n","19","ionice","-c3",
                    "aircrack-ng","-b", self.bssid, "-e", self.ssid,
                    "-w", path, self.cap_file
                ]
                self.status.emit(f"Running aircrack-ng on batch {batch_idx}…")
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )

                for line in self._proc.stdout or []:
                    if self._stop:
                        break
                    txt = line.rstrip()
                    self.status.emit(txt)
                    if "KEY FOUND" in txt.upper():
                        m = re.search(r"\[ *(.+?) *\]", txt)
                        if m:
                            key, found = m.group(1), True
                        break

                if self._proc:
                    self._proc.wait()
                try:
                    os.remove(path)
                except:
                    pass
                if found or self._stop:
                    break

            self._cleanup_temp()
            if found:
                self.status.emit(f"KEY FOUND: {key}")
                self.finished.emit(True, key)
            elif self._stop:
                self.status.emit("Combo-pipe attack stopped by user.")
                self.finished.emit(False, "")
            else:
                self.status.emit(f"Finished—no key after {total} combos.")
                self.finished.emit(False, "")

        except Exception as e:
            self.status.emit(f"ERROR: {e}")
