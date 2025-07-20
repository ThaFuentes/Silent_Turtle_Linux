#generators.py
import os
import random
import string
from PyQt5.QtCore import QThread, pyqtSignal

from file_ops import load_names  # Keep your file I/O centralized!

# ── Paths & Constants ─────────────────────────────────────────────────────────
BASE_DIR = os.path.expanduser("~/wifitoolkit/pass")  # fixed base dir to your toolkit folder
PASS_DIR = BASE_DIR
WORDLIST_PATH = os.path.join(PASS_DIR, "generated_wordlist.txt")

# Make sure the pass directory exists!
os.makedirs(PASS_DIR, exist_ok=True)


# ── Standard Password Generator Thread ───────────────────────────────────────
class GeneratorThread(QThread):
    warning  = pyqtSignal(str)
    finished = pyqtSignal(int)

    def __init__(self, length_range, include_name, mode, max_count,
                 sequential, prefix, suffix, insert_text):
        super().__init__()
        self.min_len, self.max_len = length_range
        self.include_name = include_name
        self.mode = mode
        self.max_count = max_count
        self.sequential = sequential
        self.prefix = prefix or ""
        self.suffix = suffix or ""
        self.insert_text = insert_text or ""

        if mode == "Numbers Only":
            self.chars = string.digits
        elif mode == "Letters Only":
            self.chars = string.ascii_letters
        elif mode == "Mix":
            self.chars = string.ascii_letters + string.digits
        else:
            self.chars = string.ascii_letters + string.digits + string.punctuation

    def run(self):
        total_possible = 0
        for length in range(self.min_len, self.max_len + 1):
            core = length - len(self.prefix) - len(self.suffix)
            if core < 0:
                continue
            total_possible += (10 ** core if self.sequential else len(self.chars) ** core)

        to_generate = min(self.max_count, total_possible)
        if to_generate < self.max_count:
            self.warning.emit(
                f"Only {total_possible} unique passwords exist; generating {to_generate}."
            )

        count = 0
        with open(WORDLIST_PATH, "w", encoding="utf-8") as f:
            if self.sequential:
                for length in range(self.min_len, self.max_len + 1):
                    core = length - len(self.prefix) - len(self.suffix)
                    if core < 0:
                        continue
                    for i in range(10 ** core):
                        pwd = self.prefix + str(i).zfill(core) + self.suffix
                        if self.insert_text:
                            p = random.randint(0, len(pwd))
                            pwd = pwd[:p] + self.insert_text + pwd[p:]
                        if self.include_name and len(pwd) < self.max_len:
                            name = random.choice(load_names())
                            pos = random.randint(0, len(pwd))
                            pwd = pwd[:pos] + name + pwd[pos:]
                        f.write(pwd + "\n")
                        count += 1
                        if count >= to_generate:
                            break
                    if count >= to_generate:
                        break
            else:
                seen = set()
                while count < to_generate:
                    length = random.randint(self.min_len, self.max_len)
                    core = length - len(self.prefix) - len(self.suffix)
                    if core < 0:
                        continue
                    base = "".join(random.choice(self.chars) for _ in range(core))
                    pwd = self.prefix + base + self.suffix
                    if self.insert_text:
                        p = random.randint(0, len(pwd))
                        pwd = pwd[:p] + self.insert_text + pwd[p:]
                    if self.include_name and len(pwd) < self.max_len:
                        name = random.choice(load_names())
                        pos = random.randint(0, len(pwd))
                        pwd = pwd[:pos] + name + pwd[pos:]
                    if pwd in seen:
                        continue
                    seen.add(pwd)
                    f.write(pwd + "\n")
                    count += 1
        self.finished.emit(count)


# ── Smart Name + Date Combo Generator Thread ────────────────────────────────
class SmartComboThread(QThread):
    finished = pyqtSignal(int)

    def __init__(self, symbols="!@#$%&*"):
        super().__init__()
        self.symbols = symbols

    def run(self):
        names  = load_names()
        months = [f"{m:02}" for m in range(1, 13)]
        days   = [f"{d:02}" for d in range(1, 32)]
        years  = [str(y) for y in range(1970, 2031)]

        count = 0
        with open(WORDLIST_PATH, "w", encoding="utf-8") as f:
            for name in names:
                variants = {name, name.lower(), name.upper(), name.capitalize()}
                for n in variants:
                    for m in months:
                        for d in days:
                            for sym in self.symbols:
                                f.write(f"{n}{m}{d}{sym}\n")
                                count += 1
                                f.write(f"{m}{d}{sym}{n}\n")
                                count += 1
                    for y in years:
                        for sym in self.symbols:
                            f.write(f"{n}{y}{sym}\n")
                            count += 1
                            f.write(f"{y}{sym}{n}\n")
                            count += 1
        self.finished.emit(count)
