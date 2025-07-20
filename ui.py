#!/usr/bin/env python3
# ui.py — CrackerWidget with drag-drop GUI popup for pattern order on ALL-PASS start/resume, full rebuild

import os
import re
import json
from pathlib import Path
from typing import List, Optional, Tuple

from PyQt5.QtWidgets import (
    QWidget, QApplication, QVBoxLayout, QHBoxLayout, QTableWidget,
    QTableWidgetItem, QPushButton, QLabel, QLineEdit, QTextEdit,
    QCheckBox, QMessageBox, QDoubleSpinBox, QHeaderView, QFileDialog,
    QComboBox, QProgressBar, QInputDialog, QGroupBox, QToolButton,
    QDialog, QListWidget, QListWidgetItem, QDialogButtonBox
)
from PyQt5.QtCore import Qt, QSettings, QThread, QTimer, QEvent
from PyQt5.QtGui import QColor, QPalette

from scapy.all import rdpcap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, EAPOL

import file_ops
from generators import GeneratorThread, SmartComboThread
from scanners import FullScanThread, QuickScanThread
from crack_worker import AircrackThread
from combo_builder import ComboBuilderWindow
from combo_pipe_worker import ComboPipeWorker

from all_pass_worker import AllPassWorker
from worker_manager import WorkerManager
from password import PasswordGenerator

RESUME_FILE = Path("allpass_resume_states.json")


def load_all_states() -> dict:
    if not RESUME_FILE.exists():
        return {}
    try:
        data = json.loads(RESUME_FILE.read_text("utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def save_state_for_cap(cap_path: str, ssid: str, bssid: str,
                       last_chunk_idxs: List[int], area_codes: Optional[List[str]],
                       pattern_order: Optional[List[str]] = None) -> None:
    state = load_all_states()
    state[cap_path] = {
        "ssid": ssid or "",
        "bssid": bssid or "",
        "last_chunk_idxs": last_chunk_idxs,
        "area_codes": area_codes or [],
        "pattern_order": pattern_order or []
    }
    RESUME_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def delete_state_for_cap(cap_path: str) -> None:
    state = load_all_states()
    if cap_path in state:
        del state[cap_path]
        RESUME_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


# -- New GUI dialog for pattern order selection with drag and drop --
class PatternOrderDialog(QDialog):
    def __init__(self, parent=None, patterns=None):
        super().__init__(parent)
        self.setWindowTitle("Select Password Pattern Order")
        self.setMinimumWidth(400)

        # Default patterns fallback
        self.patterns = patterns or [
            "gen_name_month_day_year",
            "gen_phone_numbers",
            "gen_name_month_day",
            "gen_name_month_day_sym"
        ]

        self.layout = QVBoxLayout(self)

        self.info_label = QLabel("Drag to reorder patterns. Select default or reorder as you want.")
        self.layout.addWidget(self.info_label)

        self.list_widget = QListWidget()
        self.list_widget.setDragDropMode(QListWidget.InternalMove)
        self.list_widget.setDefaultDropAction(Qt.MoveAction)
        for pat in self.patterns:
            item = QListWidgetItem(pat)
            self.list_widget.addItem(item)
        self.layout.addWidget(self.list_widget)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)

    def get_order(self) -> List[str]:
        return [self.list_widget.item(i).text() for i in range(self.list_widget.count())]


# --- Main CrackerWidget class ---
class CrackerWidget(QWidget):
    LOG_MAX_LINES = 500

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wi-Fi Handshake Cracker")
        self.resize(1000, 980)
        self.showFullScreen()

        self.settings = QSettings("Fuentes", "WiFiToolkit")

        self.handshakes: dict[str, Tuple[str, str]] = {}

        self.current_wordlist_path = os.path.join(os.getcwd(), "generated_wordlist.txt")
        self.current_names_path = self.settings.value(
            "names_path", os.path.join(os.getcwd(), "names.txt")
        )
        self.current_adj_path = self.settings.value(
            "adj_path", os.path.join(os.getcwd(), "adjectives.txt")
        )
        self.current_noun_path = self.settings.value(
            "noun_path", os.path.join(os.getcwd(), "nouns.txt")
        )

        self.combo_pattern: Optional[List[str]] = None
        self.combo_cfg: Optional[dict] = None

        self._pipe: Optional[QThread] = None
        self._crack: Optional[QThread] = None
        self.manager: Optional[WorkerManager] = None

        self.current_cap_path: Optional[str] = None
        self.current_ssid: Optional[str] = None
        self.current_bssid: Optional[str] = None
        self._allpass_running = False
        self._allpass_paused = False

        self.current_running_chunks: List[int] = [-1, -1, -1]

        self.resume_states = load_all_states()

        self.current_cracking: Optional[str] = None

        self._log_lines: List[str] = []

        self._load_handshake_index()

        self._build_ui()

        self.refresh()

        self._event_timer = QTimer(self)
        self._event_timer.timeout.connect(self._pump_events)
        self._event_timer.start(500)

    def _pump_events(self):
        QApplication.processEvents()

    def event(self, event):
        if event.type() == QEvent.WindowActivate:
            self._append_log("Window activated — refreshing output…", "info")
            self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())
        return super().event(event)

    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(10)

        # Handshake table
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["SSID", "BSSID", "File", "Password", "Resume"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        main_layout.addWidget(self.table, stretch=3)

        # Middle controls container
        self.middle_controls_widget = QWidget()
        mc_layout = QVBoxLayout(self.middle_controls_widget)
        mc_layout.setSpacing(15)

        # Scan & Cleanup
        scan_box = QGroupBox("🔍 Scan & Cleanup")
        scan_box.setStyleSheet("QGroupBox { color: #0f0; font-weight: bold; }")
        scan_layout = QHBoxLayout()
        for txt, fn in (
                ("Full Scan", self.full_scan),
                ("Quick Scan", self.quick_scan),
                ("Delete Selected", self._delete_selected),
                ("Delete All", self._delete_all),
        ):
            btn = QPushButton(txt)
            btn.clicked.connect(fn)
            scan_layout.addWidget(btn)
        scan_box.setLayout(scan_layout)
        mc_layout.addWidget(scan_box)

        # Password Generation
        gen_box = QGroupBox("🔧 Password Generation")
        gen_box.setStyleSheet("QGroupBox { color: #ffb100; font-weight: bold; }")
        gen_layout = QHBoxLayout()
        self.lr = QLineEdit("10-10")
        self.name_chk = QCheckBox("Include common name")
        self.mode_cb = QComboBox()
        self.mode_cb.addItems(["Numbers Only", "Letters Only", "Mix", "Random"])
        self.seq_chk = QCheckBox("Sequential")
        self.pref, self.ins, self.suf = QLineEdit(), QLineEdit(), QLineEdit()
        self.size = QDoubleSpinBox()
        self.size.setRange(1, 5024)
        self.size.setValue(50)
        self.size.setSuffix(" MB")
        for widget in (
                QLabel("Len(min-max):"), self.lr,
                self.name_chk, QLabel("Mode:"), self.mode_cb,
                self.seq_chk, QLabel("Prefix:"), self.pref,
                QLabel("Insert:"), self.ins, QLabel("Suffix:"), self.suf,
                QLabel("Size:"), self.size,
        ):
            gen_layout.addWidget(widget)
        gen_box.setLayout(gen_layout)
        mc_layout.addWidget(gen_box)

        # Wordlist Files
        file_box = QGroupBox("📁 Wordlist Files")
        file_box.setStyleSheet("QGroupBox { color: #00aaff; font-weight: bold; }")
        file_layout = QHBoxLayout()
        for txt, fn in (
                ("Names", self._choose_names),
                ("Adjectives", self._choose_adj),
                ("Nouns", self._choose_noun),
        ):
            btn = QPushButton(f"Choose {txt}")
            btn.clicked.connect(fn)
            file_layout.addWidget(btn)
        file_box.setLayout(file_layout)
        mc_layout.addWidget(file_box)

        # Combo Crack + ALL-PASS Controls
        combo_allpass_layout = QHBoxLayout()
        combo_allpass_layout.setSpacing(20)

        combo_box = QGroupBox("🔗 Combo Crack")
        combo_box.setStyleSheet("QGroupBox { color: #ff69b4; font-weight: bold; }")
        combo_layout = QHBoxLayout()
        self.combo_builder_btn = QPushButton("Combo Builder…")
        self.combo_builder_btn.clicked.connect(self._open_combo_builder)
        self.combo_crack_btn = QPushButton("Start Combo Crack")
        self.combo_crack_btn.setEnabled(False)
        self.combo_crack_btn.clicked.connect(self._on_combo_crack)
        combo_layout.addWidget(self.combo_builder_btn)
        combo_layout.addWidget(self.combo_crack_btn)
        combo_box.setLayout(combo_layout)
        combo_allpass_layout.addWidget(combo_box, stretch=1)

        allpass_box = QGroupBox("🛡️ ALL-PASS Controls")
        allpass_box.setStyleSheet("QGroupBox { color: #00ff00; font-weight: bold; }")
        allpass_layout = QHBoxLayout()
        self.all_pass_btn = QPushButton("Start ALL-PASS")
        self.all_pass_btn.clicked.connect(self._on_all_pass_start)
        self.pause_all_pass_btn = QPushButton("Pause ALL-PASS")
        self.pause_all_pass_btn.setEnabled(False)
        self.pause_all_pass_btn.clicked.connect(self._on_all_pass_pause_resume)
        allpass_layout.addWidget(self.all_pass_btn)
        allpass_layout.addWidget(self.pause_all_pass_btn)
        allpass_box.setLayout(allpass_layout)
        combo_allpass_layout.addWidget(allpass_box, stretch=1)

        mc_layout.addLayout(combo_allpass_layout)

        main_layout.addWidget(self.middle_controls_widget, stretch=1)

        # Bottom Actions
        action_box = QGroupBox("⚡ Actions")
        action_box.setStyleSheet("QGroupBox { color: #ffaa00; font-weight: bold; }")
        action_layout = QHBoxLayout()
        self.standard_gen_btn = QPushButton("Generate List")
        self.smart_gen_btn = QPushButton("Generate Smart List")
        self.file_open_btn = QPushButton("Open List")
        self.run_selected_btn = QPushButton("Run Pass List")
        self.run_generated_btn = QPushButton("Run Gen List")
        self.all_stop_btn = QPushButton("ALL STOP")
        for btn in (
                self.standard_gen_btn, self.smart_gen_btn, self.file_open_btn,
                self.run_selected_btn, self.run_generated_btn, self.all_stop_btn,
        ):
            action_layout.addWidget(btn)
        action_box.setLayout(action_layout)

        self.toggle_button = QToolButton()
        self.toggle_button.setText("Hide Options ▲")
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(True)
        self.toggle_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle_button.toggled.connect(lambda checked: (
            self.middle_controls_widget.setVisible(checked),
            self.toggle_button.setText("Hide Options ▲" if checked else "Show Options ▼")
        ))

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.toggle_button)
        bottom_layout.addWidget(action_box)
        main_layout.addLayout(bottom_layout)

        self.chunk_bar = QProgressBar()
        self.chunk_bar.setVisible(False)
        main_layout.addWidget(self.chunk_bar)
        self.status = QLabel("")
        main_layout.addWidget(self.status)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFixedHeight(250)
        main_layout.addWidget(self.log)

        # Connect buttons
        self.standard_gen_btn.clicked.connect(self._on_generate_standard)
        self.smart_gen_btn.clicked.connect(self._on_generate_smart)
        self.file_open_btn.clicked.connect(self._on_open)
        self.run_selected_btn.clicked.connect(self._on_run_selected)
        self.run_generated_btn.clicked.connect(self._on_run_generated)
        self.all_stop_btn.clicked.connect(self._on_all_stop)

    def _append_log(self, msg: str, style: str = "normal"):
        if msg.startswith("Trying:"):
            color = "#FFA500"
        else:
            colors = {"error": "#F44", "success": "#0F0", "info": "#88F", "normal": "#EEE"}
            color = colors.get(style, "#EEE")
        formatted = f"<span style='color:{color};'>{msg}</span>"

        if len(self._log_lines) >= self.LOG_MAX_LINES:
            self._log_lines.clear()
            self.log.clear()

        self._log_lines.append(formatted)
        self.log.append(formatted)
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def _append_aircrack_log(self, line: str):
        text = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', line).strip()
        low = text.lower()

        m_start = re.search(r"(starting chunk|testing chunk #?)(\d+)", low)
        if m_start and self.current_cap_path:
            idx = int(m_start.group(2))
            if idx not in self.current_running_chunks:
                self.current_running_chunks.append(idx)
            idxs = sorted(self.current_running_chunks)
            if len(idxs) > 3:
                idxs = idxs[-3:]
            while len(idxs) < 3:
                idxs.insert(0, -1)
            self.current_running_chunks = idxs
            save_state_for_cap(
                self.current_cap_path,
                self.current_ssid or "",
                self.current_bssid or "",
                self.current_running_chunks,
                getattr(self.manager, "area_codes", [])
            )

        if "current passphrase:" in low:
            col = "#FF69B4"
        elif text.startswith("Trying:"):
            col = "#FFA500"
        elif "key found" in low or "key:" in low:
            col = "#00FFFF"
        elif "key not found" in low:
            col = "#F44"
        elif any(k in low for k in ("eapol", "hmac")):
            col = "#88F"
        elif any(k in low for k in ("error", "fail")):
            col = "#F44"
        else:
            col = "#EEE"
        formatted = f"<span style='color:{col};'>{text}</span>"

        if len(self._log_lines) >= self.LOG_MAX_LINES:
            self._log_lines.clear()
            self.log.clear()

        self._log_lines.append(formatted)
        self.log.append(formatted)
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def _save_current_progress(self):
        if self.manager and self.current_cap_path:
            idxs = self.current_running_chunks.copy() if any(
                i >= 0 for i in self.current_running_chunks) else self.manager.last_chunk_idxs
            save_state_for_cap(
                self.current_cap_path,
                self.current_ssid or "",
                self.current_bssid or "",
                idxs,
                getattr(self.manager, "area_codes", []),
                getattr(self.manager, "generator_order", [])  # Pass the pattern order here!
            )

    def _choose_names(self):
        self._pick_file("Names", "names")

    def _choose_adj(self):
        self._pick_file("Adjectives", "adj")

    def _choose_noun(self):
        self._pick_file("Nouns", "noun")

    def _pick_file(self, label: str, key: str):
        dirs = {
            "names": os.path.dirname(self.current_names_path),
            "adj": os.path.dirname(self.current_adj_path),
            "noun": os.path.dirname(self.current_noun_path),
        }
        start_dir = dirs.get(key, os.getcwd())
        p, _ = QFileDialog.getOpenFileName(self, f"Select {label}", start_dir, "Text Files (*.txt)")
        if p:
            if key == "names":
                self.current_names_path = p
                self.settings.setValue("names_path", p)
            elif key == "adj":
                self.current_adj_path = p
                self.settings.setValue("adj_path", p)
            elif key == "noun":
                self.current_noun_path = p
                self.settings.setValue("noun_path", p)
            self._append_log(f"{label} set → {p}", "success")

    def add_cap(self, p: str):
        s, b = file_ops.parse_cap_filename(os.path.basename(p))
        if s and p not in self.handshakes:
            self.handshakes[p] = (s, b)

    def refresh(self):
        self.resume_states = load_all_states()
        self.table.setRowCount(0)
        for i, (p, (s, b)) in enumerate(sorted(self.handshakes.items())):
            self.table.insertRow(i)

            ssid_item = QTableWidgetItem(s)
            ssid_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            self.table.setItem(i, 0, ssid_item)

            bssid_item = QTableWidgetItem(b)
            bssid_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            self.table.setItem(i, 1, bssid_item)

            file_item = QTableWidgetItem(p)
            file_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            self.table.setItem(i, 2, file_item)

            cap_path = Path(p)
            directory = cap_path.parent
            stem = cap_path.stem
            prefix = "_".join(stem.split("_")[:-1]) if "_" in stem else stem

            cracked_pwd = ""
            txt_candidates = list(directory.glob(f"{prefix}_*.txt"))
            if txt_candidates:
                chosen_txt = sorted(txt_candidates)[-1]
                try:
                    cracked_pwd = chosen_txt.read_text(encoding="utf-8").strip()
                except Exception:
                    cracked_pwd = ""
            pwd_item = QTableWidgetItem(cracked_pwd)
            pwd_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            self.table.setItem(i, 3, pwd_item)

            if p in self.resume_states:
                resume_btn = QPushButton("Resume")
                resume_btn.clicked.connect(lambda _, cap=p: self._resume_specific_cap(cap))
                self.table.setCellWidget(i, 4, resume_btn)
            else:
                empty_item = QTableWidgetItem("")
                empty_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                self.table.setItem(i, 4, empty_item)

            if self.current_cracking == p:
                color = "#005500"
            elif cracked_pwd:
                color = "#003300"
            elif p in self.resume_states:
                color = "#000055"
            else:
                color = None

            for col in range(5):
                cell_widget = self.table.cellWidget(i, col)
                if isinstance(cell_widget, QPushButton):
                    if color:
                        cell_widget.setStyleSheet(f"background-color: {color}")
                    else:
                        cell_widget.setStyleSheet("")
                else:
                    item = self.table.item(i, col)
                    if item is not None and color:
                        item.setBackground(QColor(color))
                    elif item is not None:
                        item.setBackground(QColor(Qt.transparent))

    def full_scan(self):
        self.handshakes.clear()
        root_dirs = ["/"]
        skip_dirs = {"/proc", "/sys", "/dev", "/run", "/tmp", "/var/lib/docker", "/var/run"}

        self._append_log("Full scan started", "info")

        for root_dir in root_dirs:
            for root, dirs, files in os.walk(root_dir, topdown=True):
                dirs[:] = [d for d in dirs if os.path.join(root, d) not in skip_dirs]

                for f in files:
                    if not f.lower().endswith(".cap"):
                        continue
                    full_path = os.path.join(root, f)
                    try:
                        s, b = self._extract_ssid_bssid_from_filename(full_path)
                        if s is None or b is None:
                            continue
                        if full_path not in self.handshakes:
                            self.handshakes[full_path] = (s, b)
                    except Exception:
                        continue

        self.refresh()
        count = len(self.handshakes)
        self._append_log(f"Full scan finished — found {count} handshake{'s' if count != 1 else ''}", "success")

    def _extract_ssid_bssid_from_filename(self, filename: str) -> Tuple[Optional[str], Optional[str]]:
        from collections import Counter
        from pathlib import Path
        import re

        ssid = None
        bssid = None

        try:
            packets = rdpcap(filename)
        except Exception as e:
            self._append_log(f"Failed to read pcap file: {e}", "error")
            return None, None

        ssid_counts = Counter()
        bssid_counts = Counter()

        for pkt in packets:
            if pkt.haslayer(Dot11Elt):
                elt = pkt.getlayer(Dot11Elt)
                if elt.ID == 0 and elt.info:
                    name = elt.info.decode(errors="ignore").strip()
                    if name:
                        ssid_counts[name] += 1
                        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                            addr = pkt.addr3 or pkt.addr2
                            if addr:
                                bssid_counts[addr] += 1

        if ssid_counts:
            ssid = ssid_counts.most_common(1)[0][0]
        if bssid_counts:
            bssid = bssid_counts.most_common(1)[0][0]

        if not bssid:
            for pkt in packets:
                if pkt.haslayer(EAPOL):
                    bssid = pkt.addr3 or pkt.addr2 or pkt.addr1
                    if bssid:
                        break

        if bssid:
            bssid = bssid.lower().replace("-", ":")

        if not ssid or ssid.lower() == "hidden":
            stem = Path(filename).stem
            parts = stem.split("_")
            if len(parts) >= 3:
                ssid_candidate = " ".join(parts[:-2]).strip(" _-")
                raw_bssid = parts[-2]
                candidate_bssid = raw_bssid.replace("-", ":").lower()
                if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", candidate_bssid):
                    bssid = candidate_bssid
                ssid = ssid_candidate if ssid_candidate else ssid

        if not ssid or not bssid:
            self._append_log("Could not parse SSID/BSSID", "error")
            return None, None

        self._append_log(f"Parsed ESSID={ssid}, BSSID={bssid}", "info")
        return ssid, bssid

    def _load_handshake_index(self):
        index_path = os.path.join(os.getcwd(), "handshakes", "handshakes_index.json")
        if os.path.isfile(index_path):
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    idx = json.load(f)
                idx = {p: v for p, v in idx.items() if os.path.isfile(p)}
                self.handshakes = {p: tuple(v) for p, v in idx.items()}
            except Exception as e:
                self._append_log(f"Failed to load handshake index: {e}", "error")
                self.handshakes = {}
        else:
            self.handshakes = {}

    def quick_scan(self):
        self.handshakes.clear()
        scan_dir = os.path.join(os.getcwd(), "handshakes")
        os.makedirs(scan_dir, exist_ok=True)
        for f in sorted(os.listdir(scan_dir)):
            if f.endswith(".cap"):
                self.add_cap(os.path.join(scan_dir, f))
        self.refresh()
        self._append_log("Quick scan done", "success")

    def _resume_specific_cap(self, cap_path: str):
        print("DEBUG: Loading resume state from file...")
        self.resume_states = load_all_states()
        state = self.resume_states.get(cap_path)
        if not state:
            print("DEBUG: No resume state found for", cap_path)
            return

        ssid = state.get("ssid", "")
        bssid = state.get("bssid", "")
        raw_idxs = state.get("last_chunk_idxs", [-1, -1, -1])
        if not isinstance(raw_idxs, list):
            raw_idxs = [-1, -1, -1]
        if len(raw_idxs) < 3:
            raw_idxs = (raw_idxs + [-1, -1, -1])[:3]
        last_idxs = raw_idxs
        area_codes = state.get("area_codes", [])

        pattern_order = state.get("pattern_order")
        if not pattern_order or not isinstance(pattern_order, list) or len(pattern_order) == 0:
            pattern_order = [
                "gen_phone_numbers",
                "gen_name_month_day_year",
                "gen_name_month_day",
                "gen_name_month_day_sym",
                "gen_single_name",
                "gen_single_adj",
                "gen_single_noun",
                "gen_two_word_permutations",
                "gen_three_word_permutations",
                "gen_word_digits_sym",
                "gen_two_words_digits_sym",
                "gen_three_words_digits_sym",
                "gen_word_year_sym",
                "gen_two_words_year_sym",
                "gen_three_words_year_sym",
                "gen_name_static_digits_sym",
                "gen_random_insert",
                "gen_word_phone_sym",
                "gen_phone_year_sym",
                "gen_letter_phone_letter_sym",
            ]

        print(
            f"DEBUG: Resuming All-Pass on {cap_path} with last_idxs={last_idxs}, area_codes={area_codes}, pattern_order length={len(pattern_order)}")

        if self.manager and (self._allpass_running or self._allpass_paused):
            self._save_current_progress()
            self.manager.stop()
            self._allpass_running = False
            self._allpass_paused = False
            self.current_cracking = None

        self.current_running_chunks = last_idxs.copy()

        self.manager = WorkerManager(generator_order=pattern_order)
        self.manager.last_chunk_idxs = last_idxs.copy()
        self.manager.area_codes = area_codes[:]
        self.manager.cap_path = cap_path
        self.manager.ssid = ssid
        self.manager.bssid = bssid

        # Pass saved persistent wordlist file paths to manager if needed
        self.manager.names_path = self.current_names_path
        self.manager.adj_path = self.current_adj_path
        self.manager.noun_path = self.current_noun_path

        self.manager.status.connect(lambda wid, msg: self._append_aircrack_log(f"[W{wid}] {msg}"))
        self.manager.progress.connect(lambda wid, idx: self._on_chunk_progress(cap_path, ssid, bssid, idx, area_codes))
        self.manager.cracked.connect(lambda wid, key: self._on_key_found(wid, key))
        self.manager.finished.connect(self._on_all_pass_finished)
        self.manager.save_progress.connect(self._save_current_progress)

        self.current_cap_path = cap_path
        self.current_ssid = ssid
        self.current_bssid = bssid

        self._append_log(f"Resuming All-Pass on {cap_path}…", "info")
        self.all_pass_btn.setEnabled(False)
        self.pause_all_pass_btn.setEnabled(True)
        self.pause_all_pass_btn.setText("Pause ALL-PASS")
        self.chunk_bar.setVisible(True)
        self.chunk_bar.setRange(0, 0)

        self.manager.resume()

        self._allpass_running = True
        self._allpass_paused = False
        self.current_cracking = cap_path
        self.refresh()

    def _ask_pattern_order_dialog(self) -> Optional[List[str]]:
        default_patterns = [
            "gen_phone_numbers",
            "gen_name_month_day_year",
            "gen_name_month_day",
            "gen_name_month_day_sym",
            "gen_single_name",
            "gen_single_adj",
            "gen_single_noun",
            "gen_two_word_permutations",
            "gen_three_word_permutations",
            "gen_word_digits_sym",
            "gen_two_words_digits_sym",
            "gen_three_words_digits_sym",
            "gen_word_year_sym",
            "gen_two_words_year_sym",
            "gen_three_words_year_sym",
            "gen_name_static_digits_sym",
            "gen_random_insert",
            "gen_word_phone_sym",
            "gen_phone_year_sym",
            "gen_letter_phone_letter_sym",
        ]
        dlg = PatternOrderDialog(self, default_patterns)
        if dlg.exec() == QDialog.Accepted:
            order = dlg.get_order()
            if order:
                return order
        return None

    def _on_chunk_progress(self, cap_path: str, ssid: str, bssid: str, chunk_index: int, area_codes: List[str]):
        if not isinstance(self.manager.last_chunk_idxs, list):
            self.manager.last_chunk_idxs = [-1, -1, -1]
        if chunk_index not in self.manager.last_chunk_idxs:
            self.manager.last_chunk_idxs.append(chunk_index)
        idxs = sorted(self.manager.last_chunk_idxs)
        if len(idxs) > 3:
            idxs = idxs[-3:]
        while len(idxs) < 3:
            idxs.insert(0, -1)
        self.manager.last_chunk_idxs = idxs

        self.current_running_chunks = idxs.copy()

        save_state_for_cap(cap_path, ssid, bssid, self.manager.last_chunk_idxs, area_codes)
        self._append_aircrack_log(f"[W?] Completed chunk {chunk_index}")

    def _confirm(self, title: str, msg: str) -> bool:
        return QMessageBox.question(self, title, msg, QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes

    def _delete_selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select", "No handshake selected")
            return
        p = self.table.item(row, 2).text()
        if self._confirm("Delete", f"Delete {p} and its .txt and resume state?"):
            self._delete_paths([p])

    def _delete_all(self):
        if not self.handshakes:
            QMessageBox.information(self, "Empty", "No handshakes loaded")
            return
        if self._confirm("Delete ALL", "Delete all captures, .txt files, and resume states?"):
            self._delete_paths(list(self.handshakes.keys()))

    def _delete_paths(self, paths: List[str]):
        for p in paths:
            try:
                os.remove(p)
                cap_path = Path(p)
                directory = cap_path.parent
                stem = cap_path.stem
                prefix = "_".join(stem.split("_")[:-1]) if "_" in stem else stem
                for txt_file in directory.glob(f"{prefix}_*.txt"):
                    txt_file.unlink()
                delete_state_for_cap(p)
            except Exception as e:
                self._append_log(f"Fail delete {p}: {e}", "error")
        for p in paths:
            self.handshakes.pop(p, None)
            if self.current_cracking == p:
                self.current_cracking = None
                self._allpass_running = False
                self._allpass_paused = False
        self.refresh()
        self._append_log(f"Deleted {len(paths)} capture(s)", "success")

    def _on_generate_standard(self):
        try:
            lo, hi = [int(x) for x in self.lr.text().split("-")]
        except ValueError:
            self._append_log("Bad len range", "error")
            return
        include = self.name_chk.isChecked()
        mode = self.mode_cb.currentText()
        seq = self.seq_chk.isChecked()
        prefix, insert, suffix = self.pref.text(), self.ins.text(), self.suf.text()
        count = int(self.size.value() * 1024 * 1024 / 50)

        self.standard_gen_btn.setEnabled(False)
        self._append_log("Generating…", "info")
        self._gen = GeneratorThread((lo, hi), include, mode, count, seq, prefix, suffix, insert)
        self._gen.warning.connect(lambda w: self._append_log(w, "error"))
        self._gen.finished.connect(lambda c: (
            self._append_log(f"Generated {c} → {self.current_wordlist_path}", "success"),
            self.standard_gen_btn.setEnabled(True),
        ))
        self._gen.start()

    def _on_generate_smart(self):
        names = file_ops.load_names(self.current_names_path)
        self.smart_gen_btn.setEnabled(False)
        self._append_log("Smart gen…", "info")
        self._smart = SmartComboThread(names)
        self._smart.finished.connect(lambda c: (
            self._append_log(f"Generated {c} smart → {self.current_wordlist_path}", "success"),
            self.smart_gen_btn.setEnabled(True),
        ))
        self._smart.start()

    def _open_combo_builder(self):
        dlg = ComboBuilderWindow(self.settings, self)
        dlg.confirmed.connect(self._on_combo_built)
        dlg.exec_()

    def _on_combo_built(self, pattern: List[str], cfg: dict):
        self.combo_pattern = pattern
        self.combo_cfg = cfg
        self.combo_crack_btn.setEnabled(True)
        self._append_log(f"Pattern set → {' + '.join(pattern)}", "success")

    def _on_combo_crack(self):
        sel = self.get_selected()
        if not sel:
            return
        cap, ssid, bssid = sel
        if not self.combo_pattern:
            QMessageBox.warning(self, "Pattern", "Build a pattern first!")
            return
        self.combo_crack_btn.setEnabled(False)
        self._append_log("Combo pipe crack started", "info")
        self._pipe = ComboPipeWorker(cap, ssid, bssid, self.combo_pattern, self.combo_cfg)
        self._pipe.status.connect(self._append_aircrack_log)
        self._pipe.finished.connect(lambda f, k: (
            self._append_log(f"[✓] Key Found: {k}" if f else "No key found", "success" if f else "info"),
            self.combo_crack_btn.setEnabled(True),
        ))
        self._pipe.start()

    def _on_all_pass_start(self):
        sel = self.get_selected()
        if not sel:
            return
        cap, ssid, bssid = sel

        # Stop existing manager if running or paused
        if self.manager and (self._allpass_running or self._allpass_paused):
            self._save_current_progress()
            self.manager.stop()
            self._allpass_running = False
            self._allpass_paused = False
            self.current_cracking = None

        self.current_cap_path = cap
        self.current_ssid = ssid
        self.current_bssid = bssid
        self.current_running_chunks = [-1, -1, -1]

        # Ask for area codes
        text, ok = QInputDialog.getText(
            self, "Area Codes",
            "Enter 3-digit area codes, separated by commas (e.g. 201,212),\n"
            "or leave empty to use ALL area codes:"
        )
        if not ok:
            return
        user_input = text.strip()
        area_codes: Optional[List[str]] = []
        if user_input:
            codes = [c.strip() for c in user_input.split(",")]
            for c in codes:
                if not re.fullmatch(r"\d{3}", c):
                    QMessageBox.warning(self, "Invalid Input", f"“{c}” is not a valid 3-digit area code.")
                    return
            area_codes = codes

        # Ask for pattern order using the GUI dialog
        pattern_order = self._ask_pattern_order_dialog()
        if pattern_order is None or len(pattern_order) == 0:
            QMessageBox.warning(self, "Pattern Order", "You must enter a valid password pattern order.")
            return

        # Create WorkerManager and pass saved paths for names, adjectives, nouns
        self.manager = WorkerManager(generator_order=pattern_order)
        self.manager.last_chunk_idxs = [-1, -1, -1]
        self.manager.area_codes = area_codes[:]
        self.manager.cap_path = cap
        self.manager.ssid = ssid
        self.manager.bssid = bssid

        # Pass saved persistent wordlist file paths to manager
        self.manager.names_path = self.current_names_path
        self.manager.adj_path = self.current_adj_path
        self.manager.noun_path = self.current_noun_path

        self.manager.status.connect(lambda wid, msg: self._append_aircrack_log(f"[W{wid}] {msg}"))
        self.manager.progress.connect(lambda wid, idx: self._on_chunk_progress(cap, ssid, bssid, idx, area_codes))
        self.manager.cracked.connect(lambda wid, key: self._on_key_found(wid, key))
        self.manager.finished.connect(self._on_all_pass_finished)
        self.manager.save_progress.connect(self._save_current_progress)

        save_state_for_cap(cap, ssid, bssid, self.manager.last_chunk_idxs, area_codes)

        self.all_pass_btn.setEnabled(False)
        self.pause_all_pass_btn.setEnabled(True)
        self.pause_all_pass_btn.setText("Pause ALL-PASS")
        self.chunk_bar.setVisible(True)
        self.chunk_bar.setRange(0, 0)

        self._append_aircrack_log(
            f"Starting All-Pass on {cap} with area codes {area_codes or 'ALL'} and pattern order {pattern_order}…")

        self.manager.start(cap, ssid, bssid, area_codes)
        self._allpass_running = True
        self._allpass_paused = False
        self.current_cracking = cap
        self.refresh()

    def _on_all_pass_pause_resume(self):
        if not (self._allpass_running or self._allpass_paused):
            return

        if self._allpass_running:
            self._append_aircrack_log(f"Pausing All-Pass on {self.current_cap_path}…")
            self._save_current_progress()
            self.manager.pause()
            self._allpass_running = False
            self._allpass_paused = True
            self.pause_all_pass_btn.setText("Resume ALL-PASS")
            self.all_pass_btn.setEnabled(True)
        else:
            if self.current_cap_path and self.current_cap_path in load_all_states():
                self._resume_specific_cap(self.current_cap_path)
                return

        self.current_cracking = self.current_cap_path if self._allpass_running else None
        self.refresh()

    def _on_all_pass_finished(self, found: bool, key: str):
        cap = self.current_cap_path or ""
        if found:
            self._append_aircrack_log(f"[✓] Key Found for {cap}: {key}")
        else:
            self._append_aircrack_log(f"All-Pass on {cap} finished. No key found.")
        self.chunk_bar.setVisible(False)
        self.all_pass_btn.setEnabled(True)
        self.pause_all_pass_btn.setEnabled(False)
        self.pause_all_pass_btn.setText("Pause ALL-PASS")
        self._allpass_running = False
        self._allpass_paused = False

        if found:
            delete_state_for_cap(cap)

        self.current_cracking = None
        self.refresh()

    def _on_open(self):
        p, _ = QFileDialog.getOpenFileName(self, "Password List", os.getcwd(), "Text Files (*.txt)")
        if p:
            self.current_wordlist_path = p
            self._append_log(f"Using list: {p}", "success")

    def _run(self, cap: str, ssid: str, bssid: str, wordlist: str, btn: QPushButton):
        btn.setEnabled(False)
        self._append_aircrack_log("aircrack-ng…")
        self._crack = AircrackThread(cap, ssid, bssid, wordlist)
        self._crack.status.connect(self._append_aircrack_log)
        self._crack.finished.connect(lambda f, k: (
            self._append_log(f"[✓] Key Found: {k}" if f else "No key found", "success" if f else "info"),
            btn.setEnabled(True),
            self._on_wordlist_finished(cap)
        ))
        self.current_cracking = cap
        self.refresh()
        self._crack.start()

    def _on_run_selected(self):
        sel = self.get_selected()
        if not sel:
            return
        cap, ssid, bssid = sel
        if not os.path.isfile(self.current_wordlist_path):
            self._append_log("Password list missing", "error")
            return
        self._run(cap, ssid, bssid, self.current_wordlist_path, self.run_selected_btn)

    def _on_run_generated(self):
        sel = self.get_selected()
        if not sel:
            return
        cap, ssid, bssid = sel

        gen_path = os.path.join(os.getcwd(), "pass", "generated_wordlist.txt")
        if not os.path.isfile(gen_path):
            self._append_log("Generated list missing in pass/generated_wordlist.txt", "error")
            return
        self._run(cap, ssid, bssid, gen_path, self.run_generated_btn)

    def _on_wordlist_finished(self, cap: str):
        self.current_cracking = None
        self.refresh()

    def _on_all_stop(self):
        self._append_aircrack_log("ALL STOP requested")
        if self._pipe and getattr(self._pipe, "isRunning", lambda: False)():
            try:
                self._pipe.stop()
            except Exception:
                pass

        if self.manager and (self._allpass_running or self._allpass_paused):
            self._save_current_progress()
            self.manager.stop()
        self._allpass_running = False
        self._allpass_paused = False

        if self._crack and getattr(self._crack, "isRunning", lambda: False)():
            try:
                self._crack.terminate()
            except Exception:
                pass

        self.all_pass_btn.setEnabled(True)
        self.pause_all_pass_btn.setEnabled(False)
        self.pause_all_pass_btn.setText("Pause ALL-PASS")
        self.chunk_bar.setVisible(False)
        self.combo_crack_btn.setEnabled(True)
        self.current_cracking = None
        self.refresh()

    def get_selected(self) -> Optional[Tuple[str, str, str]]:
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select", "Select a handshake first.")
            return None
        path_item = self.table.item(row, 2)
        if not path_item:
            return None
        path = path_item.text()
        return (path, *self.handshakes.get(path, ("", "")))

    def _on_key_found(self, worker_id: int, key: str):
        print(f"DEBUG: _on_key_found called with worker {worker_id}, key={key}")  # Debug print

        cap = self.current_cap_path or ""
        self._append_log(f"[✓] Key Found by worker {worker_id}: {key}", "success")
        QMessageBox.information(self, "Key Found", f"Handshake {cap} cracked!\nKey: {key}")

        # Save password to .txt file next to the handshake capture
        try:
            from pathlib import Path
            cap_path = Path(cap)
            txt_path = cap_path.with_suffix(".txt")
            with txt_path.open("w", encoding="utf-8") as f:
                f.write(key + "\n")
            self._append_log(f"Saved cracked password to {txt_path}", "success")
        except Exception as e:
            self._append_log(f"Failed to save password file: {e}", "error")

        # Stop the cracking manager/workers immediately
        if self.manager and (self._allpass_running or self._allpass_paused):
            self.manager.stop()
            self._allpass_running = False
            self._allpass_paused = False

        delete_state_for_cap(cap)
        self.current_cracking = None
        self.refresh()


if __name__ == "__main__":
    import sys

    app = QApplication(sys.argv)

    palette = QPalette()
    palette.setColor(palette.Window, QColor(0, 10, 0))
    palette.setColor(palette.WindowText, QColor(0, 255, 0))
    palette.setColor(palette.Base, QColor(0, 5, 0))
    palette.setColor(palette.Text, QColor(0, 255, 0))
    palette.setColor(palette.Button, QColor(0, 10, 0))
    palette.setColor(palette.ButtonText, QColor(0, 255, 0))
    palette.setColor(palette.Highlight, QColor(0, 255, 0))
    palette.setColor(palette.HighlightedText, QColor(0, 0, 0))
    app.setPalette(palette)
    app.setFont(app.font().family(), 12)

    w = CrackerWidget()
    w.show()
    sys.exit(app.exec_())
