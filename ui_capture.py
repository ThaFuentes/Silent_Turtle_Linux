#ui_capture.py
#!/usr/bin/env python3
# ui_capture.py – rebuilt 2025-05-27 with monitor-mode enforcement
# + real .pcap conversion post-capture, verification, and one-time conversion per file.

import subprocess
from pathlib import Path

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QMessageBox
)
from PyQt5.QtCore import QTimer, QThread, pyqtSignal

from config import (
    ALL_CHANNELS,
    INFO_COLOR, SCAN_COLOR, ERROR_COLOR,
    PARTIAL_COLOR, HS_COLOR, SSID_COLOR
)
from sys_helpers import enable_monitor
from threads import (
    LiveViewThread, HScaptureThread,
    DeauthThread, DeauthAllManagerThread
)
from utils import parse_dwell


class PcapConvertThread(QThread):
    log = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, hs_dir: Path, pcap_dir: Path):
        super().__init__()
        self.hs_dir = hs_dir
        self.pcap_dir = pcap_dir

    def run(self):
        # ensure output dir
        self.pcap_dir.mkdir(parents=True, exist_ok=True)

        # convert any .cap without a matching .pcap
        for cap_path in sorted(self.hs_dir.glob("*.cap")):
            pcap_path = self.pcap_dir / (cap_path.stem + ".pcap")
            if not pcap_path.exists():
                try:
                    subprocess.run(
                        ["editcap", "-F", "libpcap", str(cap_path), str(pcap_path)],
                        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    self.log.emit(f"[Convert] {cap_path.name} → {pcap_path.name}")
                except Exception as e:
                    self.log.emit(f"[Convert ERROR] {cap_path.name}: {e}")

        # verification
        cap_count = len(list(self.hs_dir.glob("*.cap")))
        pcap_count = len(list(self.pcap_dir.glob("*.pcap")))
        if pcap_count < cap_count:
            self.log.emit(f"[Verify] {cap_count} .cap but only {pcap_count} .pcap! Missing conversions.")
        else:
            self.log.emit(f"[Verify] {cap_count} .cap and {pcap_count} .pcap ✓")

        self.finished.emit()


class CaptureWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wi-Fi Capture & Handshake Monitor")

        # project dirs
        self.root_dir = Path.cwd()
        self.hs_dir = self.root_dir / "handshakes"
        self.pcap_dir = self.root_dir / "pcaps"
        self.hs_dir.mkdir(exist_ok=True)
        self.pcap_dir.mkdir(exist_ok=True)

        # runtime state
        self.hs_count, self.ssid_map = 0, {}
        self.latest_nets, self.display_order = {}, []

        # threads
        self.mon_iface = None
        self.live_thread = self.cap_thread = None
        self.focus_thread = self.deauth_thread = None
        self.deauth_all_thread = None
        self._converter = None

        self._single_bssid = self._single_ch = None

        # build UI
        self._build_ui()
        self.refresh_iface()
        if self.iface_cb.count():
            self.start_live_view(auto_init=True)

    def _build_ui(self):
        lay = QVBoxLayout(self)

        # Interface & Refresh
        row = QHBoxLayout()
        row.addWidget(QLabel("Interface:"))
        self.iface_cb = QComboBox()
        row.addWidget(self.iface_cb)
        btn_ref = QPushButton("Refresh")
        btn_ref.clicked.connect(self.refresh_iface)
        row.addWidget(btn_ref)
        lay.addLayout(row)

        # Live SSID feed
        lay.addWidget(QLabel("Live SSID Feed"))
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["SSID", "BSSID", "Channel", "Signal"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(self.table.SelectRows)
        self.table.setSelectionMode(self.table.SingleSelection)
        lay.addWidget(self.table)

        self.channel_summary = QLabel("Channels:")
        self.channel_summary.setWordWrap(True)
        lay.addWidget(self.channel_summary)

        # Logs & Counter
        lay.addWidget(QLabel("Logs"))
        self.log = QTextEdit(readOnly=True)
        self.log.setStyleSheet("background:#0D0D0D;color:#EEE;font-family:'Fira Code';")
        lay.addWidget(self.log)
        self.counter = QLabel("Handshakes: 0")
        lay.addWidget(self.counter)

        # Capture / Deauth controls
        ctl = QHBoxLayout()
        ctl.addWidget(QLabel("Channel:"))
        self.ch_cb = QComboBox()
        self.ch_cb.addItems(["All", "Active"] + [str(c) for c in ALL_CHANNELS])
        ctl.addWidget(self.ch_cb)

        ctl.addWidget(QLabel("Dwell:"))
        self.dwell_input = QLineEdit("5s")
        ctl.addWidget(self.dwell_input)

        self.btn_cap_start = QPushButton("Start Capture")
        self.btn_cap_start.clicked.connect(self.start_capture)
        ctl.addWidget(self.btn_cap_start)

        self.btn_cap_stop = QPushButton("Stop Capture")
        self.btn_cap_stop.clicked.connect(self.stop_capture)
        self.btn_cap_stop.setEnabled(False)
        ctl.addWidget(self.btn_cap_stop)

        self.btn_deauth = QPushButton("Deauth")
        self.btn_deauth.clicked.connect(self.deauth_selected)
        ctl.addWidget(self.btn_deauth)

        self.btn_deauth_all = QPushButton("Deauth All & Capture")
        self.btn_deauth_all.clicked.connect(self.deauth_all_capture)
        ctl.addWidget(self.btn_deauth_all)
        lay.addLayout(ctl)

        # Live-view controls
        live = QHBoxLayout()
        self.btn_live_start = QPushButton("Start Live")
        self.btn_live_start.clicked.connect(self.start_live_view)
        live.addWidget(self.btn_live_start)

        self.btn_live_stop = QPushButton("Stop Live")
        self.btn_live_stop.clicked.connect(self.stop_live_view)
        self.btn_live_stop.setEnabled(False)
        live.addWidget(self.btn_live_stop)

        self.btn_live_restart = QPushButton("Restart Live")
        self.btn_live_restart.clicked.connect(lambda: self.start_live_view(restart=True))
        self.btn_live_restart.setEnabled(False)
        live.addWidget(self.btn_live_restart)
        lay.addLayout(live)

    def append(self, msg, typ="info", bssid=None):
        colors = {
            "scan": SCAN_COLOR, "capture": "#00D7D7", "deauth": "#FFB300",
            "wait": "#4CAF50", "error": ERROR_COLOR, "handshake": HS_COLOR,
            "info": INFO_COLOR, "partial": PARTIAL_COLOR, "ssid": SSID_COLOR,
            "normal": "#EEE",
        }
        esc = lambda t: t.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        line = f'<span style="color:{colors.get(typ,colors["normal"])};">{esc(msg)}</span>'
        if bssid:
            line += f' <span style="color:{colors["ssid"]};">{esc(bssid)}</span>'
        self.log.append(line)
        if typ == "handshake":
            self.hs_count += 1
            self.counter.setText(f"Handshakes: {self.hs_count}")
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def _safe_stop(self, name):
        th = getattr(self, name, None)
        if th and getattr(th, "isRunning", lambda: False)():
            try:
                if hasattr(th, "requestInterruption"):
                    th.requestInterruption()
                if hasattr(th, "stop"):
                    th.stop()
                th.quit()
            except Exception:
                pass
            th.wait(100)
        setattr(self, name, None)

    # ───── Live-view ─────
    def start_live_view(self, restart=False, auto_init=False):
        if restart:
            self.stop_live_view()
            iface = self.iface_cb.currentText()
            if iface:
                self.mon_iface = enable_monitor(iface)
        if self.live_thread and self.live_thread.isRunning():
            return
        dwell = parse_dwell(self.dwell_input.text()) or 5
        self.live_thread = LiveViewThread(self.mon_iface, dwell, self.ssid_map)
        self.live_thread.updated.connect(self.update_live)
        self.live_thread.start()
        if not auto_init:
            self.append("[Live] Beacon feed started", "scan")
        self.btn_live_start.setEnabled(False)
        self.btn_live_stop.setEnabled(True)
        self.btn_live_restart.setEnabled(True)

    def stop_live_view(self):
        self._safe_stop("live_thread")
        self.append("[Live] Beacon feed stopped", "scan")
        self.btn_live_start.setEnabled(True)
        self.btn_live_stop.setEnabled(False)
        self.btn_live_restart.setEnabled(False)

    def closeEvent(self, e):
        for name in ("live_thread","cap_thread","focus_thread","deauth_thread","deauth_all_thread"):
            self._safe_stop(name)
        super().closeEvent(e)

    def refresh_iface(self):
        self.iface_cb.clear()
        out = subprocess.getoutput("iw dev")
        ifaces = [ln.split()[1] for ln in out.splitlines() if ln.strip().startswith("Interface")]
        self.iface_cb.addItems(ifaces)
        self.append(f"[i] {len(ifaces)} iface(s)", "info")
        mon = None
        for i in ifaces:
            info = subprocess.getoutput(f"iw dev {i} info")
            if "type monitor" in info.lower():
                mon = i; break
        if mon:
            self.iface_cb.setCurrentText(mon); self.mon_iface = mon
        elif ifaces:
            chosen = ifaces[0]
            self.iface_cb.setCurrentText(chosen)
            self.mon_iface = enable_monitor(chosen)

    def update_live(self, nets):
        self.latest_nets = nets
        keys = list(nets)
        self.display_order = [k for k in self.display_order if k in keys] + [k for k in keys if k not in self.display_order]
        prev = self.table.verticalScrollBar().value()
        sel_row = self.table.currentRow()
        sel_key = (self.table.item(sel_row,1).text(), self.table.item(sel_row,0).text()) if sel_row>=0 else None
        self.table.setRowCount(len(self.display_order))
        for r,k in enumerate(self.display_order):
            info = nets[k]
            self.table.setItem(r,0, QTableWidgetItem(info["ssid"]))
            self.table.setItem(r,1, QTableWidgetItem(info["bssid"]))
            self.table.setItem(r,2, QTableWidgetItem(str(info.get("channel",""))))
            self.table.setItem(r,3, QTableWidgetItem(str(info["signal"])))
            if sel_key==(info["bssid"],info["ssid"]):
                self.table.selectRow(r)
        self.table.verticalScrollBar().setValue(prev)
        counts={}
        for i in nets.values():
            try:
                ch=int(i.get("channel"))
                counts[ch]=counts.get(ch,0)+1
            except:
                continue
        if counts:
            mx=max(counts.values())
            parts=[f"<b>Ch {c}: {n} APs</b>" if n==mx else f"Ch {c}: {n} APs" for c,n in sorted(counts.items())]
            self.channel_summary.setText("Channels: "+" | ".join(parts))
        else:
            self.channel_summary.setText("Channels: No APs detected")

    # ───── Capture start/stop ─────
    def start_capture(self):
        dwell = parse_dwell(self.dwell_input.text())
        if dwell is None:
            QMessageBox.warning(self,"Invalid dwell","Use 5s, 1m …"); return
        choice = self.ch_cb.currentText()
        if choice=="All":
            chans = ALL_CHANNELS[:]
        elif choice=="Active":
            chans = sorted(int(i.get("channel")) for i in self.latest_nets.values() if str(i.get("channel")).isdigit())
            if not chans:
                QMessageBox.warning(self,"No active channels","No APs detected");return
        else:
            try: chans=[int(choice)]
            except:
                QMessageBox.warning(self,"Bad channel",choice);return
        self._safe_stop("cap_thread")
        self.cap_thread = HScaptureThread(self.mon_iface, chans, dwell, self.ssid_map)
        self.cap_thread.log.connect(self.append)
        self.cap_thread.finished.connect(lambda: None)
        self.cap_thread.start()
        self.append(f"[Capture] HS on {chans} dwell={dwell}s","capture")
        self.btn_cap_start.setEnabled(False)
        self.btn_cap_stop.setEnabled(True)

    def stop_capture(self):
        self._safe_stop("cap_thread"); self._safe_stop("focus_thread")
        self.append("[Capture] Stopped","capture")
        self.btn_cap_start.setEnabled(True); self.btn_cap_stop.setEnabled(False)

    # ───── Single‐AP deauth + focus ─────
    def deauth_selected(self):
        row=self.table.currentRow()
        if row<0:
            QMessageBox.warning(self,"Pick AP","Select a row first");return
        self._single_bssid=self.table.item(row,1).text()
        try:
            self._single_ch=int(self.table.item(row,2).text())
        except:
            QMessageBox.warning(self,"Bad channel","Row has invalid channel");return
        for t in ("live_thread","cap_thread","focus_thread"):
            self._safe_stop(t)
        QTimer.singleShot(0,self._run_deauth_selected)

    def _run_deauth_selected(self):
        b,ch=self._single_bssid,self._single_ch
        self.append(f"[Deauth] {b} ch {ch}","deauth")
        self.btn_deauth.setEnabled(False)
        self.deauth_thread=DeauthThread(self.mon_iface,b,ch)
        self.deauth_thread.error.connect(lambda m: self.append(f"[Deauth ERR] {m}","error",b))
        self.deauth_thread.done.connect(lambda: QTimer.singleShot(0,self._after_deauth))
        self.deauth_thread.start()

    def _after_deauth(self):
        self._safe_stop("deauth_thread")
        ch=self._single_ch
        self.append(f"[Deauth] Done ch {ch}","deauth")
        # focus capture for 60s
        self.focus_thread=HScaptureThread(self.mon_iface,[ch],60,self.ssid_map)
        self.focus_thread.log.connect(self.append)
        self.focus_thread.finished.connect(lambda: QTimer.singleShot(0,self._focus_done))
        self.focus_thread.start()
        self.append(f"[Capture] Focus 60 s ch {ch}","capture")

    def _focus_done(self):
        self._safe_stop("focus_thread")
        self.append("[Capture] Focus done → live","capture")
        self.start_live_view(restart=True)
        self.btn_deauth.setEnabled(True)
        # now convert any new .cap → .pcap
        self._start_conversion()

    # ───── Deauth‐All + capture ─────
    def deauth_all_capture(self):
        if not self.latest_nets:
            QMessageBox.warning(self,"No APs","Nothing to deauth");return
        for t in ("live_thread","cap_thread","focus_thread","deauth_thread","deauth_all_thread"):
            self._safe_stop(t)
        targets=[(i["bssid"],i["channel"]) for i in self.latest_nets.values()]
        self.btn_deauth_all.setEnabled(False)
        self.append(f"[DeauthAll] {len(targets)} APs","deauth")
        self.deauth_all_thread=DeauthAllManagerThread(self.mon_iface,targets,60,self.ssid_map)
        self.deauth_all_thread.log.connect(self.append)
        self.deauth_all_thread.progress.connect(lambda i,t: self.append(f"[DeauthAll] {i}/{t}","info"))
        self.deauth_all_thread.finished.connect(lambda: QTimer.singleShot(0,self._deauth_all_done))
        self.deauth_all_thread.start()

    def _deauth_all_done(self):
        self._safe_stop("deauth_all_thread")
        self.append("[DeauthAll] Done → live","deauth")
        self.start_live_view(restart=True)
        self.btn_deauth_all.setEnabled(True)
        self._start_conversion()

    # ───── Conversion helper ─────
    def _start_conversion(self):
        if self._converter and self._converter.isRunning():
            return  # already converting
        self._converter = PcapConvertThread(self.hs_dir, self.pcap_dir)
        self._converter.log.connect(lambda m: self.append(m,"info"))
        self._converter.start()
