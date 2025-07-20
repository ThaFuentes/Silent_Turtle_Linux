# Silent_Turtle_Linux
Silent Turtle is a Python Wi-Fi pentesting toolkit with live scanning, handshake capture, and CPU-based WPA cracking. It features pause/resume, customizable password patterns, and .cap to .pcap conversion for GPU cracking on Windows. Perfect for quiet, effective Wi-Fi security testing without GPU reliance.

Silent Turtle is a Python Wi-Fi pentesting toolkit with live scanning, handshake capture, and CPU-based WPA cracking. It features pause/resume, customizable password patterns, and .cap to .pcap conversion for GPU cracking on Windows. Perfect for quiet, effective Wi-Fi security testing without GPU reliance.

---- IF YOU HAVE ISSUES WITH MONITOR MODE - RESTART THE PROGRAM ----

Silent Turtle — Complete Install Requirements
OS
Linux only (Ubuntu/Debian recommended)

Windows NOT supported for running; ONLY for exporting .pcap files for GPU cracking externally

System Packages (Linux)
Install all these with your package manager (apt example below):

bash
Copy
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-pyqt5 \
    build-essential libpcap-dev libsqlite3-dev \
    aircrack-ng iw wireless-tools tcpdump \
    wireshark # includes editcap for .cap to .pcap conversion
python3-pyqt5 — GUI

build-essential — compilers for dependencies

libpcap-dev — packet capture libs

libsqlite3-dev — database support

aircrack-ng — core capture & cracking tools

iw and wireless-tools — wireless device management

tcpdump — packet analysis/debugging

wireshark — includes editcap for capture file conversion

Python Packages (install via pip3)
bash
Copy
pip3 install scapy pyqt5
Ollama (LLM AI Assistant)
Required if you want to use the Ollama Chat UI inside Silent Turtle

Install from https://ollama.com/docs/installation

Ollama CLI must be available (ollama run <model>)

Download a model (e.g., dolphin-llama3:8b) with Ollama CLI before use

Ollama runs on Linux or macOS only (no Windows support currently)

Wireless Adapter Requirements
Must support monitor mode and packet injection on Linux

Supported chipsets: Atheros, Ralink, Realtek (check your driver compatibility)

Proper drivers installed and configured

GPU Cracking (External Use Only)
Silent Turtle uses CPU only cracking on Linux

To use GPU cracking:

Export .pcap handshake files from Silent Turtle

Transfer files to GPU-equipped Windows or Linux machine

Run GPU cracking tools (Hashcat, etc.) separately
