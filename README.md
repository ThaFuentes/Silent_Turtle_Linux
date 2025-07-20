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

Export .pcap handshake files from Silent Turtle

Transfer files to GPU-equipped Windows or Linux machine

Run GPU cracking tools (Hashcat, etc.) separately


Silent Turtle: Advanced Wi-Fi Handshake Capture & Cracking Suite
OVERVIEW
Silent Turtle is a professional-grade, GUI-based wireless network security toolkit for Linux, focused on automating, accelerating, and simplifying the entire Wi-Fi handshake cracking workflow — from discovery, capture, and attack, to exhaustive password generation and distributed brute force. It is engineered for penetration testers, security researchers, and advanced users who want granular control, modular extensibility, and zero vendor lock-in.

Key Principles:

100% offline, local-first, no cloud required

No commercial dependencies, FOSS preferred

You control every input, wordlist, and pattern — nothing is “hardcoded”

Built for high-volume, multi-target workflows

Modular: Every part can be swapped or extended

CORE COMPONENTS & ARCHITECTURE
1. Capture Module
Live Beacon Feed:

Real-time display of all detected SSIDs, BSSIDs, channels, and signal strengths.

Color-coded, sortable, instantly updates as networks appear/disappear.

Monitor Mode Enforcement:

Automatically switches your wireless adapter to monitor mode; supports chipsets that allow it.

Channel Hopping:

Hops across all (or user-chosen) Wi-Fi channels to maximize capture surface area.

Dwell time fully user-configurable.

Handshake Capture:

Auto-detects 4-way WPA/WPA2 handshakes using scapy, regardless of client activity or AP stealth.

Focused capture available for a single AP/channel.

Deauthentication Attack:

One-click deauths individual APs or “deauth all” for mass handshake gathering.

Automatically launches a focused 60-second capture post-deauth.

Handshakes Directory:

All captures saved in a structured handshakes/ folder, with .cap (original) and .pcap (editcap-converted) files.

PCAP Conversion:

Integrated, automatic .cap → .pcap conversion for downstream compatibility (Hashcat, Windows, etc).

Verification:

Verifies all .cap and .pcap files post-capture; highlights missing or corrupted files.

2. Cloned Access Point & Captive Portal
Cloning Tool:

Replicates the SSID of a target AP using airbase-ng, setting up a “fake AP” with the same name.

Broadcasts on a specified channel.

Captive Portal:

Instantly serves a custom, mobile-friendly Flask web portal that mimics a typical Wi-Fi login.

Captures and logs all attempted passwords submitted by users.

Portal workflow:

User connects to fake AP

Browser is redirected to verification page

Entered password is logged and can trigger AP teardown if desired

One-Time Use:

Each portal session logs only the first few attempts for forensic accuracy.

Safe teardown after successful capture (kills airbase-ng, cleans up interface, flushes iptables).

3. Password Generation & Combo Builder
Advanced Password Generator:

Streams password lists in chunks, optimized for WPA/WPA2 cracking.

Multiple token types:

Names, adjectives, nouns (from user-editable files)

Dates: all possible years (full and short), months (number, abbr, full), days

Digits: area codes, phone number structures, customizable digit runs

Special symbols, custom static phrases

Random insertion, letter+number mixing, prefix/suffix combos

Area Code Priority:

Optional: Restrict or prioritize combos using a custom set of 3-digit area codes

Combo Patterns:

20+ built-in generator patterns (permutations, phone numbers, name+date combos, etc)

User selects pattern order via drag-n-drop dialog before starting a run

Combo Builder:

Interactive GUI for constructing custom wordlist combos, chaining fields (e.g., Name+Year+Symbol).

Combo cracking mode supports custom configurations, on-the-fly smart wordlist synthesis.

Chunked Processing:

Passwords are tested in buffered chunks (default: 500,000), allowing for progress tracking, pause/resume, and checkpoint recovery.

4. ALL-PASS: Distributed Cracking Engine
Parallel Brute Force:

Multi-threaded worker model (3 by default), each cracking a distinct chunk in parallel.

Full Resume Support:

Save & restore every cracking job at any chunk, including custom area codes and pattern order.

Resume even if system crashes or user restarts the program.

Live Progress & Logging:

Color-coded log window, chunk progress, and per-handshake status updates in real time.

Cracked Password Handling:

Found keys are instantly written to .txt files next to their respective .cap/.pcap.

5. Ollama Chat Integration (AI Assistant)
Integrated LLM Chat UI:

Embeds a chat window running local models via Ollama (dolphin-llama3:8b or similar).

Lets you ask security, scripting, or operational questions without leaving the app.

Privacy First:

No internet required; all LLM inference happens locally via the Ollama runtime.

6. System & Workflow Automation
Full Handshake Scanning:

Automatic scan of root (/) or quick scan of handshakes/ to index all available handshake files.

Metadata extraction: SSID/BSSID parsing even from corrupted or incomplete files.

Safe File Operations:

Deleting a handshake auto-deletes associated .txt (passwords) and resume files.

Wordlist Path Persistence:

User-specified names, adjectives, nouns files saved per-session and passed to every cracking job.

Modular Utility Scripts:

All system-level commands (iw, aircrack-ng, editcap) run in silent, robust wrappers, with error handling.

7. Cross-Platform Export (for GPU cracking)
PCAP Export:

All .cap handshakes are converted and verified as .pcap, ready for transfer to Windows or other GPU-equipped systems.

No GPU on Linux:

Cracking engine is CPU-only by design; intended to maximize compatibility and avoid driver hell on Linux.

Windows Use:

Silent Turtle does NOT run on Windows, but exported .pcap files can be cracked with Hashcat/other GPU tools externally.

USER WORKFLOW EXAMPLES
Capturing a Handshake:

Launch Silent Turtle, set your interface to monitor mode.

Start live feed; watch SSIDs and signals update in real time.

Click to deauth a target, then immediately capture handshake traffic.

Handshake is saved in handshakes/ as both .cap and .pcap.

Cracking a Handshake (ALL-PASS):

Select any handshake from the indexed table.

Enter custom area codes if you want (or leave blank for all).

Drag and reorder password patterns as needed in the GUI.

Start ALL-PASS. See real-time chunk logs, status, and color-coded events.

Pause/resume at any time. All state is checkpointed.

When key is found, password is saved and UI updates instantly.

Combo Builder (Smart Crack):

Build a pattern using Name+Year+Symbol, or whatever combo is needed.

Generate and crack with custom combo lists in real time.

Captive Portal/Cloned AP:

Clone a network using a fake AP.

Run captive portal and harvest credentials from unsuspecting users.

Export for GPU Cracking:

After capture, copy .pcap files to a Windows/Linux GPU box.

Run Hashcat or your preferred GPU cracker using those files.

SECURITY & ETHICS NOTICE
Silent Turtle is a professional auditing tool. Only use it on networks you own or have explicit, written permission to test. Unauthorized use may be illegal and is strictly against the intent of this project.

SUMMARY TABLE
Feature	Details
Supported OS	Linux only (Debian/Ubuntu best)
Wireless chipset	Any with monitor mode + injection support
Handshake capture	Full, focused, live; deauth attack, channel hop
PCAP export	Built-in, all .cap auto-converted to .pcap
Wordlist generation	Fully modular, priority-ordered, 20+ pattern combos, area code filtering
All-Pass brute force	Multi-worker, chunked, full resume, per-worker progress
Combo builder	GUI for custom wordlists and smart cracks
Captive portal	Flask-based, customizable, logs all password attempts
Ollama chat	Integrated local LLM (optional), AI helper for power users
Logging	Color-coded, per-action, chunk status, handshake stats
GPU support	Not on Linux; export .pcap for use on GPU boxes (Hashcat etc)


