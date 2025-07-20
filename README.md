Silent Turtle — Detailed Documentation

Overview

Silent Turtle is a comprehensive Python-based Wi-Fi penetration testing toolkit designed for Linux environments. It integrates extensive capabilities for wireless scanning, handshake capturing, password cracking using CPU-based methods, captive portal creation, password pattern generation, and exporting captures for GPU-based cracking on external systems (Windows or GPU-equipped Linux machines).

System Requirements

Supported Operating System

Linux Only: Ubuntu/Debian recommended.

Windows: NOT supported for running the application; only for handling exported .pcap files for GPU cracking.

Wireless Adapter Requirements

Must support monitor mode and packet injection.

Recommended chipsets: Atheros, Ralink, Realtek.

Proper Linux-compatible drivers required.

Installation Guide

Linux System Packages (Install via apt)

sudo apt update
sudo apt install -y python3 python3-pip python3-pyqt5 build-essential libpcap-dev libsqlite3-dev aircrack-ng iw wireless-tools tcpdump wireshark

Python Packages (Install via pip3)

pip3 install scapy pyqt5

Ollama (Optional AI Chat Integration)

Install Ollama from official site.

Download a model (e.g., dolphin-llama3:8b) via Ollama CLI.

Detailed Features

Capture Module

Live SSID Feed:

Displays real-time Wi-Fi networks with signal strength, SSID, BSSID, and channel info.

Monitor Mode Enforcement:

Automatically sets wireless adapters to monitor mode.

Manual restart recommended if initial setup fails.

Channel Hopping:

Automatically scans across Wi-Fi channels.

Customizable dwell times.

Handshake Capture:

Automatic detection and capture of WPA/WPA2 handshakes.

Focused capture available for single-target APs.

Deauthentication Attacks:

Single or mass AP deauthentication to force handshakes.

Automatic 60-second post-deauth focused captures.

Handshakes Directory:

Stores captures as .cap and auto-converts to .pcap files.

File Conversion & Verification:

Automatic .cap to .pcap conversion via editcap (Wireshark).

Integrity verification of captures post-conversion.

Cloned Access Point & Captive Portal

Fake AP Creation:

Replicates SSID and broadcasts via airbase-ng.

Captive Portal:

Flask-based, customizable captive web portal.

Logs attempted passwords securely.

One-time Sessions:

Limits attempts per session.

Automated teardown after successful captures.

Password Generation & Combo Builder

Advanced Password Generation:

Supports extensive patterns: names, adjectives, nouns, years, months, days, digits, symbols, custom phrases.

Area-code prioritization for phone number-based passwords.

Over 20 built-in password patterns.

Combo Builder GUI:

Interactive custom password combination creation.

Drag-and-drop interface for defining password patterns.

Supports real-time smart cracking with custom combinations.

ALL-PASS: Distributed Cracking Engine

Multi-threaded Brute Force:

Supports parallel password cracking across multiple threads.

CPU-based cracking engine (no GPU support).

Chunked Processing & Resumption:

Passwords processed in configurable chunks (default: 500,000).

Checkpoint recovery and full pause/resume capabilities.

Real-time progress updates with detailed logging.

Cracked Password Handling:

Automatically saves cracked passwords to .txt files next to respective captures.

Ollama Chat Integration (Optional)

Local LLM Chat:

Embeds Ollama-powered AI chat for security and scripting assistance.

Runs entirely offline and locally.

Workflow Automation & Utilities

Automated Handshake Scanning:

Quick or full system scans for available handshake files.

Metadata extraction for file indexing.

File Management:

Integrated deletion and cleanup of captures, logs, and associated files.

Cross-platform Export:

Prepares .pcap files for external GPU-based cracking.

GPU-based cracking not supported internally; export required.

Usage Examples

Capturing a Handshake

Launch Silent Turtle, initiate monitor mode.

Start live SSID feed and identify target.

Perform deauthentication attack and automatically capture handshake.

Cracking a Handshake (ALL-PASS)

Select handshake from the indexed table.

Customize area codes and password patterns if desired.

Initiate ALL-PASS cracking, monitor real-time progress.

Exporting for GPU Cracking

Use Silent Turtle to capture handshake and convert to .pcap.

Transfer .pcap files to GPU-equipped system.

Perform GPU-based cracking externally with tools like Hashcat.

Troubleshooting & Notes

Monitor Mode Issues:

Restart program if monitor mode fails initially.

Check compatibility and drivers if issues persist.

GPU Cracking Clarification:

VMware/Linux does not support GPU sharing; hence GPU usage removed.

GPU cracking functionality limited to exported .pcap files on compatible systems.

Security & Ethical Notice

Silent Turtle is intended strictly for authorized network security testing. Unauthorized usage is prohibited and may be illegal.

Summary

Feature

Description

Supported OS

Linux (Ubuntu/Debian)

Wireless Compatibility

Monitor mode, packet injection

Handshake Capture

Live, focused, automatic

PCAP Export

Automatic conversion to .pcap

Password Generation

Highly customizable, extensive patterns

Cracking Engine

CPU-based, distributed, chunked, resume capability

Captive Portal

Flask-based, customizable logging

Ollama Integration

Local offline AI assistant (optional)

GPU Cracking

External use only via .pcap export
