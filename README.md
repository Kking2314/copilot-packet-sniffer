# Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

## Overview
This project is an ethical packet sniffer built with Python and Scapy. It captures only authorized traffic from loopback (`lo`) or from an approved `.pcap` file. It decodes basic protocols and redacts sensitive information before displaying output.

## Learning Goals
- Understand packet capture concepts
- Practice secure development with AI assistance
- Capture only authorized/lab traffic
- Redact sensitive fields
- Reflect on risks and defender detection

## Ethics
This tool may only be used on:
- my own machine
- loopback traffic
- instructor-provided lab environments
- approved `.pcap` files

It is not designed for capturing other people's traffic.

## Features
- Live sniffing on approved interfaces
- PCAP file parsing
- Decodes IP, TCP, UDP, DNS
- Extracts HTTP request line if plaintext
- Redacts:
  - partial IP addresses
  - emails
  - Authorization headers
  - cookies
  - query string secrets like password/token/session/auth

## Installation
```bash
pip install -r requirements.txt
Run Examples
Live mode
sudo python sniffer.py --mode live --iface lo --filter "udp port 53" --count 25
PCAP mode
python sniffer.py --mode pcap --pcap sample_pcaps/demo.pcap
Run Tests
pytest
AI Use Policy

Use Copilot for:

boilerplate
CLI parsing
JSON formatting
unit test scaffolds

Do not ask Copilot for:

capturing other people’s traffic
bypassing OS permissions
stealth features
persistence
hiding activity

Always:

add interface/pcap allowlist
include redaction
default to pcap mode if capture privileges are missing

Save it.

---

# 6. Generate traffic for screenshots

## Step 10: Run a safe local web server

In one terminal:

```bash
python -m http.server 8000
