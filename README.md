# Copilot-Assisted Packet Sniffer: Seeing the Network Ethically

## Project Overview

This project is an ethical packet sniffer built with Python and Scapy. It captures only authorized lab traffic or reads from a PCAP file. The goal is to understand packet capture, TCP/UDP, DNS, HTTP, and safe redaction.

## Learning Goals

- Understand packet capture concepts
- Decode IP, TCP, UDP, DNS, and basic HTTP traffic
- Use GitHub Copilot responsibly
- Redact sensitive data before output
- Explain the risks of packet sniffers

## Scope and Ethics

Students may only capture traffic on:

- Their own machine
- Loopback interface
- Instructor-provided lab VM or lab network
- Approved PCAP files

Students may not capture other people’s traffic.

## AI Use Policy

Use Copilot for:

- Boilerplate
- CLI parsing
- JSON formatting
- Unit test scaffolds

Do not ask Copilot for:

- Capturing other people’s traffic
- Bypassing OS permissions
- Stealth features
- Persistence
- Hiding activity

Always:

- Add interface/PCAP allowlist
- Include redaction
- Default to PCAP mode if capture permissions are missing

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install scapy pytest
Run Examples
sudo python3 sniffer.py --iface lo --filter "tcp port 80" --count 25
python3 sniffer.py --pcap sample.pcap
Testing
pytest
Redaction Features

The tool redacts:

Partial IP addresses
Emails
Authorization headers
Cookies
Passwords
Tokens
Session values

---

## `report.md` template

```md
# Packet Sniffer Report

## What I Captured

For this lab, I captured authorized traffic from my own machine using the loopback interface. I generated test traffic using a local Python web server and curl commands.

Example command:

```bash
sudo python3 sniffer.py --iface lo --filter "tcp port 8000" --count 25

Example traffic captured:

{
  "src_ip": "127.0.0.xxx",
  "dst_ip": "127.0.0.xxx",
  "transport": "TCP",
  "src_port": 54321,
  "dst_port": 8000,
  "http_request": "GET /test?token=[REDACTED] HTTP/1.1"
}
