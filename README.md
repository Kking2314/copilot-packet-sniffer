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
