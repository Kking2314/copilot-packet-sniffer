## What I Captured
I captured live network traffic using the en0 interface.
Traffic included DNS queries and HTTP requests generated using curl and ping.

## What I Redacted
- IP addresses (masked last octet)
- Emails
- Authorization headers
- Cookies/session tokens
- Query parameters like password and token

## Why Redaction Matters
Packet sniffers can expose sensitive data such as credentials and session tokens. Redaction ensures ethical and safe usage.

## Copilot Reflection
Copilot helped with:
- CLI parsing
- JSON formatting
- regex for redaction

I rejected:
- unsafe suggestions without redaction
- unrestricted packet capture

## Risks of Packet Sniffers
- Can capture private user data
- Can expose login credentials
- Used in attacks like MITM

## How Defenders Detect Misuse
- Monitoring unusual traffic
- Detecting promiscuous mode
- IDS systems
