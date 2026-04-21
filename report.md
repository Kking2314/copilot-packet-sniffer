
## What I Captured
I captured only authorized traffic on my own machine using the loopback interface (`lo`) and local test traffic. I generated traffic with a local Python web server and `curl`. I also tested the tool in pcap mode using a saved capture file.

## What I Decoded
The tool decoded:
- IP addresses
- TCP and UDP ports
- DNS query names when present
- HTTP request lines for plaintext traffic

## What I Redacted and Why
I masked IP addresses partially to reduce exposure of full host information. I also redacted:
- email addresses
- Authorization headers
- cookies
- query-string secrets such as `token=` and `password=`

I did this because packet sniffers can expose sensitive data, and the project requires ethical guardrails.

## Copilot Reflection
I used Copilot for boilerplate structure, CLI setup ideas, and test scaffolding. I rejected or modified suggestions that were too broad or unsafe. For example, I kept an interface allowlist, added redaction before output, and supported pcap mode in case live capture permissions were unavailable.

## Risks and Defender Detection
Packet sniffers are powerful because they can reveal metadata and sometimes sensitive content in unencrypted traffic. Defenders can detect misuse by monitoring for unauthorized packet capture tools, unusual privilege use, suspicious promiscuous-mode behavior, and unexpected access to network interfaces.
