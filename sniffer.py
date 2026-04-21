import argparse
import json
import re
from scapy.all import sniff, rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw

ALLOWED_INTERFACES = {"lo", "eth0"}

def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".xxx"
    return "[REDACTED_IP]"

def redact_text(text: str) -> str:
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', text)
    text = re.sub(r'Authorization:\s*.*', 'Authorization: [REDACTED_AUTH]', text, flags=re.IGNORECASE)
    text = re.sub(r'Cookie:\s*.*', 'Cookie: [REDACTED_COOKIE]', text, flags=re.IGNORECASE)
    text = re.sub(r'(?i)(password|token|session|auth)=([^&\s]+)', r'\1=[REDACTED]', text)
    return text

def extract_http_line(payload: str):
    lines = payload.splitlines()
    if not lines:
        return None
    first = lines[0]
    if first.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
        return redact_text(first)
    return None

def parse_packet(pkt):
    result = {
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "dns_query": None,
        "http_request": None,
    }

    if IP in pkt:
        result["src_ip"] = mask_ip(pkt[IP].src)
        result["dst_ip"] = mask_ip(pkt[IP].dst)

    if TCP in pkt:
        result["protocol"] = "TCP"
        result["src_port"] = pkt[TCP].sport
        result["dst_port"] = pkt[TCP].dport
    elif UDP in pkt:
        result["protocol"] = "UDP"
        result["src_port"] = pkt[UDP].sport
        result["dst_port"] = pkt[UDP].dport

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            qname = pkt[DNSQR].qname.decode(errors="ignore")
            result["dns_query"] = redact_text(qname)
        except Exception:
            result["dns_query"] = "[UNREADABLE_DNS_QUERY]"

    if pkt.haslayer(Raw):
        try:
            payload = pkt[Raw].load.decode(errors="ignore")
            http_line = extract_http_line(payload)
            if http_line:
                result["http_request"] = http_line
        except Exception:
            pass

    return result

def handle_packet(pkt):
    parsed = parse_packet(pkt)
    print(json.dumps(parsed, indent=2))

def run_live(iface, bpf_filter, count):
    if iface not in ALLOWED_INTERFACES:
        raise ValueError(f"Interface {iface} not allowed")
    sniff(iface=iface, filter=bpf_filter, prn=handle_packet, count=count, store=False)

def run_pcap(path):
    packets = rdpcap(path)
    for pkt in packets:
        handle_packet(pkt)

def main():
    parser = argparse.ArgumentParser(description="Ethical packet sniffer with redaction")
    parser.add_argument("--mode", choices=["live", "pcap"], required=True)
    parser.add_argument("--iface", default="lo")
    parser.add_argument("--filter", default="udp port 53")
    parser.add_argument("--count", type=int, default=25)
    parser.add_argument("--pcap")
    args = parser.parse_args()

    try:
        if args.mode == "live":
            run_live(args.iface, args.filter, args.count)
        else:
            if not args.pcap:
                raise ValueError("PCAP path required in pcap mode")
            run_pcap(args.pcap)
    except PermissionError:
        print("Permission denied for live capture. Use --mode pcap instead.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
