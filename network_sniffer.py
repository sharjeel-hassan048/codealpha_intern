#!/usr/bin/env python3
"""
Task 1: Basic Network Sniffer
-----------------------------
Captures network packets with Scapy and displays:
  - Source / destination IP addresses (and MAC addresses)
  - Protocol (TCP, UDP, ICMP, ARP, ...)
  - Ports, TCP flags
  - Payload (hex + printable ASCII preview)

Usage examples (run with admin/root privileges):
  sudo python3 network_sniffer.py
  sudo python3 network_sniffer.py -c 20
  sudo python3 network_sniffer.py -i eth0 -f "tcp port 80"
  sudo python3 network_sniffer.py -c 50 -w capture.pcap

Install:  pip install scapy
Windows:  also install Npcap (https://npcap.com) and run as Administrator.

Only capture traffic on networks you own or are authorised to monitor.
"""

import argparse
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import (
        sniff, wrpcap, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNSQR, Raw
    )
except ImportError:
    sys.exit("Scapy is required. Install it with:  pip install scapy")

# IP protocol numbers -> names (fallback when no higher-layer is decoded)
PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP"}

packet_count = 0
protocol_stats = Counter()
captured_packets = []


def format_payload(data: bytes, max_bytes: int = 64) -> str:
    """Return a hex dump and an ASCII preview of the payload."""
    chunk = data[:max_bytes]
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    more = f" ... (+{len(data) - max_bytes} more bytes)" if len(data) > max_bytes else ""
    return f"    Hex  : {hex_part}{more}\n    ASCII: {ascii_part}{more}"


def tcp_flags(pkt) -> str:
    names = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}
    return ",".join(names.get(f, f) for f in str(pkt[TCP].flags)) or "-"


def process_packet(pkt):
    """Callback run for every captured packet: parse it and print the details."""
    global packet_count
    packet_count += 1
    captured_packets.append(pkt)

    timestamp = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
    print(f"\n{'=' * 70}")
    print(f"Packet #{packet_count}  |  {timestamp}  |  {len(pkt)} bytes")
    print("-" * 70)

    # ---- Layer 2 (Ethernet) ----
    if pkt.haslayer(Ether):
        print(f"  MAC  : {pkt[Ether].src}  ->  {pkt[Ether].dst}")

    # ---- Layer 3 (Network) ----
    protocol = "OTHER"
    if pkt.haslayer(IP):
        ip = pkt[IP]
        protocol = PROTO_NAMES.get(ip.proto, f"IP-proto-{ip.proto}")
        print(f"  IP   : {ip.src}  ->  {ip.dst}   (TTL={ip.ttl})")
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        protocol = PROTO_NAMES.get(ip6.nh, f"IPv6-nh-{ip6.nh}")
        print(f"  IPv6 : {ip6.src}  ->  {ip6.dst}")
    elif pkt.haslayer(ARP):
        arp = pkt[ARP]
        protocol = "ARP"
        op = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
        print(f"  ARP  : {arp.psrc} ({arp.hwsrc})  ->  {arp.pdst} ({arp.hwdst})  [{op}]")

    # ---- Layer 4 (Transport) ----
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        protocol = "TCP"
        print(f"  TCP  : port {t.sport}  ->  {t.dport}   flags=[{tcp_flags(pkt)}]  seq={t.seq}")
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        protocol = "UDP"
        print(f"  UDP  : port {u.sport}  ->  {u.dport}   len={u.len}")
    elif pkt.haslayer(ICMP):
        ic = pkt[ICMP]
        protocol = "ICMP"
        print(f"  ICMP : type={ic.type} code={ic.code}")

    # ---- Application layer hints ----
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname
        qname = qname.decode(errors="ignore") if isinstance(qname, bytes) else str(qname)
        print(f"  DNS  : query for {qname}")
    if pkt.haslayer(TCP):
        ports = {pkt[TCP].sport, pkt[TCP].dport}
        if 80 in ports:
            protocol = "HTTP"
        elif 443 in ports:
            protocol = "HTTPS/TLS"
    if pkt.haslayer(UDP) and 53 in {pkt[UDP].sport, pkt[UDP].dport}:
        protocol = "DNS"

    print(f"  Protocol: {protocol}")
    protocol_stats[protocol] += 1

    # ---- Payload ----
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        print(f"  Payload ({len(payload)} bytes):")
        print(format_payload(payload))
    else:
        print("  Payload: none")


def print_summary():
    print(f"\n{'#' * 70}\nCapture summary: {packet_count} packets\n{'#' * 70}")
    for proto, count in protocol_stats.most_common():
        print(f"  {proto:<12} {count:>5}  ({count / packet_count * 100:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Basic network sniffer (Scapy)")
    parser.add_argument("-i", "--interface", help="Interface to sniff on (default: Scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 80" or "icmp"')
    parser.add_argument("-w", "--write", help="Save captured packets to a .pcap file")
    args = parser.parse_args()

    print("[*] Starting sniffer... press Ctrl+C to stop.")
    if args.interface:
        print(f"[*] Interface: {args.interface}")
    if args.filter:
        print(f"[*] Filter   : {args.filter}")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=process_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        sys.exit("[!] Permission denied. Run as root/Administrator (e.g. with sudo).")
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # e.g. missing libpcap/Npcap, bad interface name
        sys.exit(f"[!] Capture failed: {exc}")

    if packet_count:
        print_summary()
        if args.write:
            wrpcap(args.write, captured_packets)
            print(f"[*] Saved {packet_count} packets to {args.write}")
    else:
        print("\n[*] No packets captured.")


if __name__ == "__main__":
    main()