#!/usr/bin/env python3
"""
Simple PCAP Network Analyzer
----------------------------
Reads a classic .pcap file (Ethernet or raw IPv4) without third-party packages.
Reports packet totals, unique IPv4 addresses, TCP/UDP/ICMP counts, and
IPv4 fragmentation details.

Usage:
    python network_analyzer.py ipv4frags.pcap
"""

import argparse
import socket
import struct
from collections import Counter


def read_pcap(filename):
    """Yield captured packet bytes from a classic PCAP file."""
    with open(filename, "rb") as capture:
        header = capture.read(24)
        if len(header) != 24:
            raise ValueError("File is too small to contain a PCAP header.")

        magic = header[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": "<",  # little-endian, microseconds
            b"\xa1\xb2\xc3\xd4": ">",  # big-endian, microseconds
            b"\x4d\x3c\xb2\xa1": "<",  # little-endian, nanoseconds
            b"\xa1\xb2\x3c\x4d": ">",  # big-endian, nanoseconds
        }
        if magic not in formats:
            raise ValueError("Unsupported file: expected a classic .pcap file.")

        endian = formats[magic]
        link_type = struct.unpack(endian + "I", header[20:24])[0]

        while True:
            packet_header = capture.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("Incomplete packet header in PCAP file.")

            seconds, fraction, captured_len, original_len = struct.unpack(
                endian + "IIII", packet_header
            )
            packet = capture.read(captured_len)
            if len(packet) != captured_len:
                raise ValueError("Incomplete packet data in PCAP file.")

            yield packet, link_type


def analyze_packet(packet, link_type, stats):
    """Extract IPv4 information and update aggregate statistics."""
    # Common link types: 1 = Ethernet, 101 = raw IP, 228 = IPv4.
    if link_type == 1:  # Ethernet II
        if len(packet) < 14:
            stats["non_ipv4_or_unparsed"] += 1
            return
        ether_type = struct.unpack("!H", packet[12:14])[0]
        offset = 14

        # Support VLAN-tagged Ethernet frames.
        while ether_type in (0x8100, 0x88A8, 0x9100):
            if len(packet) < offset + 4:
                stats["non_ipv4_or_unparsed"] += 1
                return
            ether_type = struct.unpack("!H", packet[offset + 2:offset + 4])[0]
            offset += 4

        if ether_type != 0x0800:
            stats["non_ipv4_or_unparsed"] += 1
            return
    elif link_type in (101, 228):  # Raw IP / IPv4
        offset = 0
    else:
        stats["non_ipv4_or_unparsed"] += 1
        return

    if len(packet) < offset + 20:
        stats["non_ipv4_or_unparsed"] += 1
        return

    ip = packet[offset:]
    version = ip[0] >> 4
    header_length = (ip[0] & 0x0F) * 4
    if version != 4 or header_length < 20 or len(ip) < header_length:
        stats["non_ipv4_or_unparsed"] += 1
        return

    protocol = ip[9]
    source_ip = socket.inet_ntoa(ip[12:16])
    destination_ip = socket.inet_ntoa(ip[16:20])

    stats["ipv4_packets"] += 1
    stats["source_ips"].add(source_ip)
    stats["destination_ips"].add(destination_ip)
    stats["all_ips"].update((source_ip, destination_ip))
    stats["protocols"][protocol] += 1

    # Fragment offset is stored in 8-byte units; MF is the lowest flag bit.
    flags_and_offset = struct.unpack("!H", ip[6:8])[0]
    more_fragments = bool(flags_and_offset & 0x2000)
    fragment_offset = flags_and_offset & 0x1FFF
    if more_fragments or fragment_offset != 0:
        stats["fragmented_ipv4_packets"] += 1


def main():
    parser = argparse.ArgumentParser(
        description="Count packets, IPv4 addresses, protocols, and fragments."
    )
    parser.add_argument("pcap_file", help="Path to the input .pcap file")
    args = parser.parse_args()

    stats = {
        "total_packets": 0,
        "ipv4_packets": 0,
        "non_ipv4_or_unparsed": 0,
        "source_ips": set(),
        "destination_ips": set(),
        "all_ips": set(),
        "protocols": Counter(),
        "fragmented_ipv4_packets": 0,
    }

    try:
        for packet, link_type in read_pcap(args.pcap_file):
            stats["total_packets"] += 1
            analyze_packet(packet, link_type, stats)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    print("\n========== PCAP NETWORK ANALYSIS ==========")
    print(f"File: {args.pcap_file}")
    print(f"Total captured packets: {stats['total_packets']}")
    print(f"IPv4 packets analyzed: {stats['ipv4_packets']}")
    print(f"Non-IPv4/unparsed packets: {stats['non_ipv4_or_unparsed']}")
    print(f"Unique IPv4 addresses: {len(stats['all_ips'])}")
    print("IP addresses:", ", ".join(sorted(stats["all_ips"])) or "None")
    print(f"Unique source IPs: {len(stats['source_ips'])}")
    print(f"Unique destination IPs: {len(stats['destination_ips'])}")
    print(f"Fragmented IPv4 packets: {stats['fragmented_ipv4_packets']}")
    print("\nProtocol counts (IPv4):")
    for number, count in sorted(stats["protocols"].items()):
        name = protocol_names.get(number, f"Other (protocol {number})")
        print(f"  {name}: {count}")
    print("\nNote: TCP and UDP counts are based on the IPv4 protocol field.")
    print("Fragmented packets are counted as packets, not reassembled datagrams.")
    print("===========================================\n")


if __name__ == "__main__":
    main()
