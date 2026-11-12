# Android Club R&D — Network Analysis

A small Python script that analyzes a classic PCAP capture without third-party libraries.

## Features
- Counts total captured packets.
- Extracts IPv4 source and destination addresses.
- Lists unique IPv4 addresses.
- Counts IPv4 packets by protocol (ICMP, TCP, UDP, and other protocol numbers).
- Detects IPv4 fragmented packets.
- Supports Ethernet II (including VLAN tags) and raw IPv4 link types.

## Requirements
- Python 3.8 or newer
- No external packages required

## Usage
Place `network_analyzer.py` and the supplied capture file in the same folder, then run:

```bash
python network_analyzer.py ipv4frags.pcap
```

## Results for the supplied `ipv4frags.pcap`
- Total captured packets: 3
- IPv4 packets analyzed: 3
- Unique IPv4 addresses: 2 (`2.1.1.1`, `2.1.1.2`)
- Fragmented IPv4 packets: 2
- ICMP: 3
- TCP: 0
- UDP: 0

The capture contains ICMP traffic, so zero TCP and UDP packets is the correct result for this file. Fragment count refers to individual fragmented IPv4 packets, not reassembled datagrams.

## Files
- `network_analyzer.py` — analysis script
