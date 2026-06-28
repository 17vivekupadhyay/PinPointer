#!/usr/bin/env python3
"""
PinPointer — Network Forensics & Threat Intelligence Dashboard
Usage:
  python run.py                        # demo mode (no tshark needed)
  python run.py --live                 # live capture on default interface
  python run.py --iface eth0           # live capture on specific interface
  python run.py --pcap traffic.pcap    # replay a saved capture file
  python run.py --port 8080            # run on a different port
"""

import argparse
import server


def main():
    parser = argparse.ArgumentParser(description="PinPointer Network Forensics Dashboard")
    parser.add_argument("--live",  action="store_true", help="Live capture (requires tshark + root)")
    parser.add_argument("--iface", default=None, help="Network interface for live capture")
    parser.add_argument("--pcap",  default=None, help="Path to a .pcap file to analyse")
    parser.add_argument("--host",  default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port",  default=8765, type=int, help="Port (default: 8765)")
    args = parser.parse_args()

    iface = args.iface if (args.live or args.iface) else None

    server.start(
        interface=iface,
        pcap_file=args.pcap,
        host=args.host,
        port=args.port,
    )


if __name__ == "__main__":
    main()
