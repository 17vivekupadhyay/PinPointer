"""
Packet capture layer.
Supports two modes:
  - live: wraps tshark for real-time capture (requires Wireshark/tshark + sudo/root)
  - pcap: replays a saved .pcap/.pcapng file at full speed
"""

import subprocess
import json
import threading
import time
import os
import re
from typing import Callable


def _parse_tshark_line(line: str) -> dict | None:
    """Parse a single tshark JSON object into a normalised packet dict."""
    try:
        obj = json.loads(line)
        layers = obj.get("_source", {}).get("layers", {})

        ip = layers.get("ip", {})
        ipv6 = layers.get("ipv6", {})
        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})
        eth = layers.get("eth", {})
        frame = layers.get("frame", {})

        src = ip.get("ip.src") or ipv6.get("ipv6.src", "")
        dst = ip.get("ip.dst") or ipv6.get("ipv6.dst", "")
        if not src or not dst:
            return None

        if tcp:
            proto    = "TCP"
            dst_port = int(tcp.get("tcp.dstport", 0))
            src_port = int(tcp.get("tcp.srcport", 0))
            flags    = tcp.get("tcp.flags_tree", {})
        elif udp:
            proto    = "UDP"
            dst_port = int(udp.get("udp.dstport", 0))
            src_port = int(udp.get("udp.srcport", 0))
            flags    = {}
        else:
            proto    = frame.get("frame.protocols", "OTHER").upper().split(":")[-1]
            dst_port = 0
            src_port = 0
            flags    = {}

        length = int(frame.get("frame.len", 0))

        return {
            "src_ip":   src,
            "dst_ip":   dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto":    proto,
            "length":   length,
            "flags":    flags,
        }
    except Exception:
        return None


def _tshark_cmd(interface: str | None, pcap_file: str | None) -> list[str]:
    fields = [
        "-e", "frame.len",
        "-e", "frame.protocols",
        "-e", "ip.src",    "-e", "ip.dst",
        "-e", "ipv6.src",  "-e", "ipv6.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "tcp.flags_tree",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "eth.src",   "-e", "eth.dst",
    ]
    cmd = ["tshark", "-T", "ek", "-n"]  # EK (Elasticsearch/JSON) output
    if pcap_file:
        cmd += ["-r", pcap_file]
    else:
        cmd += ["-i", interface or "any", "-l"]
    return cmd


class PacketCapture:
    def __init__(
        self,
        callback: Callable[[dict], None],
        interface: str | None = None,
        pcap_file: str | None = None,
    ):
        self._cb        = callback
        self._iface     = interface
        self._pcap      = pcap_file
        self._proc      = None
        self._thread    = None
        self._stop_evt  = threading.Event()

    def start(self):
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def _run(self):
        # Demo mode: no interface or pcap specified
        if not self._iface and not self._pcap:
            print("[capture] demo mode — streaming simulated attack traffic")
            self._demo_loop()
            return

        cmd = _tshark_cmd(self._iface, self._pcap)
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            print("[capture] tshark not found — falling back to demo mode")
            self._demo_loop()
            return

        print(f"[capture] tshark started on {self._iface or self._pcap}")
        for line in self._proc.stdout:
            if self._stop_evt.is_set():
                break
            line = line.strip()
            if not line:
                continue
            pkt = _parse_tshark_line(line)
            if pkt:
                self._cb(pkt)

        self._proc.wait()

    def _demo_loop(self):
        """Emit realistic fake packets when tshark isn't available.
        Geo data is pre-baked so no HTTP calls are needed in demo mode."""
        import random
        DEMO_ATTACKERS = [
            {
                "src_ip": "77.104.92.143", "dst_ip": "34.223.4.11",
                "dst_port": 22, "proto": "TCP",
                "geo": {"country": "Iran", "countryCode": "IR", "city": "Tehran",
                        "lat": 35.6892, "lon": 51.3890, "isp": "Respina Networks",
                        "org": "AS48159 Respina", "private": False},
            },
            {
                "src_ip": "218.92.0.112", "dst_ip": "34.223.4.11",
                "dst_port": 22, "proto": "TCP",
                "geo": {"country": "China", "countryCode": "CN", "city": "Shanghai",
                        "lat": 31.2222, "lon": 121.4581, "isp": "Chinanet",
                        "org": "AS4134 Chinanet", "private": False},
            },
            {
                "src_ip": "45.155.204.97", "dst_ip": "34.223.4.11",
                "dst_port": 22, "proto": "TCP",
                "geo": {"country": "Russia", "countryCode": "RU", "city": "Moscow",
                        "lat": 55.7558, "lon": 37.6173, "isp": "PE Ivanov",
                        "org": "AS206728 Media Land", "private": False},
            },
            {
                "src_ip": "103.56.207.22", "dst_ip": "34.223.4.11",
                "dst_port": 443, "proto": "TCP",
                "geo": {"country": "Hong Kong", "countryCode": "HK", "city": "Hong Kong",
                        "lat": 22.3193, "lon": 114.1694, "isp": "Sondercloud",
                        "org": "AS138915 Sondercloud", "private": False},
            },
            {
                "src_ip": "185.234.219.4", "dst_ip": "34.223.4.11",
                "dst_port": 80, "proto": "TCP",
                "geo": {"country": "Netherlands", "countryCode": "NL", "city": "Amsterdam",
                        "lat": 52.3740, "lon": 4.8897, "isp": "Serverius",
                        "org": "AS50673 Serverius", "private": False},
            },
            {
                "src_ip": "36.110.228.254", "dst_ip": "34.223.4.11",
                "dst_port": 22, "proto": "TCP",
                "geo": {"country": "China", "countryCode": "CN", "city": "Beijing",
                        "lat": 39.9042, "lon": 116.4074, "isp": "CNCGROUP",
                        "org": "AS4837 CNCGROUP", "private": False},
            },
            {
                "src_ip": "91.240.118.72", "dst_ip": "34.223.4.11",
                "dst_port": 3389, "proto": "TCP",
                "geo": {"country": "Ukraine", "countryCode": "UA", "city": "Kyiv",
                        "lat": 50.4501, "lon": 30.5234, "isp": "FS LLC",
                        "org": "AS62282 FS LLC", "private": False},
            },
            {
                "src_ip": "5.188.86.195", "dst_ip": "34.223.4.11",
                "dst_port": 22, "proto": "TCP",
                "geo": {"country": "Russia", "countryCode": "RU", "city": "St Petersburg",
                        "lat": 59.9343, "lon": 30.3351, "isp": "PIN LLC",
                        "org": "AS34665 PIN LLC", "private": False},
            },
            {
                "src_ip": "193.32.162.34", "dst_ip": "34.223.4.11",
                "dst_port": 53, "proto": "UDP",
                "geo": {"country": "Germany", "countryCode": "DE", "city": "Frankfurt",
                        "lat": 50.1109, "lon": 8.6821, "isp": "Contabo GmbH",
                        "org": "AS51167 Contabo", "private": False},
            },
            {
                "src_ip": "209.58.183.11", "dst_ip": "34.223.4.11",
                "dst_port": 8080, "proto": "TCP",
                "geo": {"country": "United States", "countryCode": "US", "city": "Ashburn",
                        "lat": 39.0438, "lon": -77.4874, "isp": "Verizon Business",
                        "org": "AS701 Verizon", "private": False},
            },
        ]
        while not self._stop_evt.is_set():
            attacker = random.choice(DEMO_ATTACKERS)
            pkt = {
                "src_ip":   attacker["src_ip"],
                "dst_ip":   attacker["dst_ip"],
                "src_port": random.randint(1024, 65535),
                "dst_port": attacker["dst_port"],
                "proto":    attacker["proto"],
                "length":   random.randint(40, 1500),
                "flags":    {},
                "geo":      attacker["geo"],
            }
            self._cb(pkt)
            time.sleep(random.uniform(0.3, 1.0))
