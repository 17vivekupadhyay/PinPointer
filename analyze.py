"""
Threat fingerprinting engine.
Scores and classifies connections based on behavior patterns.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field

# Ports commonly targeted in brute-force / recon
BRUTE_FORCE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC",
                     21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP"}
SUSPICIOUS_PORTS   = {4444, 1337, 31337, 6667, 6660, 8443, 9001, 9050}  # C2/Tor
HIGH_RISK_COUNTRIES = {"Iran", "North Korea", "Russia", "China"}
SCAN_THRESHOLD     = 15   # distinct dst ports in SCAN_WINDOW seconds = port scan
BRUTE_THRESHOLD    = 10   # repeated hits to same brute-force port in BRUTE_WINDOW
SCAN_WINDOW        = 30
BRUTE_WINDOW       = 60
EXFIL_BYTES        = 5_000_000  # 5 MB outbound to single IP triggers flag


@dataclass
class ConnectionState:
    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float  = field(default_factory=time.time)
    packets: int      = 0
    bytes_out: int    = 0
    dst_ports: set    = field(default_factory=set)
    port_hits: dict   = field(default_factory=lambda: defaultdict(int))
    threat_tags: list = field(default_factory=list)
    score: int        = 0


class ThreatAnalyzer:
    def __init__(self):
        self._states: dict[str, ConnectionState] = {}
        self._lock = __import__("threading").Lock()

    def ingest(self, pkt: dict) -> dict:
        """
        Accept a parsed packet dict and return an enriched event dict
        with threat score and tags.
        """
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        dst_port = pkt.get("dst_port", 0)
        length = pkt.get("length", 0)
        proto = pkt.get("proto", "TCP")
        country = pkt.get("geo", {}).get("country", "")
        now = time.time()

        with self._lock:
            if src not in self._states:
                self._states[src] = ConnectionState(ip=src)
            st = self._states[src]

        st.last_seen = now
        st.packets  += 1
        st.bytes_out += length
        if dst_port:
            st.dst_ports.add(dst_port)
            st.port_hits[dst_port] += 1

        tags = []
        score = 0

        # --- Port scan detection ---
        recent_ports = {p for p in st.dst_ports}
        if len(recent_ports) >= SCAN_THRESHOLD:
            tags.append("PORT_SCAN")
            score += 40

        # --- Brute-force detection ---
        for port, label in BRUTE_FORCE_PORTS.items():
            if st.port_hits.get(port, 0) >= BRUTE_THRESHOLD:
                tags.append(f"BRUTE_{label}")
                score += 50

        # --- Suspicious port ---
        if dst_port in SUSPICIOUS_PORTS:
            tags.append("SUSPICIOUS_PORT")
            score += 30

        # --- High-risk country ---
        if country in HIGH_RISK_COUNTRIES:
            tags.append("HIGH_RISK_COUNTRY")
            score += 20

        # --- Data exfiltration ---
        if st.bytes_out >= EXFIL_BYTES:
            tags.append("EXFIL")
            score += 60

        # Deduplicate tags against what's already recorded
        new_tags = [t for t in tags if t not in st.threat_tags]
        st.threat_tags.extend(new_tags)
        st.score = max(st.score, score)

        severity = "critical" if score >= 60 else "high" if score >= 40 else \
                   "medium"   if score >= 20 else "low"

        return {
            "src_ip":      src,
            "dst_ip":      dst,
            "dst_port":    dst_port,
            "proto":       proto,
            "length":      length,
            "score":       score,
            "severity":    severity,
            "tags":        tags,
            "packets":     st.packets,
            "bytes_out":   st.bytes_out,
            "geo":         pkt.get("geo", {}),
            "timestamp":   now,
        }

    def snapshot(self) -> list[dict]:
        """Return current state of all tracked IPs for the dashboard."""
        with self._lock:
            return [
                {
                    "ip":        s.ip,
                    "packets":   s.packets,
                    "bytes_out": s.bytes_out,
                    "score":     s.score,
                    "tags":      s.threat_tags,
                    "ports":     sorted(s.dst_ports)[-20:],
                }
                for s in sorted(self._states.values(), key=lambda x: -x.score)
            ]

    def clear_old(self, max_age: float = 300):
        """Evict states not seen in the last max_age seconds."""
        cutoff = time.time() - max_age
        with self._lock:
            stale = [ip for ip, s in self._states.items() if s.last_seen < cutoff]
            for ip in stale:
                del self._states[ip]
