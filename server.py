"""
Flask + SocketIO server.
Bridges the capture/analysis pipeline to the browser dashboard in real time.
"""

import os
import time
import threading
import queue
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

from capture import PacketCapture
from analyze import ThreatAnalyzer
from geolocate import geolocate

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

analyzer    = ThreatAnalyzer()
event_queue = queue.Queue(maxsize=500)

_stats = {
    "total_events": 0,
    "total_packets": 0,
    "total_bytes": 0,
    "blocked": 0,
    "unique_ips": set(),
    "countries": set(),
}
_stats_lock = threading.Lock()

capture: PacketCapture | None = None


def _on_packet(pkt: dict):
    """Called by capture thread for every parsed packet."""
    # Use pre-baked geo (demo mode) or look it up live (tshark mode)
    geo = pkt.get("geo") or geolocate(pkt["src_ip"])
    pkt["geo"] = geo

    # Skip purely private/loopback traffic (LAN monitoring noise)
    if geo.get("private") and pkt["src_ip"] not in ("", None):
        src = pkt["src_ip"]
        if src.startswith(("10.", "192.168.", "127.", "::1")):
            return

    event = analyzer.ingest(pkt)

    with _stats_lock:
        _stats["total_packets"] += 1
        _stats["total_bytes"]   += pkt.get("length", 0)
        _stats["total_events"]  += 1
        _stats["unique_ips"].add(pkt["src_ip"])
        country = geo.get("country", "")
        if country and country not in ("Private", "Unknown"):
            _stats["countries"].add(country)
        if event["score"] >= 60:
            _stats["blocked"] += 1

    try:
        event_queue.put_nowait(event)
    except queue.Full:
        pass


def _emit_loop():
    """Background task: drain event_queue and push to browser via SocketIO."""
    tick = 0
    while True:
        try:
            event = event_queue.get(timeout=0.5)
            socketio.emit("event", event)
        except queue.Empty:
            pass

        tick += 1
        if tick % 4 == 0:
            with _stats_lock:
                stats_payload = {
                    "total_events":  _stats["total_events"],
                    "total_packets": _stats["total_packets"],
                    "total_bytes":   _stats["total_bytes"],
                    "blocked":       _stats["blocked"],
                    "unique_ips":    len(_stats["unique_ips"]),
                    "countries":     len(_stats["countries"]),
                }
            socketio.emit("stats", stats_payload)
            socketio.emit("snapshot", analyzer.snapshot())


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    with _stats_lock:
        return jsonify({
            "total_events":  _stats["total_events"],
            "total_packets": _stats["total_packets"],
            "total_bytes":   _stats["total_bytes"],
            "blocked":       _stats["blocked"],
            "unique_ips":    len(_stats["unique_ips"]),
            "countries":     len(_stats["countries"]),
        })


@app.route("/api/snapshot")
def api_snapshot():
    return jsonify(analyzer.snapshot())


@socketio.on("connect")
def on_connect():
    with _stats_lock:
        socketio.emit("stats", {
            "total_events":  _stats["total_events"],
            "total_packets": _stats["total_packets"],
            "total_bytes":   _stats["total_bytes"],
            "blocked":       _stats["blocked"],
            "unique_ips":    len(_stats["unique_ips"]),
            "countries":     len(_stats["countries"]),
        }, to=request.sid)
    socketio.emit("snapshot", analyzer.snapshot(), to=request.sid)


# ── Entry point ──────────────────────────────────────────────────────────────

def start(interface=None, pcap_file=None, host="0.0.0.0", port=8765):
    global capture

    socketio.start_background_task(_emit_loop)

    capture = PacketCapture(
        callback=_on_packet,
        interface=interface,
        pcap_file=pcap_file,
    )
    capture.start()

    print(f"\n  PinPointer listening on http://{host}:{port}\n")
    socketio.run(app, host=host, port=port, debug=False)
