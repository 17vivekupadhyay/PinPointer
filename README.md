# PinPointer

Network forensics and threat intelligence platform. Captures live traffic, fingerprints suspicious connections, geolocates every remote endpoint, and renders active attack flows as animated arcs on a live world map.

![Dashboard](https://raw.githubusercontent.com/17vivekupadhyay/PinPointer/main/assets/dashboard.png)

---

## What it does

- **Live packet capture** via tshark — works on any interface or replays `.pcap` files
- **Threat fingerprinting** — detects port scans, SSH/RDP brute force, C2 beaconing, and data exfiltration patterns in real time
- **IP geolocation** — enriches every source IP with country, city, ISP, and ASN data
- **Live world map** — animated arc lines trace active attack flows from source to your server
- **Threat scoring** — each connection scored 0–100 across five behavioral signals
- **AWS honeypot** — EC2 instance exposed on port 22 as bait; within hours of deployment receiving brute-force attempts from IP ranges across ------------

---

## Architecture

```
Internet
    │
    ▼
EC2 Honeypot (port 22 open)
    │
    ├── tshark (packet capture)
    │       │
    │       ▼
    │   capture.py ──► analyze.py ──► geolocate.py
    │                                      │
    │                                      ▼
    │                               server.py (Flask + WebSocket)
    │                                      │
    └──────────────────────────────────────▼
                                   Browser Dashboard
                                   (Leaflet map + live feed)

AWS: EC2 · VPC · CloudWatch Logs · VPC Flow Logs · S3 · IAM
```

---

## Threat detection

| Signal | Threshold | Score |
|---|---|---|
| Port scan | 15+ distinct ports in 30s | +40 |
| SSH/RDP brute force | 10+ hits to same port | +50 |
| Suspicious port (C2/Tor) | 4444, 1337, 9050... | +30 |
| High-risk country origin | --------- | +20 |
| Data exfiltration | 5MB+ outbound to single IP | +60 |

Severity levels: **Critical** (60+) · **High** (40+) · **Medium** (20+) · **Low**

---

## Quickstart

**Requirements**
- Python 3.11+
- tshark (`brew install wireshark` on Mac, `apt install tshark` on Linux)

```bash
git clone https://github.com/17vivekupadhyay/PinPointer
cd PinPointer
pip install -r requirements.txt
```

**Demo mode** (no tshark required — streams simulated attack traffic)
```bash
python run.py
```

**Live capture**
```bash
sudo python run.py --live --iface en0
```

**Replay a pcap file**
```bash
python run.py --pcap capture.pcap
```

Open `http://127.0.0.1:8765`

---

## AWS Honeypot Setup

**1. Launch EC2**
- Ubuntu 22.04, t2.micro (free tier)
- Security Group: allow port 22 inbound from `0.0.0.0/0`

**2. Install dependencies**
```bash
ssh -i your-key.pem ubuntu@<ec2-ip>
sudo apt update && sudo apt install -y tshark python3-pip
pip install -r requirements.txt
```

**3. Run PinPointer on the instance**
```bash
sudo python run.py --live --iface eth0 --host 0.0.0.0
```

**4. View dashboard remotely via SSH tunnel**
```bash
ssh -i your-key.pem -L 8765:localhost:8765 ubuntu@<ec2-ip> -N
```

Then open `http://127.0.0.1:8765` on your local machine.

---

## CLI Reference

```
python run.py [OPTIONS]

Options:
  --live          Live capture (requires tshark + root)
  --iface TEXT    Network interface (e.g. en0, eth0)
  --pcap TEXT     Path to .pcap file
  --host TEXT     Bind host (default: 127.0.0.1)
  --port INT      Port (default: 8765)
```

---

## Stack

**Backend** — Python, Flask, Flask-SocketIO, tshark, ip-api.com

**Frontend** — Vanilla JS, Leaflet.js, Socket.IO, Space Mono

**Infrastructure** — AWS EC2, VPC, CloudWatch Logs, VPC Flow Logs, S3, IAM

---

## License

MIT
