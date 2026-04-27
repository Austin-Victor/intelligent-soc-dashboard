"""
network_agent.py — Real-time hybrid IDS Network Monitoring Agent
================================================================
Captures live packets using Scapy, applies 15 detection rules,
saves every alert to SQLite, and streams alerts to the React
dashboard via Flask-SocketIO WebSocket.

Run as Administrator on Windows (required for Npcap promiscuous mode).

Install dependencies first:
    pip install scapy flask flask-cors flask-socketio psutil
"""

import threading
import time
import uuid
import re
from collections import defaultdict
from datetime import datetime

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
import psutil

# Scapy imports — Npcap must be installed on Windows
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw

from database import init_db, insert_alert, get_alerts, get_alert_stats, insert_stats, get_log_entries
from log_parser import parse_and_store

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Global counters ───────────────────────────────────────────────────────────
packets_captured   = 0
start_time         = time.time()
connected_clients  = 0

# Detection tracking dictionaries (reset every 60 seconds)
port_scan_tracker      = defaultdict(set)        # src_ip -> {dst_ports}
syn_flood_tracker      = defaultdict(int)         # src_ip -> SYN count
brute_force_tracker    = defaultdict(lambda: defaultdict(int))  # port -> src_ip -> count
c2_beacon_tracker      = defaultdict(list)        # src_ip:dst_ip -> [timestamps]
dns_payload_tracker    = defaultdict(list)        # src_ip -> [payload sizes]
exfil_tracker          = defaultdict(int)         # src_ip -> bytes out
icmp_flood_tracker     = defaultdict(int)         # src_ip -> ICMP count
lateral_tracker        = defaultdict(set)         # src_ip -> {dst_ips}
arp_table              = {}                       # ip -> mac (persistent)

# Suspicious ports associated with common RATs / pentest frameworks
SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 9999, 6666, 5555, 12345, 54321}

# Brute force target ports
BRUTE_PORTS = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet"}

# Private IP ranges for lateral movement detection
def is_internal(ip: str) -> bool:
    return (ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("172."))


# ── Alert generation ──────────────────────────────────────────────────────────
SEVERITY_MAP = {
    "Port Scan":            "HIGH",
    "SYN Flood":            "CRITICAL",
    "SSH Brute Force":      "CRITICAL",
    "RDP Brute Force":      "CRITICAL",
    "FTP Brute Force":      "HIGH",
    "Telnet Brute Force":   "HIGH",
    "C2 Beaconing":         "CRITICAL",
    "DNS Tunneling":        "HIGH",
    "ARP Spoofing":         "CRITICAL",
    "Lateral Movement":     "CRITICAL",
    "Data Exfiltration":    "CRITICAL",
    "ICMP Flood":           "HIGH",
    "Suspicious Port":      "CRITICAL",
    "SQL Injection":        "CRITICAL",
    "Directory Traversal":  "HIGH",
}

MITRE_MAP = {
    "Port Scan":            "T1046",
    "SYN Flood":            "T1498",
    "SSH Brute Force":      "T1110",
    "RDP Brute Force":      "T1110.001",
    "FTP Brute Force":      "T1110",
    "Telnet Brute Force":   "T1110",
    "C2 Beaconing":         "T1071",
    "DNS Tunneling":        "T1071.004",
    "ARP Spoofing":         "T1557.002",
    "Lateral Movement":     "T1021",
    "Data Exfiltration":    "T1041",
    "ICMP Flood":           "T1498.001",
    "Suspicious Port":      "T1571",
    "SQL Injection":        "T1190",
    "Directory Traversal":  "T1083",
}

RULE_MAP = {
    "Port Scan":            "RULE-001",
    "SYN Flood":            "RULE-002",
    "SSH Brute Force":      "RULE-003",
    "RDP Brute Force":      "RULE-004",
    "FTP Brute Force":      "RULE-005",
    "Telnet Brute Force":   "RULE-006",
    "C2 Beaconing":         "RULE-007",
    "DNS Tunneling":        "RULE-008",
    "ARP Spoofing":         "RULE-009",
    "Lateral Movement":     "RULE-010",
    "Data Exfiltration":    "RULE-011",
    "ICMP Flood":           "RULE-012",
    "Suspicious Port":      "RULE-013",
    "SQL Injection":        "RULE-014",
    "Directory Traversal":  "RULE-015",
}

CONFIDENCE_MAP = {
    "CRITICAL": 0.95,
    "HIGH":     0.82,
    "MEDIUM":   0.65,
    "LOW":      0.50,
}


def generate_alert(threat_type: str, src_ip: str, dst_ip: str = "",
                   src_port: int = 0, dst_port: int = 0,
                   protocol: str = "", description: str = "",
                   confidence_override: float = None) -> dict:
    """Build, save, and emit a structured alert."""
    severity   = SEVERITY_MAP.get(threat_type, "MEDIUM")
    confidence = confidence_override or CONFIDENCE_MAP.get(severity, 0.75)

    alert = {
        "id":          f"{int(time.time())}-{src_ip}-{uuid.uuid4().hex[:6]}",
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threat_type": threat_type,
        "severity":    severity,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "src_port":    src_port,
        "dst_port":    dst_port,
        "protocol":    protocol,
        "description": description or f"{threat_type} detected from {src_ip}",
        "mitre_id":    MITRE_MAP.get(threat_type, ""),
        "rule_id":     RULE_MAP.get(threat_type, ""),
        "confidence":  round(confidence, 3),
        "is_real":     True,
    }

    # Persist to database
    insert_alert(alert)

    # Stream to all connected dashboard clients
    socketio.emit("real_alert", alert)
    print(f"[ALERT] {severity:<8} | {threat_type:<22} | {src_ip} → {dst_ip}")
    return alert


# ── Detection logic ───────────────────────────────────────────────────────────

def detect_port_scan(src_ip, dst_port):
    """RULE-001: >15 unique destination ports per source per minute."""
    port_scan_tracker[src_ip].add(dst_port)
    if len(port_scan_tracker[src_ip]) > 15:
        generate_alert(
            "Port Scan", src_ip,
            description=f"Port scan: {src_ip} contacted {len(port_scan_tracker[src_ip])} unique ports"
        )
        port_scan_tracker[src_ip].clear()


def detect_syn_flood(src_ip, dst_ip, dst_port):
    """RULE-002: >100 SYN packets per source per second window."""
    syn_flood_tracker[src_ip] += 1
    if syn_flood_tracker[src_ip] > 100:
        generate_alert(
            "SYN Flood", src_ip, dst_ip, dst_port=dst_port, protocol="TCP",
            description=f"SYN flood: {syn_flood_tracker[src_ip]} SYNs from {src_ip}"
        )
        syn_flood_tracker[src_ip] = 0


def detect_brute_force(src_ip, dst_ip, dst_port):
    """RULE-003 to 006: >10 connection attempts to brute-force ports per minute."""
    if dst_port in BRUTE_PORTS:
        brute_force_tracker[dst_port][src_ip] += 1
        if brute_force_tracker[dst_port][src_ip] > 10:
            service = BRUTE_PORTS[dst_port]
            generate_alert(
                f"{service} Brute Force", src_ip, dst_ip,
                dst_port=dst_port, protocol="TCP",
                description=f"{service} brute force: {brute_force_tracker[dst_port][src_ip]} attempts from {src_ip}"
            )
            brute_force_tracker[dst_port][src_ip] = 0


def detect_c2_beacon(src_ip, dst_ip):
    """RULE-007: Connection timing std deviation <5s = likely beacon."""
    key = f"{src_ip}:{dst_ip}"
    now = time.time()
    c2_beacon_tracker[key].append(now)

    timestamps = c2_beacon_tracker[key]
    if len(timestamps) >= 8:
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        mean = sum(intervals) / len(intervals)
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5

        if std_dev < 5.0 and mean < 60:
            generate_alert(
                "C2 Beaconing", src_ip, dst_ip,
                description=f"C2 beacon: {src_ip}→{dst_ip} interval std_dev={std_dev:.2f}s",
                confidence_override=round(max(0.7, 1 - (std_dev / 10)), 3)
            )
            c2_beacon_tracker[key] = []


def detect_dns_tunneling(src_ip, payload_size):
    """RULE-008: Average DNS query payload >100 bytes = likely tunneling."""
    dns_payload_tracker[src_ip].append(payload_size)
    if len(dns_payload_tracker[src_ip]) >= 5:
        avg = sum(dns_payload_tracker[src_ip]) / len(dns_payload_tracker[src_ip])
        if avg > 100:
            generate_alert(
                "DNS Tunneling", src_ip,
                protocol="DNS",
                description=f"DNS tunneling: avg payload {avg:.0f} bytes from {src_ip}"
            )
            dns_payload_tracker[src_ip] = []


def detect_arp_spoofing(src_ip, src_mac):
    """RULE-009: MAC address change for a known IP = ARP spoofing."""
    if src_ip in arp_table:
        if arp_table[src_ip] != src_mac:
            generate_alert(
                "ARP Spoofing", src_ip,
                description=f"ARP spoof: IP {src_ip} changed MAC {arp_table[src_ip]} → {src_mac}",
                confidence_override=0.97
            )
    arp_table[src_ip] = src_mac


def detect_lateral_movement(src_ip, dst_ip):
    """RULE-010: Internal host contacting >10 unique internal hosts per minute."""
    if is_internal(src_ip) and is_internal(dst_ip) and src_ip != dst_ip:
        lateral_tracker[src_ip].add(dst_ip)
        if len(lateral_tracker[src_ip]) > 10:
            generate_alert(
                "Lateral Movement", src_ip,
                description=f"Lateral movement: {src_ip} reached {len(lateral_tracker[src_ip])} internal hosts"
            )
            lateral_tracker[src_ip].clear()


def detect_exfiltration(src_ip, byte_count):
    """RULE-011: >50 MB outbound from one source per minute."""
    exfil_tracker[src_ip] += byte_count
    if exfil_tracker[src_ip] > 50 * 1024 * 1024:  # 50 MB
        generate_alert(
            "Data Exfiltration", src_ip,
            description=f"Exfiltration: {src_ip} sent {exfil_tracker[src_ip] // (1024*1024)} MB outbound"
        )
        exfil_tracker[src_ip] = 0


def detect_icmp_flood(src_ip, dst_ip):
    """RULE-012: >50 ICMP packets per source per second window."""
    icmp_flood_tracker[src_ip] += 1
    if icmp_flood_tracker[src_ip] > 50:
        generate_alert(
            "ICMP Flood", src_ip, dst_ip,
            protocol="ICMP",
            description=f"ICMP flood: {icmp_flood_tracker[src_ip]} packets from {src_ip}"
        )
        icmp_flood_tracker[src_ip] = 0


def detect_suspicious_port(src_ip, dst_ip, dst_port):
    """RULE-013: Connection to known malicious / backdoor ports."""
    if dst_port in SUSPICIOUS_PORTS:
        generate_alert(
            "Suspicious Port", src_ip, dst_ip,
            dst_port=dst_port, protocol="TCP",
            description=f"Suspicious port: {src_ip} connected to port {dst_port} on {dst_ip}"
        )


def detect_http_attacks(src_ip, dst_ip, dst_port, payload: str):
    """RULE-014 & 015: SQL injection and directory traversal in HTTP."""
    sql_patterns = ["select ", "union ", "drop ", "insert ", "' or ", "1=1", "--", "xp_", "exec("]
    traversal_patterns = ["../", "..\\", "%2e%2e", "etc/passwd", "windows/system32"]

    payload_lower = payload.lower()

    for pattern in sql_patterns:
        if pattern in payload_lower:
            generate_alert(
                "SQL Injection", src_ip, dst_ip,
                dst_port=dst_port, protocol="HTTP",
                description=f"SQL injection attempt from {src_ip}: pattern '{pattern}'"
            )
            break

    for pattern in traversal_patterns:
        if pattern in payload_lower:
            generate_alert(
                "Directory Traversal", src_ip, dst_ip,
                dst_port=dst_port, protocol="HTTP",
                description=f"Directory traversal attempt from {src_ip}: pattern '{pattern}'"
            )
            break


# ── Packet analysis callback ──────────────────────────────────────────────────

def analyze_packet(pkt):
    """Called for every captured packet. Routes to detection handlers."""
    global packets_captured
    packets_captured += 1

    try:
        # ── ARP layer ──
        if ARP in pkt:
            if pkt[ARP].op == 2:  # ARP reply
                detect_arp_spoofing(pkt[ARP].psrc, pkt[ARP].hwsrc)
            return

        if IP not in pkt:
            return

        src_ip  = pkt[IP].src
        dst_ip  = pkt[IP].dst
        pkt_len = len(pkt)

        # ── ICMP ──
        if ICMP in pkt:
            detect_icmp_flood(src_ip, dst_ip)
            return

        # ── DNS ──
        if UDP in pkt and DNS in pkt and pkt[UDP].dport == 53:
            if DNSQR in pkt:
                qname = pkt[DNSQR].qname
                payload_size = len(qname) if qname else 0
                detect_dns_tunneling(src_ip, payload_size)
            return

        # ── TCP ──
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags    = pkt[TCP].flags

            # Port scan detection (track unique ports contacted)
            detect_port_scan(src_ip, dst_port)

            # SYN flood (SYN flag set, no ACK)
            if flags == 0x02:
                detect_syn_flood(src_ip, dst_ip, dst_port)

            # Brute force on common service ports
            detect_brute_force(src_ip, dst_ip, dst_port)

            # Suspicious backdoor ports
            detect_suspicious_port(src_ip, dst_ip, dst_port)

            # C2 beacon detection (established connections)
            if flags & 0x10:  # ACK flag = established
                detect_c2_beacon(src_ip, dst_ip)

            # HTTP payload analysis
            if Raw in pkt and dst_port in (80, 8080, 8000):
                try:
                    payload = pkt[Raw].load.decode("utf-8", errors="ignore")
                    detect_http_attacks(src_ip, dst_ip, dst_port, payload)
                except Exception:
                    pass

        # ── Lateral movement (any protocol between internal hosts) ──
        detect_lateral_movement(src_ip, dst_ip)

        # ── Data exfiltration (track outbound bytes) ──
        if not is_internal(dst_ip):
            detect_exfiltration(src_ip, pkt_len)

    except Exception as e:
        pass  # Never crash the capture thread


# ── Tracker reset thread ──────────────────────────────────────────────────────

def reset_trackers():
    """Clear all rolling-window counters every 60 seconds."""
    global port_scan_tracker, syn_flood_tracker, brute_force_tracker
    global icmp_flood_tracker, lateral_tracker, exfil_tracker

    while True:
        time.sleep(60)
        port_scan_tracker.clear()
        syn_flood_tracker.clear()
        brute_force_tracker.clear()
        icmp_flood_tracker.clear()
        lateral_tracker.clear()
        exfil_tracker.clear()

        # Save a stats snapshot to the database
        stats = get_alert_stats()
        insert_stats({
            "packets_captured": packets_captured,
            "alerts_total":     stats["total"],
            "alerts_critical":  stats["critical"],
            "false_positives":  0,
            "uptime_seconds":   int(time.time() - start_time),
        })
        print(f"[*] Trackers reset | packets={packets_captured} | alerts={stats['total']}")


# ── Packet capture thread ─────────────────────────────────────────────────────

def start_capture():
    print("[*] Starting packet capture on all interfaces...")
    sniff(
        filter="ip or arp",
        prn=analyze_packet,
        store=False
    )


# ── Flask REST API endpoints ──────────────────────────────────────────────────

@app.route("/api/alerts", methods=["GET"])
def api_get_alerts():
    """GET /api/alerts?limit=100&severity=CRITICAL"""
    limit    = request.args.get("limit", 100, type=int)
    severity = request.args.get("severity", None)
    alerts   = get_alerts(limit=limit, severity=severity)
    return jsonify({"status": "ok", "count": len(alerts), "alerts": alerts})


@app.route("/api/stats", methods=["GET"])
def api_get_stats():
    """GET /api/stats — dashboard summary counts."""
    stats = get_alert_stats()
    stats["uptime_seconds"]   = int(time.time() - start_time)
    stats["packets_captured"] = packets_captured
    return jsonify({"status": "ok", "stats": stats})


@app.route("/api/alerts/<alert_id>", methods=["GET"])
def api_get_alert(alert_id):
    """GET /api/alerts/<id> — single alert detail."""
    alerts = get_alerts(limit=1000)
    match  = next((a for a in alerts if a["alert_id"] == alert_id), None)
    if match:
        return jsonify({"status": "ok", "alert": match})
    return jsonify({"status": "error", "message": "Alert not found"}), 404


@app.route("/api/logs/parse", methods=["POST"])
def api_parse_log():
    data     = request.get_json()
    text     = data.get("text", "")
    filename = data.get("filename", "uploaded")
    result   = parse_and_store(text, filename)
    return jsonify({"status": "ok", **result})


@app.route("/api/logs", methods=["GET"])
def api_get_logs():
    flagged_only = request.args.get("flagged", "false").lower() == "true"
    entries = get_log_entries(limit=200, flagged_only=flagged_only)
    return jsonify({"status": "ok", "entries": entries})


@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check endpoint for the dashboard connection indicator."""
    return jsonify({
        "status":     "online",
        "uptime":     int(time.time() - start_time),
        "packets":    packets_captured,
        "db":         "soc_ids.db",
        "timestamp":  datetime.now().isoformat()
    })


# ── WebSocket events ──────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    global connected_clients
    connected_clients += 1
    print(f"[+] Dashboard connected ({connected_clients} client(s))")
    # Send current stats immediately on connect
    socketio.emit("stats_update", get_alert_stats())


@socketio.on("disconnect")
def on_disconnect():
    global connected_clients
    connected_clients = max(0, connected_clients - 1)
    print(f"[-] Dashboard disconnected ({connected_clients} client(s))")


@socketio.on("request_history")
def on_request_history(data):
    """Client requests recent alert history on load."""
    limit  = data.get("limit", 50) if data else 50
    alerts = get_alerts(limit=limit)
    socketio.emit("alert_history", {"alerts": alerts})


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  SOC Network-Based IDS Agent — Real Backend")
    print("=" * 60)

    # Initialize database
    init_db()

    print("  Detections active:")
    rules = [
        "Port Scan (RULE-001)",       "SYN Flood (RULE-002)",
        "Brute Force SSH/RDP/FTP/Telnet (RULE-003 to 006)",
        "C2 Beaconing (RULE-007)",    "DNS Tunneling (RULE-008)",
        "ARP Spoofing (RULE-009)",    "Lateral Movement (RULE-010)",
        "Data Exfiltration (RULE-011)","ICMP Flood (RULE-012)",
        "Suspicious Port (RULE-013)", "SQL Injection (RULE-014)",
        "Directory Traversal (RULE-015)",
    ]
    for r in rules:
        print(f"    ✓ {r}")
    print("=" * 60)

    # Start tracker reset thread
    t_reset = threading.Thread(target=reset_trackers, daemon=True)
    t_reset.start()

    # Start packet capture thread
    t_capture = threading.Thread(target=start_capture, daemon=True)
    t_capture.start()

    # Start Flask-SocketIO server (blocking)
    print("[*] WebSocket server running on http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False)
