# detectors/port_scan.py
from collections import defaultdict
from utils.logger import alert

scan_map = defaultdict(set)
THRESHOLD = 10  # Unique ports per IP

def detect(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        ip = packet["IP"].src
        dport = packet["TCP"].dport

        scan_map[ip].add(dport)
        if len(scan_map[ip]) > THRESHOLD:
            alert(f"PORT SCAN DETECTED: {ip} hit {len(scan_map[ip])} ports")
