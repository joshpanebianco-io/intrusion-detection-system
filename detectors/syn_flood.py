# detectors/syn_flood.py
from collections import defaultdict
from utils.logger import alert
import time

syn_map = defaultdict(list)
THRESHOLD = 20  # SYNs per IP in 2 sec

def detect(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        ip = packet["IP"].src
        tcp = packet["TCP"]

        if tcp.flags == "S":
            now = time.time()
            syn_map[ip] = [t for t in syn_map[ip] if now - t < 2]
            syn_map[ip].append(now)

            if len(syn_map[ip]) > THRESHOLD:
                alert(f"SYN FLOOD DETECTED: {ip} sent {len(syn_map[ip])} SYNs in 2 sec")
