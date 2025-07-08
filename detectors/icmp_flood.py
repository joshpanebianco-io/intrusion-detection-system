from collections import defaultdict
from utils.logger import alert
import time

icmp_map = defaultdict(list)
THRESHOLD = 30  # Number of ICMP Echo Requests per IP in TIME_WINDOW
TIME_WINDOW = 5  # Seconds

def detect(packet):
    if packet.haslayer("ICMP") and packet["ICMP"].type == 8:  # Echo Request
        ip = packet["IP"].src
        now = time.time()

        icmp_map[ip] = [t for t in icmp_map[ip] if now - t < TIME_WINDOW]
        icmp_map[ip].append(now)

        if len(icmp_map[ip]) > THRESHOLD:
            alert(f"ICMP FLOOD DETECTED: {ip} sent {len(icmp_map[ip])} ICMP Echo Requests in {TIME_WINDOW} seconds")
