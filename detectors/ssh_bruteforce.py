from collections import defaultdict
from utils.logger import alert
import time

# Track SSH connection attempts per IP
conn_attempts = defaultdict(list)
THRESHOLD = 10  # Attempts threshold
TIME_WINDOW = 60  # seconds

def detect(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        ip = packet["IP"].src
        tcp = packet["TCP"]

        # SYN packets to port 22 (SSH)
        if tcp.dport == 22 and tcp.flags == "S":
            now = time.time()
            # Keep only recent attempts within TIME_WINDOW
            conn_attempts[ip] = [t for t in conn_attempts[ip] if now - t < TIME_WINDOW]
            conn_attempts[ip].append(now)

            if len(conn_attempts[ip]) > THRESHOLD:
                alert(f"SSH BRUTE-FORCE DETECTED: {ip} made {len(conn_attempts[ip])} SSH connection attempts in {TIME_WINDOW} seconds")
