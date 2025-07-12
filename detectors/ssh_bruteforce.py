from collections import defaultdict
from utils.logger import alert
import time
import threading
import re

# Network-based brute force detection
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
            conn_attempts[ip] = [t for t in conn_attempts[ip] if now - t < TIME_WINDOW]
            conn_attempts[ip].append(now)

            if len(conn_attempts[ip]) > THRESHOLD:
                alert(f"SSH BRUTE-FORCE DETECTED: {ip} made {len(conn_attempts[ip])} SSH connection attempts in {TIME_WINDOW} seconds")

# Log file-based successful login detection
def monitor_ssh_log(log_path="/var/log/auth.log"):
    pattern = re.compile(r'Accepted password for (\w+) from ([\d\.]+)')
    with open(log_path, "r") as f:
        f.seek(0, 2)  # Move to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            match = pattern.search(line)
            if match:
                user, ip = match.groups()
                alert(f"SSH LOGIN SUCCESS: User '{user}' logged in from IP {ip}")

# Run the log monitor in a separate thread
log_monitor_thread = threading.Thread(target=monitor_ssh_log, daemon=True)
log_monitor_thread.start()