from collections import defaultdict
from utils.logger import alert
import time

# Track connection timestamps keyed by (source IP, destination IP, destination port)
conn_times = defaultdict(list)

THRESHOLD = 5        # Number of repeated connections to trigger alert
TIME_WINDOW = 60     # Time window in seconds to check repetition

def detect(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        dst_port = packet["TCP"].dport
        now = time.time()

        key = (src_ip, dst_ip, dst_port)
        conn_times[key] = [t for t in conn_times[key] if now - t < TIME_WINDOW]
        conn_times[key].append(now)

        if len(conn_times[key]) > THRESHOLD:
            alert(f"C2 BEACONING SUSPECTED: {src_ip} made {len(conn_times[key])} connections to {dst_ip}:{dst_port} in {TIME_WINDOW}s")
