from utils.logger import alert

# Add suspicious keywords or payload snippets you want to flag
SUSPICIOUS_STRINGS = [
    b"/bin/bash",
    b"cmd.exe",
    b"evil-payload",
    b"wget",
    b"curl",
    b"powershell",
    b"nc -e",
]

def detect(packet):
    if packet.haslayer("Raw"):
        payload = packet["Raw"].load.lower()
        for s in SUSPICIOUS_STRINGS:
            if s in payload:
                alert(f"PAYLOAD STRING DETECTED: Found suspicious pattern '{s.decode()}' in packet payload")
                break
