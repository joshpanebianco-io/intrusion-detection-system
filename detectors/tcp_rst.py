from utils.logger import alert

def detect(packet):
    if packet.haslayer("TCP"):
        tcp = packet["TCP"]
        ip = packet["IP"].src

        if tcp.flags == "R":
            alert(f"TCP RESET ATTACK DETECTED: RST packet from {ip} on port {tcp.sport}")
