from collections import defaultdict
from scapy.layers.l2 import ARP
from utils.logger import alert

# IP -> set of MAC addresses claiming to be this IP
arp_map = defaultdict(set)

def detect(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply (is-at)
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        arp_map[ip].add(mac)
        if len(arp_map[ip]) > 1:
            alert(f"ARP SPOOFING DETECTED: Multiple MACs {arp_map[ip]} claiming IP {ip}")
