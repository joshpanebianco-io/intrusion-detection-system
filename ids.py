from scapy.all import sniff
from detectors import (
    port_scan,
    syn_flood,
    icmp_flood,
    tcp_rst,
    ssh_bruteforce,
    arp_spoof,
    payload_strings,
    dns_tunneling,
    c2_beacon
)

def process_packet(packet):
    port_scan.detect(packet)
    syn_flood.detect(packet)
    icmp_flood.detect(packet)
    tcp_rst.detect(packet)
    ssh_bruteforce.detect(packet)
    arp_spoof.detect(packet)
    payload_strings.detect(packet)
    dns_tunneling.detect(packet)
    c2_beacon.detect(packet)

if __name__ == "__main__":
    print("[*] Starting Lightweight IDS with advanced detectors...")
    try:
        sniff(filter="ip or arp or udp port 53", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[!] IDS stopped by user")
