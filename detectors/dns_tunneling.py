from scapy.layers.dns import DNS, DNSQR
from utils.logger import alert
import re

# Known safe domains (add more as needed)
SAFE_DOMAINS = [
    "microsoft.com",
    "azure.com",
    "windows.com",
    "msftconnecttest.com",
    "msedge.net"
]

def is_whitelisted(domain: str) -> bool:
    for safe in SAFE_DOMAINS:
        if safe in domain:
            return True
    return False

def is_suspicious_dns(name: str) -> bool:
    """
    Refined heuristic to detect DNS tunneling:
    - Excludes known safe domains
    - Triggers on unusually long, complex, or encoded-looking domains
    """
    name = name.rstrip('.')

    # Whitelist check first
    if is_whitelisted(name):
        return False

    # Length check — allow longer names than before
    if len(name) > 100:
        return True

    # Dot count (subdomains) — relax threshold
    if name.count('.') > 8:
        return True

    # Base64-like detection — looser check
    stripped = name.replace('.', '')
    base64_chars = re.compile(r'^[A-Za-z0-9+/=]{20,}$')
    if base64_chars.match(stripped):
        return True

    return False

def detect(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        dns_query = packet[DNSQR].qname.decode(errors='ignore').lower()
        if is_suspicious_dns(dns_query):
            alert(f"DNS TUNNELING SUSPECTED: Suspicious DNS query '{dns_query}'")
