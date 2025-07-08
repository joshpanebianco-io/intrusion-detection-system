from scapy.layers.dns import DNS, DNSQR
from utils.logger import alert
import re

def is_suspicious_dns(name: str) -> bool:
    """
    Basic heuristic to detect DNS tunneling by:
    - Checking for unusually long domain names
    - Checking if domain looks base64 encoded or has many subdomains
    """
    # Remove trailing dot if present
    name = name.rstrip('.')

    # Length check
    if len(name) > 50:
        return True

    # Count dots (subdomains)
    if name.count('.') > 5:
        return True

    # Check for base64-like content (simple regex)
    base64_chars = re.compile(r'^[A-Za-z0-9+/=]+$')
    # Remove dots for this check
    stripped = name.replace('.', '')
    if base64_chars.match(stripped) and len(stripped) > 20:
        return True

    return False

def detect(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        dns_query = packet[DNSQR].qname.decode(errors='ignore')
        if is_suspicious_dns(dns_query):
            alert(f"DNS TUNNELING SUSPECTED: Suspicious DNS query '{dns_query}'")
