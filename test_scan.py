"""
test_scan.py – Quick scan test (temporary debug file)
"""
from scapy.all import sniff, Dot11Beacon

found = []

def handle(p):
    if p.haslayer(Dot11Beacon):
        try:
            ssid = p.info.decode('utf-8', errors='replace').strip()
        except Exception:
            ssid = "<unknown>"
        if ssid not in found:
            found.append(ssid)
            print(f"[+] Found: {ssid}")

print("[*] Scanning for 15 seconds on wlxe84e06aed7c4...")
sniff(iface='wlxe84e06aed7c4', prn=handle, timeout=15, store=False)
print(f"\n[*] Total networks found: {len(found)}")
