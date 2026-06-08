"""
test_scan.py – Quick scan test with channel hopping (temporary debug file)
"""
from scanner import scan_networks, set_monitor_mode

IFACE = 'wlxe84e06aed7c4'

print(f"[*] Setting {IFACE} to monitor mode...")
set_monitor_mode(IFACE)

print(f"[*] Scanning for 30 seconds with channel hopping (2.4GHz + 5GHz)...")
networks = scan_networks(IFACE, duration=30)

print(f"\n[*] Total networks found: {len(networks)}")
for n in networks:
    print(f"  {n.ssid:30s} {n.bssid}  ch={n.channel}  {n.rssi}dBm  {n.security}")
