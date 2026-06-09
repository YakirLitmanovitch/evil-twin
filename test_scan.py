"""
test_scan.py – Test scanner with channel 36 (where Beacons were found)
"""
from scanner import scan_networks, set_monitor_mode
import subprocess

IFACE = 'wlxe84e06aed7c4'

print(f"[*] Setting monitor mode on {IFACE}...")
set_monitor_mode(IFACE)

# Lock to channel 36 where we know there are Beacons
subprocess.run(["iw", "dev", IFACE, "set", "channel", "36"],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print("[*] Locked to channel 36 (5180 MHz)")

print("[*] Scanning for 30 seconds...")
networks = scan_networks(IFACE, duration=30)

print(f"\n[*] Total networks found: {len(networks)}")
for n in networks:
    print(f"  {n.ssid:30s} {n.bssid}  ch={n.channel}  {n.rssi}dBm  {n.security}")
