"""
test_scan.py – Lock on channel 165 (5825MHz) and listen for Beacons
"""
import subprocess
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap

IFACE = 'wlxe84e06aed7c4'

# Lock to channel 165 (5825 MHz) - where we saw traffic in tcpdump
subprocess.run(["iw", "dev", IFACE, "set", "channel", "165"],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(f"[*] Locked to channel 165 (5825 MHz)")

networks = {}

def handle(p):
    if not p.haslayer(Dot11):
        return

    dot11 = p[Dot11]

    # Beacon = type 0 subtype 8
    if dot11.type == 0 and dot11.subtype == 8:
        bssid = dot11.addr3
        if bssid not in networks:
            try:
                ssid = p[Dot11Elt].info.decode('utf-8', errors='replace').strip()
            except Exception:
                ssid = "<hidden>"
            try:
                rssi = p[RadioTap].dBm_AntSignal
            except Exception:
                rssi = -999
            networks[bssid] = ssid
            print(f"  [BEACON] SSID={ssid:30s} BSSID={bssid}  RSSI={rssi}dBm")

    # Also print Probe Responses (type=0 subtype=5) - contain SSID too
    elif dot11.type == 0 and dot11.subtype == 5:
        bssid = dot11.addr3
        if bssid not in networks:
            try:
                ssid = p[Dot11Elt].info.decode('utf-8', errors='replace').strip()
                networks[bssid] = ssid
                print(f"  [PROBE RESP] SSID={ssid:30s} BSSID={bssid}")
            except Exception:
                pass

print(f"[*] Listening for 30 seconds...")
sniff(iface=IFACE, prn=handle, timeout=30, store=False)

print(f"\n[*] Total networks found: {len(networks)}")
for bssid, ssid in networks.items():
    print(f"    {ssid:30s} {bssid}")
