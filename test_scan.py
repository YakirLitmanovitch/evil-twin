"""
test_scan.py – Debug: what does Scapy actually see?
"""
import subprocess
import time
import threading
from scapy.all import sniff, Dot11, Dot11Beacon, RadioTap

IFACE = 'wlxe84e06aed7c4'

# 2.4GHz + 5GHz channels
CHANNELS = list(range(1, 14)) + [36, 40, 44, 48, 52, 56, 60, 64,
                                   100, 104, 108, 112, 116, 132, 136,
                                   140, 149, 153, 157, 161, 165]

stop = threading.Event()
counts = {"total": 0, "dot11": 0, "beacon": 0}

def hopper():
    idx = 0
    while not stop.is_set():
        ch = CHANNELS[idx % len(CHANNELS)]
        subprocess.run(["iw", "dev", IFACE, "set", "channel", str(ch)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        idx += 1
        time.sleep(0.2)

def handle(p):
    counts["total"] += 1
    if p.haslayer(Dot11):
        counts["dot11"] += 1
        dot11 = p[Dot11]
        # Print first 20 Dot11 frames to see what types we get
        if counts["dot11"] <= 20:
            print(f"  Dot11 type={dot11.type} subtype={dot11.subtype} "
                  f"addr1={dot11.addr1} addr2={dot11.addr2}")
    if p.haslayer(Dot11Beacon):
        counts["beacon"] += 1
        try:
            ssid = p[Dot11].payload.payload.info.decode('utf-8', errors='replace')
            print(f"  [BEACON] SSID={ssid}")
        except Exception as e:
            print(f"  [BEACON] parse error: {e}")

print(f"[*] Starting channel hopper...")
t = threading.Thread(target=hopper, daemon=True)
t.start()

print(f"[*] Sniffing for 20 seconds...")
sniff(iface=IFACE, prn=handle, timeout=20, store=False)
stop.set()

print(f"\n[*] Results:")
print(f"    Total packets : {counts['total']}")
print(f"    Dot11 packets : {counts['dot11']}")
print(f"    Beacon frames : {counts['beacon']}")
