"""
test_scan.py – Set monitor mode, capture with tcpdump, read with Scapy
"""
import subprocess
import time
from scapy.all import rdpcap, Dot11Beacon, Dot11Elt, RadioTap

IFACE = 'wlxe84e06aed7c4'
PCAP  = '/tmp/capture.pcap'

# Step 1: Set monitor mode
print("[*] Setting monitor mode...")
subprocess.run(["ip",  "link", "set", IFACE, "down"],  check=True)
subprocess.run(["iw",  "dev",  IFACE, "set", "type", "monitor"], check=True)
subprocess.run(["ip",  "link", "set", IFACE, "up"],    check=True)
print("[+] Monitor mode set")

# Step 2: Capture 20 seconds with tcpdump (no channel lock – let it stay where it is)
print("[*] Capturing with tcpdump for 20 seconds...")
proc = subprocess.Popen(
    ["tcpdump", "-i", IFACE, "-w", PCAP],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)
time.sleep(20)
proc.terminate()
proc.wait()
print(f"[+] Capture done.")

# Step 3: Read with Scapy
pkts = rdpcap(PCAP)
print(f"[*] Total packets in file: {len(pkts)}")

beacons = 0
for p in pkts:
    if p.haslayer(Dot11Beacon):
        beacons += 1
        try:
            ssid = p[Dot11Elt].info.decode('utf-8', errors='replace').strip()
            try:
                rssi = p[RadioTap].dBm_AntSignal
            except Exception:
                rssi = -999
            print(f"  [BEACON] {ssid}  rssi={rssi}dBm")
        except Exception as e:
            print(f"  [BEACON] parse error: {e}")

print(f"\n[*] Beacon frames found: {beacons}")
