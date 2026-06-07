"""
scanner.py – Network Discovery Module
--------------------------------------
Puts the wireless interface into Monitor Mode and listens for Beacon Frames.
Extracts: SSID, BSSID, Channel, Signal Strength (RSSI), and Security type.

Stage 1 of the Evil Twin attack: Network Discovery.
"""

import threading
import time
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.dot11 import Dot11EltRates, Dot11EltRSN


# ──────────────────────────────────────────────
# Data structure to hold discovered networks
# ──────────────────────────────────────────────

class Network:
    def __init__(self, ssid, bssid, channel, rssi, security):
        self.ssid     = ssid
        self.bssid    = bssid
        self.channel  = channel
        self.rssi     = rssi       # Signal strength in dBm (e.g. -65)
        self.security = security   # "WPA2", "WPA", "WEP", "Open"

    def __repr__(self):
        return (f"Network(ssid={self.ssid!r}, bssid={self.bssid}, "
                f"ch={self.channel}, rssi={self.rssi}, sec={self.security})")


# ──────────────────────────────────────────────
# Security detection helper
# ──────────────────────────────────────────────

def _get_security(packet) -> str:
    """
    Inspect the Beacon's Information Elements to determine security type.
    - Presence of RSN (Robust Security Network) IE → WPA2
    - Presence of vendor-specific Microsoft WPA IE  → WPA
    - capability 'privacy' bit set, no WPA/WPA2     → WEP
    - Otherwise                                      → Open
    """
    # RSN element (ID=48) → WPA2
    if packet.haslayer(Dot11EltRSN):
        return "WPA2"

    # Walk information elements looking for vendor IE with WPA OUI
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        # Vendor-specific IE (ID=221), Microsoft WPA OUI: 00:50:f2:01
        if elt.ID == 221 and elt.info[:4] == b'\x00\x50\xf2\x01':
            return "WPA"
        elt = elt.payload.getlayer(Dot11Elt)

    # Check the capability field's Privacy bit (bit 4)
    cap = packet[Dot11Beacon].cap
    if cap & 0x10:   # Privacy bit
        return "WEP"

    return "Open"


def _get_channel(packet) -> int:
    """Extract the DS Parameter Set IE (ID=3) which holds the channel number."""
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 3:          # DS Parameter Set
            return int(elt.info[0])
        elt = elt.payload.getlayer(Dot11Elt)
    return 0


# ──────────────────────────────────────────────
# Channel hopper – jumps across all 13 channels
# so we don't miss networks on other channels
# ──────────────────────────────────────────────

def _channel_hopper(iface: str, stop_event: threading.Event):
    """
    Continuously cycle through WiFi channels 1–13.
    This ensures Beacons from all channels are captured during the scan.
    """
    ch = 1
    while not stop_event.is_set():
        try:
            import subprocess
            subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(ch)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass
        ch = (ch % 13) + 1      # Cycle 1 → 2 → ... → 13 → 1
        time.sleep(0.25)        # Dwell 250 ms per channel


# ──────────────────────────────────────────────
# Main packet handler
# ──────────────────────────────────────────────

def _handle_beacon(packet, networks: dict):
    """
    Called by Scapy for every sniffed packet.
    Filters for Beacon Frames and extracts network info.
    """
    if not (packet.haslayer(Dot11Beacon) and packet.haslayer(Dot11Elt)):
        return

    bssid = packet[Dot11].addr3.upper()

    # Skip duplicates – we already know this AP
    if bssid in networks:
        # Update RSSI if we get a stronger reading
        try:
            rssi = packet[RadioTap].dBm_AntSignal
            if rssi > networks[bssid].rssi:
                networks[bssid].rssi = rssi
        except Exception:
            pass
        return

    # Extract SSID from the first Information Element (ID=0)
    try:
        ssid = packet[Dot11Elt].info.decode("utf-8", errors="replace").strip()
    except Exception:
        ssid = "<hidden>"

    if not ssid:
        ssid = "<hidden>"

    # RSSI from RadioTap header (signal strength in dBm)
    try:
        rssi = packet[RadioTap].dBm_AntSignal
    except Exception:
        rssi = -999

    channel  = _get_channel(packet)
    security = _get_security(packet)

    net = Network(ssid=ssid, bssid=bssid, channel=channel,
                  rssi=rssi, security=security)
    networks[bssid] = net


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def set_monitor_mode(iface: str) -> bool:
    """
    Bring the interface down, switch to monitor mode, bring it back up.
    Returns True on success.
    Uses 'iw' and 'ip' system utilities (explicitly allowed per assignment).
    """
    import subprocess
    try:
        subprocess.run(["ip",  "link", "set", iface, "down"],  check=True)
        subprocess.run(["iw",  "dev",  iface, "set", "type", "monitor"], check=True)
        subprocess.run(["ip",  "link", "set", iface, "up"],    check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to set monitor mode on {iface}: {e}")
        return False


def scan_networks(iface: str, duration: int = 60) -> list[Network]:
    """
    Scan for WiFi networks for `duration` seconds.

    Steps:
      1. Start channel hopper thread
      2. Sniff Beacon Frames with Scapy
      3. Stop hopper and return sorted results

    Args:
        iface:    Wireless interface in monitor mode (e.g. 'wlan0')
        duration: How long to scan in seconds (assignment requires 60s)

    Returns:
        List of Network objects sorted by signal strength (strongest first)
    """
    networks = {}          # bssid → Network
    stop_event = threading.Event()

    # Start channel hopper in background thread
    hopper = threading.Thread(
        target=_channel_hopper,
        args=(iface, stop_event),
        daemon=True
    )
    hopper.start()

    # Sniff packets – Scapy calls _handle_beacon for each one
    sniff(
        iface=iface,
        prn=lambda pkt: _handle_beacon(pkt, networks),
        timeout=duration,
        store=False          # Don't store raw packets in memory
    )

    # Stop the channel hopper
    stop_event.set()

    # Return sorted by RSSI descending (strongest signal first)
    return sorted(networks.values(), key=lambda n: n.rssi, reverse=True)
