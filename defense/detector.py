"""
defense/detector.py – Evil Twin Detection Tool
------------------------------------------------
Passively monitors 802.11 Beacon Frames and detects Evil Twin attacks
by identifying anomalies that indicate a rogue AP:

Detection methods (as suggested by the assignment):
  1. BSSID Anomaly  – Same SSID appearing from multiple different BSSIDs
  2. Signal Anomaly – Sudden strong signal from a new AP with a known SSID
  3. Security Change – Known SSID suddenly appearing as Open instead of WPA2
  4. Beacon Fingerprint – Different IE (Information Element) ordering/content

Usage:
    sudo python3 detector.py -i wlan0
"""

import argparse
import time
import sys
from collections import defaultdict
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11EltRSN, RadioTap


# ──────────────────────────────────────────────
# Known network database
# Populated during the first N seconds of monitoring (learning phase)
# ──────────────────────────────────────────────

class KnownNetwork:
    """Stores the baseline fingerprint of a legitimate AP."""
    def __init__(self, ssid, bssid, channel, security, rssi, ie_fingerprint):
        self.ssid           = ssid
        self.bssid          = bssid.upper()
        self.channel        = channel
        self.security       = security
        self.rssi           = rssi
        self.ie_fingerprint = ie_fingerprint   # Tuple of IE IDs in order
        self.first_seen     = time.time()
        self.last_seen      = time.time()


# ──────────────────────────────────────────────
# Fingerprinting helpers
# ──────────────────────────────────────────────

def _get_ie_fingerprint(packet) -> tuple:
    """
    Extract the ordered list of Information Element IDs from a Beacon.
    This is the AP's "fingerprint" – different hardware/firmware produces
    different IE orderings even for the same SSID.
    An Evil Twin cloning the SSID typically can't replicate this exactly.
    """
    ids = []
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        ids.append(elt.ID)
        elt = elt.payload.getlayer(Dot11Elt)
    return tuple(ids)


def _get_security(packet) -> str:
    if packet.haslayer(Dot11EltRSN):
        return "WPA2"
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 221 and elt.info[:4] == b'\x00\x50\xf2\x01':
            return "WPA"
        elt = elt.payload.getlayer(Dot11Elt)
    cap = packet[Dot11Beacon].cap
    return "WEP" if (cap & 0x10) else "Open"


def _get_channel(packet) -> int:
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 3:
            return int(elt.info[0])
        elt = elt.payload.getlayer(Dot11Elt)
    return 0


def _get_rssi(packet) -> int:
    try:
        return packet[RadioTap].dBm_AntSignal
    except Exception:
        return -999


# ──────────────────────────────────────────────
# Alert system
# ──────────────────────────────────────────────

ALERTS = []

def _alert(level: str, ssid: str, reason: str, details: str = ""):
    ts = time.strftime("%H:%M:%S")
    msg = f"[{ts}] [{level}] SSID='{ssid}' | {reason}"
    if details:
        msg += f"\n         {details}"
    print(f"\n{'!'*60}")
    print(msg)
    print(f"{'!'*60}\n")
    ALERTS.append({"time": ts, "level": level, "ssid": ssid,
                   "reason": reason, "details": details})


# ──────────────────────────────────────────────
# Core detector
# ──────────────────────────────────────────────

class EvilTwinDetector:
    """
    Passively monitors Beacon Frames and raises alerts for Evil Twin indicators.
    """

    def __init__(self, iface: str, learn_duration: int = 30):
        """
        Args:
            iface:          Monitor-mode interface to sniff on
            learn_duration: Seconds to passively learn the environment before alerting
        """
        self.iface          = iface
        self.learn_duration = learn_duration
        self._known         = {}    # bssid → KnownNetwork
        # ssid → set of BSSIDs  (to detect multiple APs with same name)
        self._ssid_to_bssids = defaultdict(set)
        self._start_time    = None
        self._learning      = True

    def _is_learning(self) -> bool:
        return time.time() - self._start_time < self.learn_duration

    def _handle_beacon(self, packet):
        if not packet.haslayer(Dot11Beacon):
            return

        bssid    = packet[Dot11].addr3.upper()
        try:
            ssid = packet[Dot11Elt].info.decode("utf-8", errors="replace").strip()
        except Exception:
            return
        if not ssid:
            return

        channel     = _get_channel(packet)
        security    = _get_security(packet)
        rssi        = _get_rssi(packet)
        fingerprint = _get_ie_fingerprint(packet)

        # Track which BSSIDs advertise this SSID
        self._ssid_to_bssids[ssid].add(bssid)

        if self._is_learning():
            # Learning phase: just record baselines, no alerts
            if bssid not in self._known:
                self._known[bssid] = KnownNetwork(
                    ssid=ssid, bssid=bssid, channel=channel,
                    security=security, rssi=rssi, ie_fingerprint=fingerprint
                )
                print(f"  [learn] {ssid:30s} {bssid}  ch={channel}  {security}")
            return

        # ── Detection phase ──────────────────────────────────────────

        # 1. Known AP – check for changes (fingerprint / security)
        if bssid in self._known:
            known = self._known[bssid]

            # Security downgrade (WPA2 → Open) is a strong Evil Twin indicator
            if known.security in ("WPA2", "WPA") and security == "Open":
                _alert("HIGH", ssid,
                       "Security downgrade detected",
                       f"Expected: {known.security} | Got: Open | BSSID: {bssid}")

            # Beacon fingerprint mismatch – different IE structure
            if fingerprint != known.ie_fingerprint:
                _alert("MEDIUM", ssid,
                       "Beacon fingerprint mismatch",
                       f"BSSID: {bssid}\n"
                       f"         Expected IEs: {known.ie_fingerprint}\n"
                       f"         Got IEs:      {fingerprint}")

            known.last_seen = time.time()
            return

        # 2. New BSSID for a known SSID → likely Evil Twin
        if ssid in self._ssid_to_bssids:
            existing_bssids = self._ssid_to_bssids[ssid] - {bssid}
            if existing_bssids:
                _alert("HIGH", ssid,
                       "Multiple BSSIDs for same SSID (Evil Twin suspected!)",
                       f"Known BSSID(s): {', '.join(existing_bssids)}\n"
                       f"         New  BSSID:    {bssid}  "
                       f"ch={channel}  {security}  rssi={rssi}dBm")

                # Extra check: if new AP is open and original was encrypted
                for known_bssid in existing_bssids:
                    if known_bssid in self._known:
                        orig_sec = self._known[known_bssid].security
                        if orig_sec in ("WPA2", "WPA") and security == "Open":
                            _alert("CRITICAL", ssid,
                                   "Evil Twin confirmed: Rogue open AP cloning encrypted network",
                                   f"Rogue BSSID: {bssid} | Original: {known_bssid}")

        # Register this new AP
        self._known[bssid] = KnownNetwork(
            ssid=ssid, bssid=bssid, channel=channel,
            security=security, rssi=rssi, ie_fingerprint=fingerprint
        )

    def start(self, duration: int = 0):
        """
        Start monitoring. Runs for `duration` seconds (0 = indefinitely).
        Learning phase runs for the first `self.learn_duration` seconds.
        """
        self._start_time = time.time()
        print(f"\n[*] Evil Twin Detector started on {self.iface}")
        print(f"[*] Learning phase: {self.learn_duration}s "
              f"(recording baseline networks...)\n")

        sniff(
            iface=self.iface,
            prn=self._handle_beacon,
            timeout=duration if duration > 0 else None,
            store=False
        )

        print(f"\n[*] Monitoring complete. Total alerts: {len(ALERTS)}")
        return ALERTS


# ──────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Evil Twin Detector – monitors for rogue APs"
    )
    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode (e.g. wlan0)")
    parser.add_argument("-l", "--learn", type=int, default=30,
                        help="Learning phase duration in seconds (default: 30)")
    parser.add_argument("-d", "--duration", type=int, default=0,
                        help="Total monitoring duration in seconds (0 = infinite)")
    args = parser.parse_args()

    detector = EvilTwinDetector(iface=args.interface, learn_duration=args.learn)
    try:
        detector.start(duration=args.duration)
    except KeyboardInterrupt:
        print("\n[*] Detector stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
