# Evil Twin Attack Tool

**Assignment 1 – Wireless and Mobile Network Security**
Ariel University | Course #2-7038910-1

---

## Group Details

- **Student 1:** Yakir
- **Student 2:** Noa

---

## Overview

A complete Evil Twin attack tool and defense detector implemented in Python using Scapy, Flask, hostapd, and dnsmasq.

### Attack Stages

| Stage | Description | Module |
|-------|-------------|--------|
| 1 | Hardware selection + Monitor Mode setup | `evil_twin.py` |
| 2 | 60-second network scan (Beacon sniffing) | `scanner.py` |
| 3 | Target network selection | `evil_twin.py` |
| 4 | Active client (victim) discovery | `client_discovery.py` |
| 5 | Evil Twin AP creation | `rogue_ap.py` |
| 6 | Captive Portal (credential capture) | `captive_portal.py` |
| 7 | Targeted Deauthentication | `deauth.py` |

### Defense Tool

Passive Evil Twin detector with BSSID anomaly detection, security downgrade detection, and beacon fingerprinting.

---

## Hardware Requirements

A wireless adapter that supports **monitor mode** and **packet injection**.

Tested adapters:
- EDUP AX3000 (EP-AX1672)
- Tenda N150
- VIA 9271

**Important:** For best results, use **two wireless adapters**:
- Adapter 1: Monitor mode (scanning, deauth)
- Adapter 2: AP mode (Evil Twin)

---

## Installation

### 1. System dependencies

```bash
sudo apt update
sudo apt install -y hostapd dnsmasq python3-pip
```

### 2. Python dependencies

```bash
pip3 install -r requirements.txt
```

### 3. Disable services that conflict with dnsmasq

```bash
sudo systemctl stop   NetworkManager
sudo systemctl disable NetworkManager

sudo systemctl stop   systemd-resolved
sudo systemctl disable systemd-resolved
```

---

## Usage

### Attack Tool

```bash
sudo python3 evil_twin.py
```

Follow the interactive prompts:
1. Select monitor interface
2. Select AP interface
3. Wait for 60-second scan
4. Choose target network
5. Wait for 30-second client scan
6. Choose victim
7. Attack launches automatically

Captured credentials are saved to `captured_credentials.txt`.

### Defense Tool

```bash
sudo python3 defense/detector.py -i wlan0
```

Options:
- `-i` / `--interface` — wireless interface in monitor mode (required)
- `-l` / `--learn` — learning phase duration in seconds (default: 30)
- `-d` / `--duration` — total run time in seconds (default: infinite)

---

## File Structure

```
evil_twin/
├── evil_twin.py             # Main entry point
├── scanner.py               # Stage 2: Network discovery
├── client_discovery.py      # Stage 4: Victim identification
├── rogue_ap.py              # Stage 5: Evil Twin AP
├── deauth.py                # Stage 7: Targeted deauthentication
├── captive_portal.py        # Stage 6: Credential capture
├── templates/
│   └── login.html           # Captive portal web page
├── configs/                 # Runtime config files (auto-generated)
├── defense/
│   └── detector.py          # Defense tool
├── requirements.txt
└── README.md
```

---

## Known Limitations

1. **Two interfaces recommended** – using a single interface for both sniffing and AP is possible but degrades scan quality.
2. **2.4GHz only** – hostapd is configured with `hw_mode=g`. 5GHz requires `hw_mode=a` and a compatible adapter.
3. **WPA3 networks** – Deauth attacks are mitigated by PMF (Protected Management Frames / 802.11w). This tool targets WPA2 and below.
4. **NetworkManager conflicts** – NetworkManager may try to reconfigure the interface. Disable it before running.
5. **DragonOS** – Tested and intended for DragonOS / Kali Linux / Ubuntu 22+.

---

## Authorization

> All testing must be performed exclusively on explicitly authorized networks and equipment within the course framework. Unauthorized use is illegal.

---

## Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [hostapd man page](https://linux.die.net/man/8/hostapd)
- [dnsmasq man page](https://linux.die.net/man/8/dnsmasq)
- [DragonOS](https://cemaxecuter.com/)
