<div align="center">

```
  ███████╗██╗   ██╗██╗     ██╗       █████╗ ██╗   ██╗████████╗ ██████╗
  ██╔════╝██║   ██║██║     ██║      ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
  █████╗  ██║   ██║██║     ██║      ███████║██║   ██║   ██║   ██║   ██║
  ██╔══╝  ██║   ██║██║     ██║      ██╔══██║██║   ██║   ██║   ██║   ██║
  ██║     ╚██████╔╝███████╗███████╗ ██║  ██║╚██████╔╝   ██║   ╚██████╔╝
  ╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝
```

**WiFi Deauthentication Tool**

![Python](https://img.shields.io/badge/Python-3.x-cyan?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-green?style=for-the-badge&logo=linux&logoColor=white)
![Scapy](https://img.shields.io/badge/Powered%20By-Scapy-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

*A fast, efficient, terminal-based WiFi deauthentication tool built for security research and academic use.*

---

> ⚠️ **For authorized testing and academic use only.**
> Using this tool on networks you do not own or have explicit written permission to test is **illegal** and punishable by law.

</div>

---

## 📌 About

**FULL-AUTO** is a Python-based WiFi deauthentication tool that exploits the unauthenticated nature of 802.11 deauth frames to disconnect clients from a target access point. Built entirely in Python using Scapy, it runs purely in the terminal with no GUI required.

Built as a final university project, inspired by [flashnuke/wifi-deauth](https://github.com/flashnuke/wifi-deauth) with additional features on top.

---

## ✨ Features

- 🔍 **Full channel scan** — automatically scans all 2.4 GHz / 5 GHz channels for APs
- 📡 **Broadcast + targeted deauth** — hits all devices at once and individual clients separately
- 👥 **Live client discovery** — detects connected clients mid-attack and adds them to the target list
- 🔁 **All-channels mode** — rotates channels during attack for channel-hopping APs
- 💾 **Save & load targets** — skip rescanning by saving known APs to disk
- 🎯 **Flexible filters** — filter by SSID, BSSID, channel, or specific client MACs
- ⚡ **Fast & lightweight** — 100ms deauth interval, fully threaded, no GUI overhead
- 🛡️ **Auto monitor mode** — sets up monitor mode and kills NetworkManager automatically

---

## 🖥️ Requirements

- Linux (tested on Fedora, Kali, Ubuntu)
- Python 3.x
- A wireless adapter that supports **monitor mode**
- Root privileges

### Recommended adapters
| Adapter | Chipset | Monitor Mode | 5 GHz |
|---|---|---|---|
| Alfa AWUS036ACH | RTL8812AU | ✅ | ✅ |
| TP-Link WN722N v1 | AR9271 | ✅ Native | ❌ |
| Alfa AWUS036ACS | RTL8811AU | ✅ | ✅ |

---

## ⚙️ Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/full-auto.git
cd full-auto

# Install the only dependency
pip install scapy
```

---

## 🚀 Usage

```bash
sudo python3 full-auto.py -i <interface> [options]
```

### Basic scan and attack
```bash
sudo python3 full-auto.py -i wlan0 --kill
```

### Target a specific SSID
```bash
sudo python3 full-auto.py -i wlan0 --kill --ssid "TargetNetwork"
```

### Lock to specific channels
```bash
sudo python3 full-auto.py -i wlan0 --kill --channels 1,6,11
```

### Rotate all channels during attack
```bash
sudo python3 full-auto.py -i wlan0 --kill --deauth-all-channels
```

### Target specific clients only
```bash
sudo python3 full-auto.py -i wlan0 --kill --clients AA:BB:CC:DD:EE:FF
```

---

## 💾 Target Persistence (New Feature)

Save a scanned AP so you can skip rescanning next time.

```bash
# Scan, select a target, and save it
sudo python3 full-auto.py -i wlan0 --kill --save

# Next run — skip the scan entirely
sudo python3 full-auto.py -i wlan0 --from-saved

# View all saved targets
python3 full-auto.py --list-targets

# Delete a saved target
python3 full-auto.py --delete-target "NetworkName"
```

Targets are stored in `~/.wifi_deauth_targets.json`.

---

## 🧰 All Flags

| Flag | Description |
|---|---|
| `-i`, `--iface` | Wireless interface (e.g. `wlan0`) |
| `-s`, `--ssid` | Filter scan by SSID name |
| `-b`, `--bssid` | Filter scan by BSSID/MAC |
| `-c`, `--channels` | Comma-separated channel list |
| `--clients` | Target specific client MACs only |
| `-k`, `--kill` | Kill NetworkManager before running |
| `-a`, `--autostart` | Auto-select when only 1 AP found |
| `--deauth-all-channels` | Rotate channels during attack |
| `--skip-monitormode` | Skip automatic monitor mode setup |
| `--save` | Save selected target after scan |
| `--from-saved` | Skip scan, pick from saved targets |
| `--list-targets` | Print all saved targets and exit |
| `--delete-target` | Remove a target from saved list |
| `-d`, `--debug` | Enable verbose debug output |

---

## 🔬 How It Works

```
┌─────────────────────────────────────────────────────┐
│                    FULL-AUTO                        │
│                                                     │
│  1. Kill NetworkManager                             │
│  2. Set interface to Monitor Mode                   │
│  3. Scan channels → collect Beacon / Probe frames   │
│  4. User selects target AP                          │
│                                                     │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐ │
│  │  Deauth  │  │    Client    │  │    Status     │ │
│  │  Loop    │  │   Listener   │  │   Reporter    │ │
│  │ 100ms/tx │  │ sniffs live  │  │ refreshes 1s  │ │
│  └──────────┘  └──────────────┘  └───────────────┘ │
│                                                     │
│  Sends:  AP→Client  +  Client→AP  +  Broadcast     │
└─────────────────────────────────────────────────────┘
```

The deauth frame abuses the unauthenticated management frame design of 802.11. The target devices receive the spoofed frames, consider them legitimate, and immediately drop the connection.

---

## 📂 Project Structure

```
full-auto/
│
├── full-auto.py          # Main tool (single file)
├── README.md
└── ~/.wifi_deauth_targets.json   # Auto-generated saved targets
```

---

## 📖 References

- [IEEE 802.11 Standard](https://standards.ieee.org/ieee/802.11/7028/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [flashnuke/wifi-deauth](https://github.com/flashnuke/wifi-deauth) — original inspiration

---

<div align="center">

Made for academic purposes / Playing around

</div>
