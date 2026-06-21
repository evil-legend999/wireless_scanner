# discovery.py
# MODULE 1: Cross-Platform Hardware Interfacing and Text Parsing

import subprocess
import platform
import re

def detect_operating_system():
    """Identifies if the host machine is Linux, Windows, or Mac."""
    os_name = platform.system().lower()
    if os_name == "linux":
        return "linux"
    elif os_name == "windows":
        return "windows"
    elif os_name == "darwin":
        return "macos"
    return "unsupported"

def create_empty_network_record():
    """Generates a strict data template so every OS output looks identical."""
    return {
        "ssid": "", "bssid": "", "signal_dbm": None, "channel": None,
        "frequency_band": "", "encryption": "", "signal_quality": "", "security_flags": []
    }

def parse_linux(raw_output):
    """Extracts network details from raw Linux 'iwlist' text."""
    networks = []
    blocks = raw_output.split("Cell ")
    for block in blocks[1:]:
        net = create_empty_network_record()
        bssid = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", block)
        if bssid: net["bssid"] = bssid.group(0).upper()
        ssid = re.search(r'ESSID:"(.*?)"', block)
        if ssid: net["ssid"] = ssid.group(1)
        signal = re.search(r"Signal level=(-\d+) dBm", block)
        if signal: net["signal_dbm"] = int(signal.group(1))
        channel = re.search(r"Channel:(\d+)", block)
        if channel:
            net["channel"] = int(channel.group(1))
            net["frequency_band"] = "2.4 GHz" if net["channel"] <= 14 else "5 GHz"
        if "Encryption key:off" in block: net["encryption"] = "OPEN"
        elif "WPA2" in block: net["encryption"] = "WPA2"
        elif "WPA3" in block: net["encryption"] = "WPA3"
        else: net["encryption"] = "WPA2"
        networks.append(net)
    return networks

def parse_windows(raw_output):
    """Extracts network details from Windows 'netsh' text."""
    networks = []
    blocks = raw_output.split("SSID ")
    for block in blocks[1:]:
        net = create_empty_network_record()
        ssid_match = re.search(r"^\s*\d*\s*:\s*(.+)", block)
        if ssid_match: net["ssid"] = ssid_match.group(1).strip()
        bssid_match = re.search(r"BSSID\s*\d*\s*:\s*([0-9a-fA-F:]{17})", block)
        if bssid_match: net["bssid"] = bssid_match.group(1).upper()
        signal_match = re.search(r"Signal\s*:\s*(\d+)%", block)
        if signal_match:
            pct = int(signal_match.group(1))
            net["signal_dbm"] = (pct // 2) - 100
        channel_match = re.search(r"Channel\s*:\s*(\d+)", block)
        if channel_match:
            net["channel"] = int(channel_match.group(1))
            net["frequency_band"] = "2.4 GHz" if net["channel"] <= 14 else "5 GHz"
        net["encryption"] = "OPEN" if "Open" in block else "WPA2"
        if net["bssid"]: networks.append(net)
    return networks

def parse_macos(raw_output):
    """Extracts network details from macOS 'airport' text."""
    networks = []
    lines = raw_output.strip().split("\n")
    for line in lines[1:]:
        if not line.strip(): continue
        net = create_empty_network_record()
        parts = line.split()
        if len(parts) >= 6:
            net["ssid"] = parts[0]
            net["bssid"] = parts[1].upper()
            try:
                net["signal_dbm"] = int(parts[2])
                channel_raw = parts[3].split(",")[0]
                net["channel"] = int(channel_raw)
                net["frequency_band"] = "2.4 GHz" if net["channel"] <= 14 else "5 GHz"
            except ValueError: pass
            net["encryption"] = "OPEN" if "NONE" in parts[-1] or "OPEN" in parts[-1] else "WPA2"
            networks.append(net)
    return networks

def discover_networks(interface="wlan0"):
    """The entry point that shoots the commands to the hardware."""
    os_type = detect_operating_system()
    try:
        if os_type == "linux":
            res = subprocess.run(["iwlist", interface, "scan"], capture_output=True, text=True, check=True)
            return parse_linux(res.stdout)
        elif os_type == "windows":
            res = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, check=True)
            return parse_windows(res.stdout)
        elif os_type == "macos":
            path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            res = subprocess.run([path, "-s"], capture_output=True, text=True, check=True)
            return parse_macos(res.stdout)
        return []
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []