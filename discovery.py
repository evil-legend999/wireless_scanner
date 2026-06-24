import subprocess
import re
import platform
from collections import Counter

def get_signal_quality(rssi):
    """Maps raw RSSI dBm integers to the exact 5-tier academic thesis thresholds."""
    if rssi >= -50:
        return "Excellent", "green"
    elif -60 <= rssi < -50:
        return "Good", "light_green"
    elif -70 <= rssi < -60:
        return "Fair", "yellow"
    elif -80 <= rssi < -70:
        return "Weak", "orange3"
    else:
        return "Very Weak / Unusable", "red"

def detect_security_flags(networks):
    """Evaluates the parsed dataset against structural security anomalies."""
    ssid_counts = Counter([net['ssid'] for net in networks if net['ssid'] and net['ssid'] != "<hidden>"])
    for net in networks:
        flags = []
        if not net['encryption'] or net['encryption'].lower() == "open":
            flags.append("🚨 OPEN NETWORK")
        if "WEP" in net['encryption'].upper():
            flags.append("❌ DEPRECATED WEP")
        if not net['ssid'] or net['ssid'] == "<hidden>" or "\\x00" in net['ssid']:
            flags.append("🔒 HIDDEN SSID")
            net['ssid'] = "<hidden>"
        if net['ssid'] in ssid_counts and ssid_counts[net['ssid']] > 1:
            flags.append("⚠️ DUPLICATE SSID (Rogue AP Risk)")
        net['flags'] = flags if flags else ["None"]
    return networks

def parse_linux_scan():
    """Invokes and parses native Linux iwlist strings."""
    try:
        cmd = ["sudo", "iwlist", "wlan0", "scanning"]
        raw_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8')
    except (subprocess.CalledProcessError, FileNotFoundError):
        return get_mock_data()

    networks = []
    current_net = {}
    for line in raw_output.split('\n'):
        line = line.strip()
        if "Cell" in line:
            if current_net: networks.append(current_net)
            current_net = {"ssid": "", "bssid": "", "rssi": -100, "channel": 1, "band": "2.4 GHz", "encryption": "Open"}
            bssid_match = re.search(r"Address:\s+([0-9A-Fa-f:]{17})", line)
            if bssid_match: current_net["bssid"] = bssid_match.group(1)
        elif "Frequency:" in line:
            if "5 GHz" in line or "5." in line: current_net["band"] = "5 GHz"
        elif "Channel" in line and not "Frequency" in line:
            ch_match = re.search(r"Channel\s+(\d+)", line)
            if ch_match: current_net["channel"] = int(ch_match.group(1))
        elif "Quality" in line:
            rssi_match = re.search(r"Signal level=(-?\d+)\s+dBm", line)
            if rssi_match: current_net["rssi"] = int(rssi_match.group(1))
        elif "Encryption key:" in line:
            if "on" in line: current_net["encryption"] = "WPA2"
        elif "ESSID:" in line:
            ssid_match = re.search(r'ESSID:"([^"]*)"', line)
            if ssid_match: current_net["ssid"] = ssid_match.group(1)

    if current_net: networks.append(current_net)
    return networks

def parse_windows_scan():
    """Invokes and parses native Windows netsh utility outputs."""
    try:
        # Run native netsh tool to reveal nearby access points and BSSIDs
        cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
        raw_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
    except (subprocess.CalledProcessError, FileNotFoundError):
        return get_mock_data()

    networks = []
    current_net = {}
    
    # Split text blocks into distinct SSIDs discovered by netsh
    for line in raw_output.split('\n'):
        line = line.strip()
        
        # Capture Logical Network Name
        if line.startswith("SSID"):
            ssid_match = re.search(r"SSID\s+\d+\s+:\s+(.*)", line)
            if ssid_match:
                # Store structural shell data
                ssid_name = ssid_match.group(1).strip()
                current_net = {"ssid": ssid_name, "encryption": "WPA2"} # Baseline default updated by fields below
        
        # Capture Authentication protocol
        elif line.startswith("Authentication"):
            auth_match = re.search(r"Authentication\s+:\s+(.*)", line)
            if current_net and auth_match:
                current_net["encryption"] = auth_match.group(1).strip()
                
        # Capture Physical Access Point details
        elif line.startswith("BSSID"):
            bssid_match = re.search(r"BSSID\s+\d+\s+:\s+([0-9A-Fa-f:]{17})", line)
            if current_net and bssid_match:
                # Copy current baseline metadata into a standalone physical hardware record
                net_entry = current_net.copy()
                net_entry["bssid"] = bssid_match.group(1).upper()
                networks.append(net_entry)
                
        # Capture Signal Strength Percentage and map to standard dBm
        elif line.startswith("Signal"):
            sig_match = re.search(r"Signal\s+:\s+(\d+)%", line)
            if networks and sig_match:
                pct = int(sig_match.group(1))
                # Windows gives signal in % (0-100). Convert to relative dBm: dBm = (pct / 2) - 100
                dbm = int((pct / 2) - 100)
                networks[-1]["rssi"] = dbm
                
        # Capture Channel and deduce Band assignment
        elif line.startswith("Channel"):
            ch_match = re.search(r"Channel\s+:\s+(\d+)", line)
            if networks and ch_match:
                ch = int(ch_match.group(1))
                networks[-1]["channel"] = ch
                networks[-1]["band"] = "5 GHz" if ch > 14 else "2.4 GHz"

    return networks if networks else get_mock_data()

def get_mock_data():
    """Safe analytical fallback dataset containing explicit testing scenarios."""
    return [
        {"ssid": "Campus-Main", "bssid": "00:1A:2B:3C:4D:5E", "rssi": -45, "channel": 6, "band": "2.4 GHz", "encryption": "WPA2"},
        {"ssid": "Campus-Main", "bssid": "00:1A:2B:3C:4D:9F", "rssi": -62, "channel": 11, "band": "2.4 GHz", "encryption": "WPA2"},
        {"ssid": "Free-Public-WiFi", "bssid": "0A:11:22:33:44:55", "rssi": -55, "channel": 1, "band": "2.4 GHz", "encryption": "Open"},
        {"ssid": "Legacy_Printer", "bssid": "B0:C0:D0:E0:F0:A0", "rssi": -75, "channel": 36, "band": "5 GHz", "encryption": "WEP"},
        {"ssid": "", "bssid": "11:22:33:44:55:66", "rssi": -82, "channel": 149, "band": "5 GHz", "encryption": "WPA3"}
    ]

def run_scanner():
    """Coordinates hardware data capture based on runtime operating system environment."""
    os_type = platform.system()
    
    if os_type == "Linux":
        raw_nets = parse_linux_scan()
    elif os_type == "Windows":
        raw_nets = parse_windows_scan()
    else:
        # Fallback loop handles macOS or unsupported test environments gracefully
        raw_nets = get_mock_data()
        
    for net in raw_nets:
        quality, color = get_signal_quality(net['rssi'])
        net['quality'] = quality
        net['color'] = color
        
    return detect_security_flags(raw_nets)