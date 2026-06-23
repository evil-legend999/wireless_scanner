import subprocess
import platform
import re

def scan_wifi_networks():
    """Detects the host OS, runs the native scanner tool, and parses the results."""
    current_os = platform.system().lower()
    networks = []

    try:
        if current_os == "windows":
            networks = _scan_windows()
        elif current_os == "linux":
            networks = _scan_linux()
        elif current_os == "darwin":  # macOS core framework
            networks = _scan_macos()
        else:
            print(f"[-] Unsupported Operating System: {current_os}")
    except Exception as e:
        print(f"[-] Diagnostic error during scan: {e}")
        
    return networks

def _scan_windows():
    """Executes and handles Windows netsh formatting flawlessly."""
    result = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"], 
        capture_output=True, 
        text=True,
        errors="ignore"
    )
    
    raw_output = result.stdout
    networks = []
    
    # Split blocks reliably regardless of line-shifting or trailing spaces
    chunks = re.split(r'SSID\s+\d+\s*:\s*', raw_output)
    
    for chunk in chunks[1:]:
        lines = [line.strip() for line in chunk.splitlines() if line.strip()]
        if not lines:
            continue
            
        ssid = lines[0]
        bssid, channel, rssi, encryption = "Unknown", "N/A", 0, "Open"
        
        for line in lines:
            if line.startswith("Authentication"):
                encryption = line.split(":", 1)[1].strip()
            elif line.startswith("BSSID 1"):
                bssid = line.split(":", 1)[1].strip()
            elif line.startswith("Signal"):
                signal_str = line.split(":", 1)[1].strip().replace("%", "")
                rssi = int(signal_str) if signal_str.isdigit() else 0
            elif line.startswith("Channel"):
                channel = line.split(":", 1)[1].strip()
                
        networks.append({
            'ssid': ssid if ssid else "[Hidden Network]",
            'bssid': bssid,
            'channel': channel,
            'encryption': encryption,
            'risk_level': "Low",
            'rssi': rssi
        })
    return networks

def _scan_linux():
    """Executes and parses Linux nmcli output perfectly using unescaped colons."""
    result = subprocess.run(
        ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "device", "wifi", "list"],
        capture_output=True,
        text=True,
        errors="ignore"
    )
    networks = []
    
    for line in result.stdout.splitlines():
        if not line:
            continue
            
        # Split ONLY on colons that are NOT preceded by a backslash (?<!\\)
        parts = re.split(r'(?<!\\):', line)
        
        if len(parts) >= 5:
            ssid = parts[0]
            # Clean up the backslashes out of the BSSID now that splitting is done
            bssid = parts[1].replace(r"\:", ":")
            channel = parts[2]
            rssi_str = parts[3]
            encryption = parts[4] if parts[4] else "Open"
            
            networks.append({
                'ssid': ssid if ssid else "[Hidden Network]",
                'bssid': bssid,
                'channel': channel,
                'rssi': int(rssi_str) if rssi_str.isdigit() else 0,
                'encryption': encryption,
                'risk_level': "Low"
            })
    return networks

def _scan_macos():
    """Executes and parses the native macOS airport utility cleanly."""
    cmd = ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"]
    result = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
    networks = []
    lines = result.stdout.splitlines()
    if not lines or len(lines) < 2:
        return networks
        
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6:
            try:
                raw_rssi = int(parts[2])
                # Convert dBm back into standard 0-100 range calculation
                quality = max(0, min(100, 2 * (raw_rssi + 100)))
            except ValueError:
                quality = 0
                
            networks.append({
                'ssid': parts[0],
                'bssid': parts[1],
                'rssi': quality,
                'channel': parts[3].split(',')[0],
                'encryption': parts[6] if len(parts) > 6 else "Unknown",
                'risk_level': "Low"
            })
    return networks