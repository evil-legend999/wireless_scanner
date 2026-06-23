import sys
import subprocess
import re

def scan_wifi_networks():
    networks = []
    current_os = sys.platform
    if current_os.startswith("linux"):
        try:
            result = subprocess.run(["nmcli", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "device", "wifi", "list"], capture_output=True, text=True, errors="ignore")
            if result.returncode != 0: return networks
            lines = result.stdout.splitlines()
            if len(lines) <= 1: return networks
            header = lines[0]
            ssid_start, bssid_start = header.find("SSID"), header.find("BSSID")
            signal_start, chan_start = header.find("SIGNAL"), header.find("CHAN")
            security_start = header.find("SECURITY")
            for line in lines[1:]:
                if not line.strip(): continue
                ssid = line[ssid_start:bssid_start].strip()
                bssid = line[bssid_start:signal_start].strip()
                signal = line[signal_start:chan_start].strip()
                channel = line[chan_start:security_start].strip()
                encryption = line[security_start:].strip()
                if ssid == "--" or not ssid: ssid = "Hidden Network"
                try: sig_val = int(signal)
                except ValueError: sig_val = 0
                networks.append({"ssid": ssid, "bssid": bssid, "rssi": sig_val, "channel": channel, "encryption": encryption if encryption and encryption != "--" else "Open"})
        except Exception: pass
    elif current_os.startswith("win"):
        try:
            result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, errors="ignore")
            if result.returncode != 0: return networks
            
            # NORMALIZE WINDOWS LINE ENDINGS NATIVELY
            clean_stdout = result.stdout.replace('\r\n', '\n')
            
            # Split blocks accurately now that line breaks are uniform
            network_blocks = clean_stdout.split("SSID ")
            for block in network_blocks[1:]:
                lines = block.splitlines()
                if not lines: continue
                net_info = {"ssid": "Hidden Network", "bssid": "N/A", "rssi": 0, "channel": "N/A", "encryption": "Unknown"}
                first_line = lines[0].strip()
                ssid_match = re.search(r'^:\s*(.*)$', first_line)
                if ssid_match and ssid_match.group(1).strip(): net_info["ssid"] = ssid_match.group(1).strip()
                for line in lines:
                    line_stripped = line.strip()
                    if "Authentication" in line_stripped:
                        enc_match = re.search(r':\s*(.*)$', line_stripped)
                        if enc_match: net_info["encryption"] = enc_match.group(1).strip()
                    elif "BSSID" in line_stripped:
                        bssid_match = re.search(r'BSSID\s*\d+\s*:\s*(.*)$', line_stripped)
                        if bssid_match: net_info["bssid"] = bssid_match.group(1).strip()
                    elif "Signal" in line_stripped:
                        sig_match = re.search(r':\s*(\d+)%', line_stripped)
                        if sig_match: net_info["rssi"] = int(sig_match.group(1))
                    elif "Channel" in line_stripped:
                        ch_match = re.search(r':\s*(\d+)$', line_stripped)
                        if ch_match: net_info["channel"] = ch_match.group(1).strip()
                networks.append(net_info)
        except Exception: pass
    elif current_os.startswith("darwin"):
        try:
            airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            result = subprocess.run([airport_path, "-s"], capture_output=True, text=True, errors="ignore")
            if result.returncode != 0: return networks
            lines = result.stdout.splitlines()
            if len(lines) <= 1: return networks
            header = lines[0]
            ssid_end = header.find("BSSID")
            for line in lines[1:]:
                if not line.strip(): continue
                ssid = line[:ssid_end].strip()
                parts = line[ssid_end:].split()
                if len(parts) < 4: continue
                bssid = parts[0]
                rssi_val = int(parts[1])
                channel = parts[2].split(',')[0]
                security = " ".join(parts[3:])
                signal_pct = 100 if rssi_val >= -50 else 0 if rssi_val <= -100 else int((rssi_val + 100) * 2)
                if not ssid: ssid = "Hidden Network"
                networks.append({"ssid": ssid, "bssid": bssid, "rssi": signal_pct, "channel": channel, "encryption": security})
        except Exception: pass
    return networks