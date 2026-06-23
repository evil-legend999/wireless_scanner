import os
import sys
import subprocess
import re
from datetime import datetime
import matplotlib.pyplot as plt

def scan_wifi_networks():
    """Detects the OS and scans for networks using native utilities."""
    networks = []
    current_os = sys.platform
    
    # ------------------ LINUX ENGINE ------------------
    if current_os.startswith("linux"):
        try:
            result = subprocess.run(
                ["nmcli", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "device", "wifi", "list"], 
                capture_output=True, text=True, errors="ignore"
            )
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
                    
                networks.append({
                    "ssid": ssid, "bssid": bssid, "rssi": sig_val, 
                    "channel": channel, "encryption": encryption if encryption and encryption != "--" else "Open"
                })
        except Exception as e:
            print(f"[-] Linux scan error: {e}")

    # ------------------ WINDOWS ENGINE ------------------
    elif current_os.startswith("win"):
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"], 
                capture_output=True, text=True, errors="ignore"
            )
            if result.returncode != 0: return networks
            network_blocks = result.stdout.split("SSID ")
            for block in network_blocks[1:]:
                lines = block.splitlines()
                if not lines: continue
                
                net_info = {"ssid": "Hidden Network", "bssid": "N/A", "rssi": 0, "channel": "N/A", "encryption": "Unknown"}
                first_line = lines[0].strip()
                ssid_match = re.search(r'^:\s*(.*)$', first_line)
                if ssid_match and ssid_match.group(1).strip():
                    net_info["ssid"] = ssid_match.group(1).strip()

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
        except Exception as e:
            print(f"[-] Windows scan error: {e}")

    # ------------------ MACOS ENGINE ------------------
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

                networks.append({
                    "ssid": ssid, "bssid": bssid, "rssi": signal_pct,
                    "channel": channel, "encryption": security
                })
        except Exception as e:
            print(f"[-] macOS scan error: {e}")
            
    return networks

def generate_visual_chart(scan_data, target_folder, timestamp):
    if not scan_data: return
    ssids = [f"{net['ssid']} (Ch:{net['channel']})" for net in scan_data[:15]]
    signals = [net['rssi'] for net in scan_data[:15]]
    
    plt.figure(figsize=(10, 6))
    colors = ['#1f77b4' if s > 70 else '#ff7f0e' if s > 40 else '#d62728' for s in signals]
    plt.barh(ssids, signals, color=colors, height=0.6)
    plt.xlabel('Signal Strength (%)')
    plt.title('Wireless Network Signal Analysis')
    plt.xlim(0, 100)
    plt.gca().invert_yaxis()
    plt.tight_layout()
    
    chart_path = os.path.join(target_folder, f"wifi_chart_{timestamp}.png")
    plt.savefig(chart_path, dpi=150)
    plt.close()

def export_report_to_desktop(scan_data):
    home_path = os.path.expanduser('~')
    target_folder = os.path.join(home_path, 'Desktop', 'Wireless_Scan_Reports')
    
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
        print(f"\n[+] Created automatic folder structure: {target_folder}")
        
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = f"wifi_report_{timestamp}.txt"
    full_file_path = os.path.join(target_folder, file_name)
    
    try:
        with open(full_file_path, 'w', encoding='utf-8') as file:
            file.write("==================================================\n")
            file.write("       WIRELESS NETWORK SECURITY & AUDIT REPORT   \n")
            file.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            file.write("==================================================\n\n")
            for idx, network in enumerate(scan_data, start=1):
                file.write(f"[{idx}] NETWORK INDEX LOG\n")
                file.write(f"    SSID:       {network['ssid']}\n")
                file.write(f"    BSSID:      {network['bssid']}\n")
                file.write(f"    Signal:     {network['rssi']}%\n")
                file.write(f"    Channel:    {network['channel']}\n")
                file.write(f"    Encryption: {network['encryption']}\n")
                file.write("-" * 50 + "\n")
        print(f"[+] Clean metric report successfully saved to: {full_file_path}")
        generate_visual_chart(scan_data, target_folder, timestamp)
    except Exception as e:
        print(f"[-] File write error: {e}")

def display_dashboard(scan_data):
    print("\n" + "="*70)
    print(f" {'SSID':<25} | {'Channel':<7} | {'Signal Strength Bar':<30} ")
    print("="*70)
    
    for net in scan_data:
        bar_chunks = int(net['rssi'] / 10)
        signal_bar = "█" * bar_chunks + "░" * (10 - bar_chunks)
        visual_bar = f"{signal_bar} ({net['rssi']}%)"
        print(f" {net['ssid'][:25]:<25} | {net['channel']:<7} | {visual_bar:<30} ")
    print("="*70 + "\n")

if __name__ == "__main__":
    results = scan_wifi_networks()
    display_dashboard(results)
    export_report_to_desktop(results)
