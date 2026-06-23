import os
from datetime import datetime
import discovery
import security_flags
import visualisation

def export_text_report(scan_data, target_folder, timestamp):
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
                file.write(f"    Audit Risk: {network['risk_level']}\n")
                file.write("-" * 50 + "\n")
        print(f"[+] Text report saved to: {full_file_path}")
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
    raw_results = discovery.scan_wifi_networks()
    audited_results = security_flags.audit_security(raw_results)
    display_dashboard(audited_results)
    home_path = os.path.expanduser('~')
    target_folder = os.path.join(home_path, 'Desktop', 'Wireless_Scan_Reports')
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    export_text_report(audited_results, target_folder, timestamp)
    visualisation.generate_visual_chart(audited_results, target_folder, timestamp)
