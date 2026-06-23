import os
import matplotlib.pyplot as plt

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
    print(f"[+] Graphical chart saved to: {chart_path}")
