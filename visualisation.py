import matplotlib.pyplot as plt
from rich.console import Console
from rich.table import Table

console = Console()

def generate_ascii_bar(rssi):
    """Calculates proportional steps to render visual terminal signal bars."""
    slots = max(0, min(10, int((rssi + 100) / 7)))
    return f"[{'█' * slots}{'░' * (10 - slots)}]"

def display_cli_table(networks):
    """Prints a styled, color-coded diagnostic table via Rich."""
    table = Table(title="Wireless Network Scanner - Active Environmental Reconnaissance", header_style="bold magenta")
    
    table.add_column("SSID", justify="left", style="cyan", no_wrap=True)
    table.add_column("BSSID (MAC)", justify="center", style="white")
    table.add_column("Signal Metrics", justify="left")
    table.add_column("Quality", justify="center")
    table.add_column("Channel (Band)", justify="center")
    table.add_column("Security Flag Violations", justify="left")
    
    for net in networks:
        bar = generate_ascii_bar(net['rssi'])
        signal_str = f"{net['rssi']} dBm {bar}"
        quality_str = f"[{net['color']}]{net['quality']}[/{net['color']}]"
        chan_str = f"Ch {net['channel']} ({net['band']})"
        
        has_alerts = any("None" not in f for f in net['flags'])
        alert_style = "bold red" if has_alerts else "white"
        flags_str = ", ".join(net['flags'])
        
        table.add_row(net['ssid'], net['bssid'], signal_str, quality_str, chan_str, f"[{alert_style}]{flags_str}[/{alert_style}]")
        
    console.print(table)

def generate_analytics_charts(networks):
    """Generates and updates empirical visualization plots for documentation."""
    # Chart 1: Channel Density Histogram
    channels = [net['channel'] for net in networks]
    plt.figure(figsize=(9, 4))
    plt.hist(channels, bins=range(1, 165), color='darkviolet', alpha=0.7, rwidth=0.8)
    plt.title("802.11 Spectral Channel Allocation Overview")
    plt.xlabel("Channel Assignment Vector")
    plt.ylabel("Observed Channel Densities")
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.savefig("channel_usage_report.png")
    plt.close()

    # Chart 2: RSSI Amplitude Spread
    names = [net['ssid'] if net['ssid'] else f"Hidden ({net['bssid'][:5]})" for net in networks]
    rssis = [net['rssi'] for net in networks]
    colors = ['green' if r >= -60 else 'gold' if r >= -80 else 'crimson' for r in rssis]
    
    plt.figure(figsize=(9, 4))
    plt.bar(names, rssis, color=colors)
    plt.title("Received Signal Strength Indicator (RSSI) Amplitude Comparison")
    plt.ylabel("Signal Amplitude (dBm)")
    plt.xlabel("Discovered Service Identifiers")
    plt.axhline(y=-80, color='red', linestyle=':', label='Unusable Line (-80 dBm)')
    plt.xticks(rotation=10)
    plt.tight_layout()
    plt.savefig("signal_distribution_report.png")
    plt.close()
    
    console.print("[bold green]✔[/bold green] Analytical graphs written to directory ([cyan]*.png[/cyan]).")

def export_plain_text(networks):
    """Writes a persistent clean flat-file log asset summarizing the scan."""
    filename = "scan_report.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=====================================================================\n")
        f.write("             802.11 WIRELESS RECONNAISSANCE AUDIT LOG\n")
        f.write("=====================================================================\n\n")
        for net in networks:
            f.write(f"Network Identity : {net['ssid']}\n")
            f.write(f"  BSSID / MAC    : {net['bssid']}\n")
            f.write(f"  Radio Profile  : Channel {net['channel']} [{net['band']}]\n")
            f.write(f"  Signal Metrics : {net['rssi']} dBm ({net['quality']})\n")
            f.write(f"  Security Status: {', '.join(net['flags'])}\n")
            f.write("-" * 69 + "\n")
    console.print(f"[bold green]✔[/bold green] Plain text study archive compiled at [cyan]{filename}[/cyan].")