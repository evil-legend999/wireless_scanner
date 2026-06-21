# visualisation.py
# MODULE 4: Pure Python Terminal Render (Zero Dependencies)

def generate_ascii_bar(dbm):
    """Creates a simple visual volume bar using standard text characters."""
    if dbm is None: 
        return "[          ]"
    strength = max(0, min(10, (dbm + 100) // 5))
    return f"[{'█' * strength}{' ' * (10 - strength)}]"

def render_dashboard_table(networks):
    """Draws a clean, organized network table using standard print statements."""
    if not networks:
        print("[!] No wireless networks found to display.")
        return

    # Print Table Header
    header_format = "{:<25} | {:<19} | {:<18} | {:<12} | {:<5} | {:<10} | {:<8}"
    row_format = "{:<25} | {:<19} | {:<18} | {:<12} | {:<5} | {:<10} | {:<8}"
    
    print("\n" + "="*111)
    print(" 🛡️  WIRELESS SPECTRUM INTELLIGENCE DASHBOARD")
    print("="*111)
    print(header_format.format("Network Name (SSID)", "Router ID (BSSID)", "Signal Strength", "Quality", "Ch", "Band", "Security"))
    print("-"*111)

    # Print Rows
    for n in networks:
        signal_display = f"{n['signal_dbm']} dBm {generate_ascii_bar(n['signal_dbm'])}"
        print(row_format.format(
            n["ssid"][:25], 
            n["bssid"], 
            signal_display, 
            n["signal_quality"], 
            str(n["channel"] or "N/A"), 
            n["frequency_band"], 
            n["encryption"]
        ))
    print("="*111)
    
    # Print Warnings
    print("\n⚠️  VULNERABILITY & TRAFFIC LOGS:")
    logged_any_warnings = False
    
    for n in networks:
        for flag in n["security_flags"]:
            print(f" • [{n['ssid']}]: {flag}")
            logged_any_warnings = True
            
    if not logged_any_warnings: 
        print(" ✓ No active security or traffic anomalies detected in this area.")

def deploy_visualisation_pipeline(networks):
    """The master switch for our pure text display layer."""
    render_dashboard_table(networks)
    # Matplotlib chart skipped to avoid the hardware instruction crash