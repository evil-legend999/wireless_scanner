# main.py
# APPLICATION ENTRY POINT: The Core Architecture Orchestrator

import sys
from discovery import discover_networks
from signal_analysis import process_signal_metrics
from security_flags import execute_security_audit
from visualisation import deploy_visualisation_pipeline

def main():
    print("[Engine] Booting core network scanner framework...\n")
    
    # STEP 1: Tell Module 1 (discovery) to scan the airwaves using your Wi-Fi card.
    raw_data = discover_networks(interface="wlan0")
    
    # STEP 2: Safety Net. If your computer doesn't have a compatible Wi-Fi card, 
    # instead of crashing or staying blank, we inject safe, simulated "test data" 
    # so you can see the entire analytics engine work perfectly anyway!
    if not raw_data:
        print("[Notice] No physical wireless card detected. Injecting safe simulation data to test the pipeline...")
        raw_data = [
            {"ssid": "My-Home-WiFi", "bssid": "00:11:22:33:44:55", "signal_dbm": -42, "channel": 6, "frequency_band": "2.4 GHz", "encryption": "WPA2", "signal_quality": "", "security_flags": []},
            {"ssid": "Neighbors-Router", "bssid": "AA:BB:CC:DD:EE:FF", "signal_dbm": -68, "channel": 11, "frequency_band": "2.4 GHz", "encryption": "WPA2", "signal_quality": "", "security_flags": []},
            {"ssid": "Suspicious-Clone", "bssid": "AA:BB:CC:DD:EE:11", "signal_dbm": -70, "channel": 11, "frequency_band": "2.4 GHz", "encryption": "WPA2", "signal_quality": "", "security_flags": []},
            {"ssid": "", "bssid": "11:22:33:44:55:66", "signal_dbm": -85, "channel": 36, "frequency_band": "5 GHz", "encryption": "OPEN", "signal_quality": "", "security_flags": []}
        ]

    # STEP 3: Pass the raw data to Module 2 (signal_analysis) to check signal quality and channel congestion.
    stage_1 = process_signal_metrics(raw_data)
    
    # STEP 4: Pass those results to Module 3 (security_flags) to hunt for vulnerabilities and Evil Twins.
    stage_2 = execute_security_audit(stage_1)
    
    # STEP 5: Pass the fully audited data to Module 4 (visualisation) to draw the table and make the chart.
    deploy_visualisation_pipeline(stage_2)
    
    print("\n[Engine] Run complete! Your visual charts and terminal tables have been successfully updated.")

if __name__ == "__main__":
    main()