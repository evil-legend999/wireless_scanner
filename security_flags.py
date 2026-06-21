# security_flags.py
# MODULE 3: Automated Security Auditing and Rogue AP Detection

from collections import defaultdict

def execute_security_audit(networks):
    """
    Scans through all discovered networks to check for security flaws
    and appends easy-to-understand warnings if any are found.
    """
    # A dictionary to keep track of network names and their physical hardware IDs (BSSIDs)
    name_to_hardware_map = defaultdict(list)
    
    for net in networks:
        # Check 1: Look for Hidden Networks
        if not net["ssid"] or net["ssid"].strip() == "":
            net["ssid"] = "[Hidden Network]"
            net["security_flags"].append(
                "SECURITY NOTICE: This network is hidden. While it seems safer, hiding a name "
                "doesn't stop hackers from finding it, and it can cause your devices to leak connection history."
            )
        
        # Check 2: Look for Completely Unprotected Networks
        if net["encryption"].upper() in ["OPEN", "NONE"]:
            net["security_flags"].append(
                "CRITICAL VULNERABILITY: Unencrypted Open Network. This network has no password. "
                "Anyone nearby can connect and potentially watch what websites you are visiting."
            )
            
        # Tally up the names and hardware IDs to check for duplicates later
        if net["ssid"] != "[Hidden Network]":
            name_to_hardware_map[net["ssid"]].append(net["bssid"])

    # Check 3: Look for Duplicate Names (Potential Evil Twin Attack)
    for net in networks:
        network_name = net["ssid"]
        if network_name in name_to_hardware_map:
            total_physical_devices = len(name_to_hardware_map[network_name])
            
            # If the exact same name is being broadcast by multiple separate hardware routers
            if total_physical_devices > 1:
                net["security_flags"].append(
                    f"THREAT WARNING: Duplicate Name Detected. There are {total_physical_devices} separate "
                    f"routers broadcasting the name '{network_name}'. If you are not at a large office, "
                    f"this could be an 'Evil Twin' attack where a hacker sets up a fake router with your "
                    f"home network's name to steal your data."
                )
            
    return networks