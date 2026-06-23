def audit_security(networks):
    for net in networks:
        enc = net["encryption"].upper()
        if "OPEN" in enc or enc == "" or "NONE" in enc:
            net["risk_level"] = "HIGH (Unencrypted)"
        elif "WEP" in enc or "WPA " in enc:
            net["risk_level"] = "MEDIUM (Outdated Protocol)"
        else:
            net["risk_level"] = "LOW (Secure)"
    return networks
