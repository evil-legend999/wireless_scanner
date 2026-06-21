# signal_analysis.py
# MODULE 2: Signal Metrics Analysis and Spectrum Congestion Tracking

def classify_rssi(dbm):
    """
    Translates raw Wi-Fi signal numbers into simple everyday language.
    In radio signals, numbers are negative. The closer to 0, the stronger the signal.
    """
    if dbm is None: 
        return "Unknown"
        
    if dbm >= -50: 
        return "Excellent"
    elif dbm >= -60: 
        return "Good"
    elif dbm >= -70: 
        return "Fair"
    elif dbm >= -80: 
        return "Weak"
    else:
        return "Very Weak / Unusable"


def evaluate_channel_congestion(networks):
    """
    Checks if multiple Wi-Fi routers are stepping on each other's toes
    by trying to use the exact same radio channel at the same time.
    """
    # Create a simple tally sheet to count how many routers are on each channel
    channel_counts = {}
    for net in networks:
        current_channel = net["channel"]
        if current_channel is not None:
            # If the channel isn't on our sheet yet, start counting at 0, then add 1
            channel_counts[current_channel] = channel_counts.get(current_channel, 0) + 1
            
    # Go back through our networks and flag the ones sharing crowded channels
    for net in networks:
        current_channel = net["channel"]
        if current_channel is not None:
            total_routers_on_this_channel = channel_counts[current_channel]
            
            # If there's more than 1 router using this channel, it's overcrowded
            if total_routers_on_this_channel > 1:
                warning_message = f"Spectrum Congestion: Channel {current_channel} has {total_routers_on_this_channel} competing networks."
                net["security_flags"].append(warning_message)
                
    return networks


def process_signal_metrics(networks):
    """
    The master button for this module. It updates the human-readable 
    quality words and labels the crowded channels.
    """
    for net in networks:
        net["signal_quality"] = classify_rssi(net["signal_dbm"])
        
    return evaluate_channel_congestion(networks)