import time

def calculate_transmission_time(transmit_value, rtt_ms):
    # Get the current Unix time in milliseconds
    current_epoch_ms = int(time.time() * 1000)
    # Calculate the ICMP timestamp difference
    transmission_time_ms = transmit_value - (rtt_ms / 2)
    # Calculate the transmission Unix timestamp
    transmission_unix_timestamp_ms = current_epoch_ms - transmission_time_ms
    # Convert milliseconds to seconds for time.gmtime()
    transmission_unix_timestamp_s = transmission_unix_timestamp_ms / 1000
    # Convert to human-readable format
    transmission_time_human = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(transmission_unix_timestamp_s))
    return transmission_time_human

transmit_value = 56863598
rtt = 76

print(f"Transmission time: {calculate_transmission_time(transmit_value, rtt)}")
