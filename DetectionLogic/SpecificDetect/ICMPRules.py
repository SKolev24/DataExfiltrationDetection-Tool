from Util.Entropy import calculate_entropy
from scapy.layers.inet import ICMP, IP
from rich import print

icmp_storage = {}
entropy_threshold = 4.5
large_payload_size = 100
repeated_packets = 8
high_volume_threshold = 1000
time_window = 60

def icmp_analysis_chain(packet):

# Checks if packet is ICMP over IP
    if not packet.haslayer(ICMP) or not packet.haslayer(IP):
        return

# Only checks ICMP echo requests
    if packet[ICMP].type != 8:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    payload = bytes(packet[ICMP].payload)
    payload_size = len(payload)
    entropy_value = calculate_entropy(payload)
    packet_time = float(packet.time)
    key = (src_ip, dst_ip)

# Ignore normal low entropy ICMP traffic
    if entropy_value <= entropy_threshold:
        return

# Initial preset
    if key not in icmp_storage:
        icmp_storage[key] = {
            "start_time": packet_time,
            "packets": 0,
            "bytes": 0
        }

# Reset counters when the packet is outside the time window
    if packet_time - icmp_storage[key]["start_time"] > time_window:
        icmp_storage[key] = {
            "start_time": packet_time,
            "packets": 0,
            "bytes": 0
        }

# Update suspicious ICMP stats
    icmp_storage[key]["packets"] += 1
    icmp_storage[key]["bytes"] += payload_size

    packet_count = icmp_storage[key]["packets"]
    total_bytes = icmp_storage[key]["bytes"]
    preview = payload[:40].decode("utf-8", errors="replace")

# Confidence level checks
    if packet_count >= repeated_packets and total_bytes > high_volume_threshold:
        print(f"[bold red]ICMP HIGH[/bold red] potential exfiltration {src_ip} -> {dst_ip} | for repeated high-entropy data size={payload_size} total={total_bytes} entropy={entropy_value:.2f} count={packet_count} data={preview!r}")

    elif packet_count >= repeated_packets:
        print(f"[yellow]ICMP MEDIUM[/yellow] potential exfiltration {src_ip} -> {dst_ip} | for repeated high-entropy payloads size={payload_size} total={total_bytes} entropy={entropy_value:.2f} count={packet_count} data={preview!r}")

    elif payload_size > large_payload_size:
        print(f"[yellow]ICMP LOW[/yellow] suspicious payload {src_ip} -> {dst_ip} | for large high-entropy ping size={payload_size} entropy={entropy_value:.2f} count={packet_count} data={preview!r}")
