from Util.Entropy import calculate_entropy
from scapy.layers.inet import ICMP, IP
from rich import print


ICMP_Storage = {}

# Baseline thresholds for ICMP detection
Entropy_Threshold = 4.5
Large_Payload_Size = 100
Repeated_Packets = 3
High_Total_Bytes = 1000
Time_Window = 60


def icmp_analysis_chain(packet, silent):

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
    if entropy_value <= Entropy_Threshold:
        return

# Initial ICMP_Storage preset
    if key not in ICMP_Storage:
        ICMP_Storage[key] = {
            "start_time": packet_time,
            "packets": 0,
            "bytes": 0
        }

# Reset counters when the packet is outside the time window
    if packet_time - ICMP_Storage[key]["start_time"] > Time_Window:
        ICMP_Storage[key] = {
            "start_time": packet_time,
            "packets": 0,
            "bytes": 0
        }

# Update suspicious ICMP stats
    ICMP_Storage[key]["packets"] += 1
    ICMP_Storage[key]["bytes"] += payload_size

    packet_count = ICMP_Storage[key]["packets"]
    total_bytes = ICMP_Storage[key]["bytes"]
    preview = payload[:40].decode("utf-8", errors="replace") if payload else "-"

# Confidence level checks
    if packet_count >= Repeated_Packets and total_bytes > High_Total_Bytes:
        print(f"[bold red]ICMP HIGH[/bold red] potential exfiltration {src_ip} -> {dst_ip} | for repeated high-entropy data size={payload_size} total={total_bytes} entropy={entropy_value:.2f} count={packet_count} data={preview!r}")

    elif packet_count >= Repeated_Packets:
        print(f"[yellow]ICMP MEDIUM[/yellow] potential exfiltration {src_ip} -> {dst_ip} | for repeated high-entropy payloads size={payload_size} total={total_bytes} entropy={entropy_value:.2f} count={packet_count} data={preview!r}")

    elif payload_size > Large_Payload_Size:
        print(f"[yellow]ICMP LOW[/yellow] suspicious payload {src_ip} -> {dst_ip} | for large high-entropy ping size={payload_size} entropy={entropy_value:.2f} count={packet_count} data={preview!r}")
