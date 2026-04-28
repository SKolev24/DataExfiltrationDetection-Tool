from scapy.layers.inet import ICMP, IP
from rich import print
import math

# Tracks total data sent between source and destination
data_volume = {}

def icmp_analysis_chain(packet, silent):

    # Only process ICMP Echo Requests (real exfiltration method)
    if not packet.haslayer(ICMP) or not packet.haslayer(IP):
        return

    if packet[ICMP].type != 8:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    payload = bytes(packet[ICMP].payload)
    size = len(payload)

    key = (src, dst)


    # Payload preview

    preview = payload[:40]
    try:
        preview_text = preview.decode("utf-8", errors="ignore")
    except:
        preview_text = str(preview)

    if not silent:
        print(f"[blue]ICMP[/blue] {src} → {dst} | Size: {len(packet)}")
        if preview_text:
            print(f"[dim]Payload:[/dim] {preview_text}")


    # Calculate entropy (detects hidden/encoded data)

    entropy = calculate_entropy(payload)

    # Track total data sent (detects slow exfiltration)
    data_volume[key] = data_volume.get(key, 0) + size


    # Detection logic

    # High confidence: large + high entropy
    if size > 100 and entropy > 4.5:
        if not silent:
            print("[red]ICMP Exfiltration Detected[/red]")

    # Slow exfiltration: lots of small packets over time
    elif data_volume[key] > 1000:
        if not silent:
            print(f"[yellow]High data transfer over ICMP from {src}[/yellow]")

    # Suspicious payload (unknown encoding / randomness)
    elif entropy > 4.5:
        if not silent:
            print("[yellow]High entropy ICMP payload[/yellow]")


# -------------------------
# Entropy calculation helper
# -------------------------
def calculate_entropy(data):
    if not data:
        return 0

    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    entropy = 0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)

    return entropy