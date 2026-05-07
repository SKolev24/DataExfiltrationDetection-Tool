from Util.Entropy import  calculate_entropy
from scapy.layers.inet import ICMP, IP
from rich import print

# Tracks suspicious ICMP activity between source and destination
SUSPICIOUS_WINDOW_SECONDS = 60
suspicious_events = {}


def icmp_analysis_chain(packet, silent):

    # Only process ICMP Echo Requests
    if not packet.haslayer(ICMP) or not packet.haslayer(IP):
        return

    if packet[ICMP].type != 8:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    payload = bytes(packet[ICMP].payload)
    size = len(payload)

    key = (src, dst)

    # Calculate entropy (detects hidden/encoded data)
    entropy = calculate_entropy(payload)

    preview = payload[:40].decode("utf-8", errors="replace") if payload else "-"
    high_entropy = entropy > 4.5
    large_payload = size > 100

    if not high_entropy:
        return

    now = float(packet.time)
    events = suspicious_events.get(key, [])
    events = [(time, bytes_sent) for time, bytes_sent in events if now - time <= SUSPICIOUS_WINDOW_SECONDS]
    events.append((now, size))
    suspicious_events[key] = events
    count = len(events)
    total = sum(bytes_sent for _, bytes_sent in events)

    # Detection logic

    # Escalate confidence only after repeated suspicious payloads.
    if count >= 3 and total > 1000:
        print(f"[bold red]ICMP HIGH[/bold red] potential exfiltration {src} -> {dst} | for repeated high-entropy data size={size} total={total} entropy={entropy:.2f} count={count} data={preview!r}")
    elif count >= 3:
        print(f"[yellow]ICMP MEDIUM[/yellow] potential exfiltration {src} -> {dst} | for repeated high-entropy payloads size={size} total={total} entropy={entropy:.2f} count={count} data={preview!r}")
    elif large_payload:
        print(f"[yellow]ICMP LOW[/yellow] suspicious payload {src} -> {dst} | for large high-entropy ping size={size} entropy={entropy:.2f} count={count} data={preview!r}")



