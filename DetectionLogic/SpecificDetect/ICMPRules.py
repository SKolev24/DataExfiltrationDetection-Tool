from scapy.layers.inet import ICMP, IP
from rich import print
import re

icmp_counter = {}
size_tracker = {}

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply"
}

def icmp_analysis_chain(packet, silent):

    if not packet.haslayer(ICMP) or not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    payload = bytes(packet[ICMP].payload)
    size = len(payload)
    icmp_type = packet[ICMP].type
    packet_length = len(packet)

    type_name = ICMP_TYPES.get(icmp_type, "Unknown")

    # Short payload preview
    preview = payload[:30]
    try:
        preview_text = preview.decode("utf-8", errors="ignore")
    except:
        preview_text = str(preview)

    if not silent:
        print(f"[blue]ICMP Packet[/blue] | {src} → {dst} | Type: {icmp_type} ({type_name}) | Size: {packet_length}")
        if preview_text:
            print(f"[dim]Payload preview:[/dim] {preview_text}")


    # Rule 1: High confidence

    if size > 100 and looks_encoded(payload):
        if not silent:
            print("[red]High confidence ICMP exfiltration detected[/red]")


    # Rule 2: Large payload

    elif size > 100:
        if not silent:
            print(f"[yellow]Large ICMP payload detected: {size} bytes[/yellow]")


    # Rule 3: Encoded payload

    elif looks_encoded(payload):
        if not silent:
            print("[yellow]Possible encoded ICMP payload[/yellow]")


    # Rule 4: High frequency

    icmp_counter[src] = icmp_counter.get(src, 0) + 1
    if icmp_counter[src] > 20:
        if not silent:
            print(f"[yellow]High ICMP activity from {src}[/yellow]")


    # Rule 5: Repeated size

    key = (src, size)
    size_tracker[key] = size_tracker.get(key, 0) + 1
    if size_tracker[key] > 10:
        if not silent:
            print(f"[yellow]Repeated ICMP packet size {size} from {src}[/yellow]")


    # Rule 6: Unusual ICMP type

    if icmp_type not in [0, 8]:
        if not silent:
            print(f"[yellow]Unusual ICMP type detected: {icmp_type} ({type_name})[/yellow]")


def looks_encoded(data):
    try:
        text = data.decode("utf-8", errors="ignore").strip()

        if len(text) < 30:
            return False

        base64_pattern = r'^[A-Za-z0-9+/=]+$'

        if re.fullmatch(base64_pattern, text):
            return True

    except:
        pass

    return False