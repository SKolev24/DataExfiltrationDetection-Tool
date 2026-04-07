from scapy.layers.inet import ICMP, IP
from rich import print
import re

icmp_counter = {}
size_tracker = {}

def icmp_analysis_chain(packet, silent):

    if not packet.haslayer(ICMP) or not packet.haslayer(IP):
        return

    src = packet[IP].src
    payload = bytes(packet[ICMP].payload)
    size = len(payload)
    icmp_type = packet[ICMP].type

    # Rule 1: High confidence (encoded + large)
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

    # Rule 5: Repeated packet size
    key = (src, size)
    size_tracker[key] = size_tracker.get(key, 0) + 1
    if size_tracker[key] > 10:
        if not silent:
            print(f"[yellow]Repeated ICMP packet size {size} from {src}[/yellow]")

    # Rule 6: Unusual ICMP type
    if icmp_type not in [0, 8]:
        if not silent:
            print(f"[yellow]Unusual ICMP type detected: {icmp_type}[/yellow]")


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