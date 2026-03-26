"""
ICMPrules.py — ICMP Exfiltration Detection

Per-packet checks (mirrors DNSrules structure):
    1. Payload size  — payloads larger than 64 bytes
    2. Entropy       — high entropy payload suggests encrypted/encoded data
    3. Type/code     — unusual ICMP type or non-zero code on echo packets

Batch checks (call icmp_batch_analysis once after the packet loop):
    4. Volume        — one host sending many echo requests to the same dst
    5. Periodicity   — evenly spaced packets of similar size (beacon pattern)
"""

import math
import statistics
from collections import defaultdict
from scapy.layers.inet import IP, ICMP
from rich.console import Console

console = Console()

# ── Thresholds ────────────────────────────────────────────────────────────────
MAX_PAYLOAD_BYTES  = 64    # normal ping payload
ENTROPY_WARN       = 6.5   # bits/byte — high = likely encrypted/encoded data
VOLUME_THRESHOLD   = 20    # echo requests from one src→dst pair
PERIODICITY_MIN    = 6     # minimum packets needed to judge timing
PERIODICITY_CV     = 0.05  # coefficient of variation — below this = too regular
UNUSUAL_TYPES      = {13, 14, 15, 16, 17, 18}

# ── Helpers ───────────────────────────────────────────────────────────────────
def _payload(pkt) -> bytes:
    return bytes(pkt[ICMP].payload) if pkt[ICMP].payload else b""

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

def _alert(rule, src, dst, msg):
    console.print(f"[bold red][{rule}][/bold red] [yellow]{src} → {dst}[/yellow]  {msg}")

# ── Per-packet checks ─────────────────────────────────────────────────────────
def icmp_analysis_chain(packet, arg_silent):
    if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
        return

    src, dst = packet[IP].src, packet[IP].dst
    icmp     = packet[ICMP]
    payload  = _payload(packet)

    if not arg_silent:
        console.print(f"[dim]ICMP {src} → {dst}  type={icmp.type}  "
                      f"payload={len(payload)}B[/dim]")

    # 1. Payload size
    if len(payload) > MAX_PAYLOAD_BYTES:
        _alert("ICMP-SIZE", src, dst,
               f"payload {len(payload)} B  frame {len(packet)} B  "
               f"(max normal: {MAX_PAYLOAD_BYTES} B)")

    # 2. Payload entropy
    if len(payload) > 0:
        h = _entropy(payload)
        if h >= ENTROPY_WARN:
            _alert("ICMP-ENTROPY", src, dst,
                   f"entropy {h:.3f} bits/byte (threshold: {ENTROPY_WARN}) "
                   "— payload may be encrypted or encoded data")

    # 3. Unusual type / non-zero code
    if icmp.type in UNUSUAL_TYPES:
        _alert("ICMP-TYPE", src, dst,
               f"unusual type {icmp.type}  (suspicious: {sorted(UNUSUAL_TYPES)})")

    if icmp.type in (0, 8) and icmp.code != 0:
        _alert("ICMP-CODE", src, dst,
               f"non-zero code {icmp.code} on echo type {icmp.type}")


# ── Batch checks (call once after the packet loop) ───────────────────────────
def icmp_batch_analysis(packets: list, arg_silent: bool):
    icmp_pkts = [p for p in packets if p.haslayer(IP) and p.haslayer(ICMP)]
    if not icmp_pkts:
        return

    # 4. Volume
    counts = defaultdict(int)
    for p in icmp_pkts:
        if p[ICMP].type == 8:
            counts[(p[IP].src, p[IP].dst)] += 1
    for (src, dst), count in counts.items():
        if count >= VOLUME_THRESHOLD:
            _alert("ICMP-VOL", src, dst,
                   f"{count} echo requests (threshold: {VOLUME_THRESHOLD})")

    # 5. Periodicity
    streams = defaultdict(list)
    for p in icmp_pkts:
        if p[ICMP].type == 8:
            streams[(p[IP].src, p[IP].dst)].append(
                (float(p.time), len(_payload(p)))
            )

    for (src, dst), entries in streams.items():
        if len(entries) < PERIODICITY_MIN:
            continue
        times     = [t for t, _ in entries]
        intervals = [times[i+1] - times[i] for i in range(len(times) - 1)]
        mean_iv   = statistics.mean(intervals)
        if mean_iv == 0:
            continue
        cv = statistics.stdev(intervals) / mean_iv
        if cv <= PERIODICITY_CV:
            _alert("ICMP-PERIOD", src, dst,
                   f"{len(entries)} echo requests  avg interval={mean_iv:.3f}s  "
                   f"CV={cv:.4f} — suspiciously regular")