import datetime
import os
from rich import console
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.utils import wrpcap
from DetectionLogic.SpecificDetect.FTPrules import ftp_analysis_chain
from DetectionLogic.SpecificDetect.ICMPRules import icmp_analysis_chain
from DetectionLogic.SpecificDetect.DNSrules import dns_analysis_chain
from scapy.utils import PcapReader

console = console.Console()
_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
_timestamp = _timestamp.replace(":", ".")
logDIR = f"logs/{_timestamp}"
pcap_file = f"{logDIR}/packet.pcap"


def _format_endpoint(address, port):
    if not address:
        return "-"
    if port is None:
        return address
    return f"{address}:{port}"


def _packet_type(packet):
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(ICMP):
        return "ICMP"
    return None


def _print_packet_row(packet, pkt_type, src, dst, length, domain):
    timestamp = datetime.datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")
    detail = f" {domain}" if domain else ""
    console.print(f"[dim]{timestamp}[/dim] [bold]{pkt_type}[/bold] {src} -> {dst} ({length} B){detail}", soft_wrap=True)


def process_packet(packet,arg_silent,arg_log, arg_import):

    domain = None
    s_port = None
    d_port = None
    src = None
    dst = None

    if arg_log and not arg_import:
        os.makedirs(logDIR, exist_ok=True)
        wrpcap(f"{logDIR}/packet.pcap", packet, append=True)

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    if packet.haslayer(UDP):
        s_port = packet[UDP].sport
        d_port = packet[UDP].dport
    elif packet.haslayer(TCP):
        s_port = packet[TCP].sport
        d_port = packet[TCP].dport


    if packet.haslayer(DNS) and packet[DNS].qd:
        try:
            domain = packet[DNS].qd.qname.decode("utf-8")
        except:
            domain = None

    src_endpoint = _format_endpoint(src, s_port)
    dst_endpoint = _format_endpoint(dst, d_port)
    pkt_type = _packet_type(packet)

    if pkt_type and not arg_silent:
        _print_packet_row(packet, pkt_type, src_endpoint, dst_endpoint, len(packet), domain)

    if packet.haslayer(DNS) and packet[DNS].qd and domain:
        dns_analysis_chain(packet,domain,arg_log)

    if packet.haslayer(ICMP):
        icmp_analysis_chain(packet, arg_silent)


    if packet.haslayer(TCP):
        ftp_analysis_chain(packet, arg_silent, arg_log)
        
def file_analysis(pcap, arg_silent, arg_log , arg_import):
    for packet in PcapReader(pcap):
        process_packet(packet,arg_silent,arg_log, arg_import)

