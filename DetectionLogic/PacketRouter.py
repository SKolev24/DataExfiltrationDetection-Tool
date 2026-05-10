from rich import console
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, TCP, ICMP
from DetectionLogic.SpecificDetect.FTPrules import ftp_analysis_chain
from DetectionLogic.SpecificDetect.ICMPRules import icmp_analysis_chain
from DetectionLogic.SpecificDetect.DNSrules import dns_analysis_chain
from scapy.utils import PcapReader

console = console.Console()
is_file = None

def process_packet(packet,arg_silent):
    domain = None
    s_port = None
    d_port = None
    src = None
    dst = None
    packettype = None

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    if packet.haslayer(UDP):
        packettype = "UDP"
        s_port = packet[UDP].sport
        d_port = packet[UDP].dport
    elif packet.haslayer(TCP):
        packettype = "TCP"
        s_port = packet[TCP].sport
        d_port = packet[TCP].dport
    if packet.haslayer(DNS) and packet[DNS].qd:
        try:
            domain = packet[DNS].qd.qname.decode("utf-8")
            packettype = "DNS"
        except:
            domain = None
            

    if packettype and not arg_silent:
        console.print(f"\nPACKET INFO: {packet},\n PACKET TYPE: {packettype},\n SOURCE ADDRESS: {src},\n SOURCE PORT: {s_port},\n DESTINATION ADDRESS: {dst},\n DESTINATION PORT: {d_port}, \n LENGTH: {len(packet)},\n DOMAIN: {domain}")

    if packet.haslayer(DNS) and packet[DNS].qd and domain:
        try:
            dns_analysis_chain(packet,domain)
        except:
            pass

    if packet.haslayer(ICMP):
        try:
            icmp_analysis_chain(packet)
        except:
            pass

    if packet.haslayer(TCP):
        try:
            ftp_analysis_chain(packet)
        except:
            pass

def file_analysis(pcap, arg_silent):
    for packet in PcapReader(pcap):
        process_packet(packet,arg_silent)

