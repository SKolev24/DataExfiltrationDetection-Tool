import datetime
import os
from rich import print, console
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.utils import wrpcap
from DetectionLogic.SpecificDetect.DNSrules import dns_analysis_chain
from scapy.utils import PcapReader
console = console.Console()
_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
_timestamp = _timestamp.replace(":", ".")
logDIR = f"logs/{_timestamp}"

pcap_file = f"{logDIR}/packet.pcap"


def process_packet(packet,arg_silent,arg_log):

    domain = None
    s_port = None
    d_port = None
    src = None
    dst = None

    if arg_log:
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

    data = {
        "timestamp": packet.time,
        "src": f"{src}:{s_port}",
        "dst": f"{dst}:{d_port}",
        "length": len(packet),
        "domain": domain
    }
    if not arg_silent:
        print(data)

    if packet.haslayer(DNS) and packet[DNS].qd:
        dns_analysis_chain(packet,domain,arg_silent)
        #--------------------- NEED HTTP AND FTB LOGIC HERE -----------------------------------
def file_analysis(pcap, arg_silent):
    for packet in PcapReader(pcap):
        process_packet(packet,arg_silent,False)

