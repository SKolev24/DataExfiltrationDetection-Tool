from scapy.all import sniff
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP, TCP

from DetectionLogic.SpecificDetect.DNSrules import dns_analysis_chain


def process_packet(packet):
    domain = None
    s_port = None
    d_port = None
    src = None
    dst = None


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
    if packet.haslayer(DNS) and packet[DNS].qd:
        dns_analysis_chain(packet)


    print(data)






