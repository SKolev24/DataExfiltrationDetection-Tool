import scapy.layers.dns
from scapy.layers.dns import DNS
import math
is_suspicious = False

def length_analysis(packet):
    if len(packet) > 118:
        is_suspicious = True
        print("WARNING: suspicious length")
    else:
        pass

def shannon_entropy(packet):
    p_x = []
    dnsDomain = packet[DNS].qd.qname.decode("utf-8")
    for c in dnsDomain:
        p_x = dnsDomain.count(c) / len(dnsDomain)
    entropy = math.log(p_x, 2)
    if entropy > 0.5:
        is_suspicious = True
        print("WARNING: suspicious entropy")


def dns_analysis_chain(packet):
    if packet.haslayer(DNS):
        length_analysis(packet)
        shannon_entropy(packet)
