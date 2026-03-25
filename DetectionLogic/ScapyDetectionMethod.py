from scapy.all import sniff
from scapy.utils import wrpcap
from PacketRouter import *
def sniff_packet(interface):
    sniff(iface=interface, prn=process_packet)

sniff_packet("WiFi")