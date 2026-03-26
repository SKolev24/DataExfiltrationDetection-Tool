
from scapy.sendrecv import sniff
from DetectionLogic.PacketRouter import *


def sniff_packet(interface, args_silent, args_log):
    print(f"Listening on {interface}: ")
    sniff(iface=interface, prn=lambda pkt: process_packet(pkt,args_silent,args_log))
