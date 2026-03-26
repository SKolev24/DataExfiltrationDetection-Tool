
from scapy.sendrecv import sniff
from DetectionLogic.PacketRouter import *


def sniff_packet(interface, args_silent):
    print(f"Listening on {interface}: ")
    sniff(iface=interface, prn=process_packet)
