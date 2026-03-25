from Util.FindNetworkInterfaces import find_network_interface
from DetectionLogic.ScapyDetectionMethod import sniff_packet

find_network_interface()
print("choose interface:")
chosenInterface = input()

sniff_packet(chosenInterface)
