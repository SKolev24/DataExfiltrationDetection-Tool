from rich.console import Console
import argparse

if __name__ == "__main__":
    console = Console()
    from DetectionLogic.ScapyDetectionMethod import sniff_packet
    from Util.FindNetworkInterfaces import find_network_interface

    parser = argparse.ArgumentParser(prog="Data Exfiltration Detector",
                                     description="Usage: e.g. 1: python3 main.py -i <pcap_file> "
                                                 "\n e.g. 2: python3 main.py -l")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-l",
                        "--live-capture",
                        "--live" ,
                        help="Analyse packets on live continuous capture on specific interface.",
                        action="store_true")

    group.add_argument("-i",
                        "--import-pcap",
                        "--import" ,
                        help="Analyse specified pcap files",
                       nargs=1,)

    parser.add_argument("-s",
                        "--silent",
                        help="Filter output to show results only",
                        action="store_true")

    args = parser.parse_args()

    if args.silent and not args.live_capture or args.silent and not args.import_pcap:
        parser.error("-s/--silent can only be used in combination with -l/--live-capture or -p/--import_pcap")

    if args.live_capture:
        find_network_interface()
        console.print("choose interface:")
        chosenInterface = input()
        sniff_packet(chosenInterface,args.silent)

    if args.import_pcap:
        from DetectionLogic.PacketRouter import file_analysis
        file_analysis(args.import_pcap,args.silent)


