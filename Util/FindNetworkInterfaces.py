import psutil
addresses = psutil.net_if_addrs()
stats = psutil.net_if_stats()
def find_network_interface():
    available_networks = []
    for intface, addr_list in addresses.items():
        if intface in stats and getattr(stats[intface], "isup"):
            available_networks.append(intface)
        else:
            continue
    print(available_networks)
    return available_networks

find_network_interface()