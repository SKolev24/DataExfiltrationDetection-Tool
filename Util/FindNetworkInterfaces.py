import psutil
stats = psutil.net_if_stats()
def find_network_interface():
    available_networks = []
    for intface in stats:
        if getattr(stats[intface], "isup"):
            available_networks.append(intface)
        else:
            continue
    print(available_networks)
    return available_networks

