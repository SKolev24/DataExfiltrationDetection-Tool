import scapy.layers.dns
from scapy.layers.dns import DNS
from rich import print, console
import math
console = console.Console()

def shannon_entropy(domain):
    entropy = 0
    p_x = []
    for c in set(domain):
        p_x = domain.count(c) / len(domain)
    entropy -= p_x * math.log(p_x, 2)
    if entropy >= 0.2:
        console.print(f"[bold yellow]WARNING: suspicious entropy {domain}[/bold yellow]")
    print(f"[bold cyan]entropy: {entropy}[/bold cyan]")

def length_analysis(domain):
    if len(domain) > 130:
        console.print("[bold orange]WARNING: suspicious length[/bold orange]")
        rarity_analysis(domain)
    else:
        pass

def rarity_analysis(domain):
    freq_analysis(domain)
    pass

def freq_analysis(domain):
    isThreat = False
    if isThreat:
        console.print(f"[bold red] THREAD DISCOVERED: {domain}")

    pass

def dns_analysis_chain(packet,domain):
    console.print(f"[bold cyan]{domain}[/bold cyan]")
    shannon_entropy(domain)
