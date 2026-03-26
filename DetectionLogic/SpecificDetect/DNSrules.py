import scapy.layers.dns
from scapy.layers.dns import DNS
from rich import print, console
import math
console = console.Console()
domain_parts = []
appearance={}
def shannon_entropy(domain):
    global domain_parts
    domain_parts = domain.split(".")
    domain = ".".join(part for part in domain.split(".") if part)
    entropy = 0
    p_x = []
    for c in set(domain):
        p_x = domain.count(c) / len(domain)
    entropy -= p_x * math.log(p_x, 2)
    if entropy >= 0.45:
        console.print(f"[bold yellow]WARNING: suspicious entropy {domain}[/bold yellow]")
        length_analysis(domain)
    print(f"[bold cyan]entropy: {entropy}[/bold cyan]")

def length_analysis(domain):
    if len(domain) > 130:
        console.print("[bold orange]WARNING: suspicious length[/bold orange]")
        rarity_analysis(domain)
    else:
        pass

def rarity_analysis(domain):
        appearance[domain] = appearance.get(domain, 0) + 1
        if appearance[domain] > 5:
            freq_analysis(domain)
        else
            pass

def freq_analysis(domain):
    isThreat = False
    for domains in appearance:
        if domain_parts[1] in appearance[domains] and domain_parts[0] != appearance[domains.split(".")[0]]:
            isThreat = True
        else:
            pass

    if isThreat:
        console.print(f"[bold red] THREAT DISCOVERED: {domain}")

def dns_analysis_chain(packet,domain):
    console.print(f"[bold cyan]{domain}[/bold cyan]")
    shannon_entropy(domain)
