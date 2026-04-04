import os
from rich import print, console
import math
from scapy.utils import wrpcap

_arg_log = False

console = console.Console()
_pcap = ""
domain_freq = {}

entropy = 0
length = 0
freq = 0

_e = False
_l = False
_f = False

confidence = 0


#Splitting the domain to get the base domain
def get_base_domain(domain):
    parts = domain.strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:]) + "."
    return domain

#Entropy level calculation
def shannon_entropy(domain):
    domain = ".".join(part for part in domain.split(".") if part)
    entropy = 0
    for c in set(domain):
        p_x = domain.count(c) / len(domain)
        entropy -= p_x * math.log2(p_x)
    return entropy

def dns_analyse(packet, domain):

    #Default Definitions
    global domain_freq, confidence, _e, _l, _f,entropy, length, freq
    _e,_l,_f = False,False,False
    confidence = 0

    #Assign all values to according list elements
    entropy = shannon_entropy(domain)
    length = len(domain)

    #Calculate Base Domain Frequency
    base = get_base_domain(domain)
    if base not in domain_freq:
        domain_freq[base] = 0
    domain_freq[base] += 1
    freq = domain_freq[base]

    #Assign confidence and flags
    if entropy >= 4.5:
        _e = True
        confidence += 1

    if length >= 135:
        _l = True
        confidence += 1

    if freq > 5:
        _f = True
        confidence += 1

    #Call to get result
    verdict(packet, domain, confidence,entropy, length, freq)


def verdict(packet, domain, confidence, entropy, length, freq):
    from DetectionLogic.PacketRouter import logDIR
    #Default variable assignment
    global _l, _e, _f, _arg_log
    _e_mes = f"[bold white]{entropy}[/bold white]"
    _l_mes = f"[bold white]{length}[/bold white]"
    _f_mes = f"[bold white]{freq}[/bold white]"

    if _e:
        _e_mes = f"[bold red]{entropy}[/bold red]"
    if _l:
        _l_mes = f"[bold red]{length}[/bold red]"
    if _f:
        _f_mes = f"[bold red]{freq}[/bold red]"

    domain = f"[bold red]{domain}[/bold red]"

    #Printing Results
    if confidence == 2 and _e:
        message = (f"Likely Threat: {domain} \n entropy: {_e_mes} \n length: {_l_mes} \n freq: {_f_mes} \n {packet} \n"
                   f"/n")
        print(message)
        if _arg_log:
            os.makedirs(logDIR, exist_ok=True)
            wrpcap(f"{logDIR}/DNS_RESULT_packet.pcap", packet, append=True)

    elif confidence == 3 and _e:
        message = (f"[bold red]****[/bold red]THREAT Discovered: {domain} \n entropy: {_e_mes} \n length: {_l_mes} \n freq: {_f_mes} \n {packet} \n"
                   f"/n")
        print(message)
        if _arg_log:
            os.makedirs(logDIR, exist_ok=True)
            wrpcap(f"{logDIR}/DNS_RESULT_packet.pcap", packet, append=True)

def dns_analysis_chain(packet, domain, arg_log):
    global _pcap, _arg_log
    _arg_log = arg_log
    dns_analyse(packet, domain)
