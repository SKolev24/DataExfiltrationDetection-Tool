import os
from rich import print, console
import math
import time
import threading
from Util import freqCalc
console = console.Console()
domain_freq = {}
entropy = 0
length = 0
freq = 0
_e = False
_l = False
_f = False
confidence = 0
_seconds_window = 300


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

def pcap_analysis_frequency_calculation(base_domain, packet_time):
        if base_domain not in domain_freq:
            domain_freq[base_domain] = []
        domain_freq[base_domain].append(packet_time)
        
        valid_times = []
        
        for timestamp in domain_freq[base_domain]:
            if packet_time - timestamp <= _seconds_window:
                valid_times.append(timestamp)

        domain_freq[base_domain] = valid_times
        return len(valid_times)

def dns_analyse(packet, domain):
    from DetectionLogic.PacketRouter import is_file
    #Default Definitions
    global domain_freq, confidence, _e, _l, _f,entropy, length, freq
    _e,_l,_f = False,False,False
    confidence = 0

    #Assign all values to according list elements
    entropy = shannon_entropy(domain)
    length = len(domain)

    #Calculate Base Domain Frequency
    base = get_base_domain(domain)

    #Frequency Fix
    if is_file is True:
        pcap_analysis_frequency_calculation(base, packet.time)
    else: 
        freq = freqCalc(domain_freq, base, 5, 60)
    
    #Assign confidence and flags
    if entropy >= 4.5:
        _e = True
        confidence += 1

    if length >= 70:
        _l = True
        confidence += 1

    if freq:
        _f = True
        confidence += 1

    #Call to get result
    verdict(packet, domain, confidence,entropy, length, freq)


def verdict(packet, domain, confidence, entropy, length, freq):
  
    #Default variable assignment
    global _l, _e, _f
    _e_mes = f"[bold white]{entropy:.2f}[/bold white]"
    _l_mes = f"[bold white]{length}[/bold white]"
    _f_mes = f"[bold white]{freq}[/bold white]"
    if _e:
        _e_mes = f"[bold red]{entropy:.2f}[/bold red]"
    if _l:
        _l_mes = f"[bold red]{length}[/bold red]"
    if _f:
        _f_mes = f"[bold red]{freq}[/bold red]"

    display_domain = f"[bold red]{domain}[/bold red]"

    #Printing Results
    if confidence == 2 and _e:
        message = f"[yellow]ALERT DNS[/yellow] likely threat {display_domain} | entropy={_e_mes} length={_l_mes} freq={_f_mes}"
        print(message)
        return packet
      

    elif confidence == 3 and _e:
        message = f"[bold red]ALERT DNS[/bold red] threat discovered {display_domain} | entropy={_e_mes} length={_l_mes} freq={_f_mes}"
        print(message)
        return packet
    return packet

def dns_analysis_chain(packet, domain):
    global _pcap, _arg_log
    return dns_analyse(packet, domain)
