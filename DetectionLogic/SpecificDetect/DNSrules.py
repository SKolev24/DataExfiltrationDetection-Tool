from rich import print, console
import math
console = console.Console()
domain_freq = {}
entropy = 0
length = 0
freq = 0
_e = False
_l = False
_f = False
confidence = 0
malicious_URL = {}
#Splitting the domain to get the base domain
def get_base_domain(domain):
    parts = domain.strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:]) + "."
    return domain

#Entropy level calculation
def shannon_entropy(domain):
    domain = "".join(part for part in domain.split("."))
    entropy = 0
    for c in set(domain):
        p_x = domain.count(c) / len(domain)
        entropy -= p_x * math.log2(p_x)
    return entropy

def frequency_calculation(base_domain):
        global domain_freq

        if base_domain not in domain_freq:
            domain_freq[base_domain] = 1
        else:
            domain_freq[base_domain] += 1

        return domain_freq[base_domain]

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

    #Frequency Fix
    freq = frequency_calculation(base)
   
    #Assign confidence and flags
    if entropy >= 4.5:
        _e = True
        confidence += 1

    if length >= 70:
        _l = True
        confidence += 1

    if freq >= 5:
        _f = True
        confidence += 1

    #Call to get result
    verdict(packet, domain, confidence,entropy, length, freq, base)


def verdict(packet, domain, confidence, entropy, length, freq, base):
  
    #Default variable assignment
    global _l, _e, _f 
    value =0
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
        malicious_URL[base] = domain_freq[base]
        for key in malicious_URL:
             value += malicious_URL[key]
        print("Total Alerts: " + str(value))
        print(message)
        return packet
    elif confidence == 3 and _e:
        message = f"[bold red]ALERT DNS[/bold red] threat discovered {display_domain} | entropy={_e_mes} length={_l_mes} freq={_f_mes}"
        malicious_URL[base] = domain_freq[base]
        for key in malicious_URL:
            value += malicious_URL[key]
        print("Total Alerts: " + str(value))
        print(message)
        return packet
    
    return packet

def dns_analysis_chain(packet, domain):
    return dns_analyse(packet, domain)
