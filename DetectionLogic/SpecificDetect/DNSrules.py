import scapy.layers.dns
from scapy.layers.dns import DNS
from rich import print, console
import math

console = console.Console()
domain_parts = []
appearance = {}
confidence = 0
entropy = 0
length = 0
freq = 0
_test_entropy = False
_test_length = False
_test_freq = False
is_silent = False


def shannon_entropy(packet, domain, arg_silent):
    global domain_parts
    global confidence
    global entropy
    confidence = 0
    domain_parts = domain.split(".")
    domain = ".".join(part for part in domain.split(".") if part)
    entropy = 0
    for c in set(domain):
        p_x = domain.count(c) / len(domain)
        entropy -= p_x * math.log2(p_x)
        if arg_silent:
            if entropy >= 4.5:
                confidence += 1
                global _test_entropy
                _test_entropy = True
                length_analysis(packet, domain, confidence)
        else:
            console.print(f"[bold cyan]{domain}[/bold cyan]")
            print(f"[bold green]entropy: {entropy}[/bold green]")
            length_analysis(packet, domain, confidence)


def length_analysis(packet, domain, confidence):
    global length
    length = len(domain)
    if length > 130:
        confidence += 1
        global _test_length
        _test_length = True
        freq_analysis(packet, domain, confidence)
    else:
        freq_analysis(packet, domain, confidence)


def freq_analysis(packet, domain, confidence):
    global freq
    domain_parts = domain.split(".")
    for part in domain_parts:
        if part in domain:
            appearance[domain] = appearance.get(domain, 0) + 1
    freq = appearance[domain]
    if freq > 5:
        confidence += 1
        global _test_freq
        _test_freq = True
        verdict(packet, domain, confidence)
    else:
        verdict(packet, domain, confidence)


def verdict(packet, domain, confidence):
    is_entropy = ""
    is_length = ""
    is_freq = ""
    Confident_T = ""
    Likely_T = ""
    Possible_T = ""

    if _test_entropy:
        is_entropy = f"[bold red]{entropy}[/bold red]"
    else:
        is_entropy = f"[bold white]{entropy}[/bold white]"
    if _test_length:
        is_length = f"[bold red]{length}[/bold red]"
    else:
        is_length = f"[bold white]{length}[/bold white]"
    if _test_freq:
        is_freq = f"[bold red]{freq}[/bold red]"
    else:
        is_freq = f"[bold white]{freq}[/bold white]"
    is_domain = f"[bold red]{domain}[/bold red]"
    if confidence == 3:
        Confident_T = f"[bold red] CONFIDENT: 3/3 [/bold red] THREAT DISCOVERED: {is_domain} \n [bold] entropy: {is_entropy} \n length: {is_length} \n freq: {is_freq} \n {packet} \n"
    elif confidence == 2:
        Likely_T = f" Confidence: 2/3, Likely Threat Discovered: {is_domain} \n entropy: {is_entropy} \n length: {is_length} \n freq: {is_freq} \n {packet} \n"
    elif confidence == 1:
        Possible_T = f" Confidence: 1/3, Possible threat discovered: {is_domain} \n entropy: {is_entropy} \n length: {is_length} \n freq: {is_freq} \n {packet} \n"
    if is_silent:
        print(Confident_T)
        print(Likely_T)
    else:
        print(Confident_T)
        print(Likely_T)
        print(Possible_T)


def dns_analysis_chain(packet, domain, arg_silent):
    global confidence, entropy, length, freq, _test_entropy, _test_length, _test_freq
    confidence = 0
    entropy = 0
    length = 0
    freq = 0
    global is_silent
    is_silent = arg_silent
    _test_entropy = False
    _test_length = False
    _test_freq = False
    shannon_entropy(packet, domain, arg_silent)