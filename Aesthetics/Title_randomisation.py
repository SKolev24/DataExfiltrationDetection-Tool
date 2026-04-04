from pyfiglet import Figlet
from rich import print

import random

FONTS = ["slant", "big", "doom", "banner3-D", "ansi_shadow", "alligator2"]

def banner(text="DEXED"):
    font = random.choice(FONTS)
    f = Figlet(font=font)
    art = f.renderText(text)
    print(f"[cyan]{art}[/cyan]")
    print(f"[cyan]Data Exfiltration Detector[/cyan]")