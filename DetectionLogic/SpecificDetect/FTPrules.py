# Packages
from Util.Entropy import  calculate_entropy
from scapy.layers.inet import TCP, IP
from rich import print
import datetime
import re

FTP_Storage = {}

# Baseline Thresholds for FTP Detection
Max_Session_Bytes = 5000000
Max_Sessions = 10
OFF_Hours_Start = 0
OFF_Hours_End = 6


def ftp_analysis_chain(packet, arg_silent, arg_log):

# Checks if Packet is using TCP as FTP uses TCP Protocal
    if not packet.haslayer(TCP):
        return

# Checks Packets for IP addresses
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    else:
        return

    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    if src_port != 21 and dst_port != 21:
        return

# Initial FTP_Storage preset
    if src_ip not in FTP_Storage:
        FTP_Storage[src_ip] = {
            "sessions": 0,
            "bytes": 0,
            "last_seen": None
        }

# Update session stats
    FTP_Storage[src_ip]["sessions"] += 1
    FTP_Storage[src_ip]["bytes"] += len(packet)
    FTP_Storage[src_ip]["last_seen"] = datetime.datetime.now()


    filename = ""
    ftp_payload = ""
    ftp_payload_upper = ""

    risk_score = 0
    ALERT = []
    currentTime = datetime.datetime.now()

# Command detection


    if packet.haslayer("Raw"):
        try:
            ftp_payload = packet["Raw"].load.decode("utf-8", errors="ignore")
            ftp_payload_upper = ftp_payload.upper()
        except:
            ftp_payload = ""
            ftp_payload_upper = ""

# Entropy Detection (Extracting File Name)


    if "STOR" in ftp_payload_upper or "APPE" in ftp_payload_upper:
        parts = ftp_payload_upper.split()

        if len(parts) > 1:
            filename = parts[1]

# Extracting file_name
    filename_match = re.search(
        r"([A-Za-z0-9_\-\s]+?\.(txt|zip|rar|7z|gz|csv|docx|xlsx|pdf))",
        ftp_payload,
        re.IGNORECASE
    )

    if filename_match:
        filename = filename_match.group(1).strip()

# Command detection
    if "STOR" in ftp_payload_upper:
        risk_score += 3
        ALERT.append(f"[yellow]ALERT FTP[/yellow] likely threat File upload detected (STOR)")

    if "APPE" in ftp_payload_upper:
        risk_score += 3
        ALERT.append(f"[yellow]ALERT FTP[/yellow] likely threat File Append detected (APPE)")

    if any(ext in ftp_payload_upper for ext in (".GZ", ".7Z", ".RAR", ".ZIP")):
        risk_score += 2
        ALERT.append(f"[yellow]ALERT FTP[/yellow] likely threat Compressed file transfer detected")

# Detection logic
    if FTP_Storage[src_ip]["sessions"] > Max_Sessions:
        risk_score += 3
        ALERT.append(f"[yellow]ALERT FTP[/yellow] likely threat High FTP traffic detected")

    if FTP_Storage[src_ip]["bytes"] > Max_Session_Bytes:
        risk_score += 3
        ALERT.append(f"[yellow]ALERT FTP[/yellow] likely threat High FTP traffic detected")

    if OFF_Hours_Start <= currentTime.hour <= OFF_Hours_End:
        risk_score += 3
        ALERT.append(f"[yellow]ALERT FTP[/yellow] likely threat Off-hours FTP activity detected")

    if FTP_Storage[src_ip]["sessions"] > 1:
        risk_score += 1
        ALERT.append(f"[yellow]ALERT FTP[/yellow] likely threat Repeated connections detected")

# Entropy Detection
    if filename:
        entropy_value = calculate_entropy(filename)
        if entropy_value > 4.5:
            risk_score += 4
            ALERT.append(f"[bold red] High entropy [/bold red] filename detected ({filename})")

# Alert if risk score exceeds threshold
    if risk_score > 5:
        print(f"\n[bold red] Possible FTP Data Exfiltration Detected [/bold red]")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Risk Score: {risk_score}")
        print(f"Alerts: {ALERT}")

