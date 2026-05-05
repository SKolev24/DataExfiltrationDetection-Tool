# Packages
from scapy.layers.inet import TCP, IP
import datetime

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

    dst_port = packet[TCP].dport

    if dst_port != 21:
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

# Payload handling for command detection
    ftp_payload_upper = ""

    if packet.haslayer("Raw"):
        try:
            ftp_payload = packet["Raw"].load.decode("utf-8", errors="ignore")
            ftp_payload_upper = ftp_payload.upper()
        except:
            ftp_payload_upper = ""

# Detection logic
    risk_score = 0
    ALERT = []
    currentTime = datetime.datetime.now()

    if FTP_Storage[src_ip]["sessions"] > Max_Sessions:
        risk_score += 3
        ALERT.append("High FTP frequency detected")

    if FTP_Storage[src_ip]["bytes"] > Max_Session_Bytes:
        risk_score += 3
        ALERT.append("High FTP traffic detected")

    if OFF_Hours_Start <= currentTime.hour <= OFF_Hours_End:
        risk_score += 3
        ALERT.append("Off-hours FTP activity detected")

    if FTP_Storage[src_ip]["sessions"] > 1:
        risk_score += 1
        ALERT.append("Repeated connections detected")

# Command detection
    if "STOR" in ftp_payload_upper:
        risk_score += 3
        ALERT.append("File upload detected (STOR)")

    if "APPE" in ftp_payload_upper:
        risk_score += 3
        ALERT.append("File append detected (APPE)")

    if any(ext in ftp_payload_upper for ext in (".GZ", ".7Z", ".RAR", ".ZIP")):
        risk_score += 2
        ALERT.append("Compressed file transfer detected")

# Alert if risk score exceeds threshold
    if risk_score > 5:
        print("\n[ALERT] Possible FTP Data Exfiltration Detected")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Risk Score: {risk_score}")
        print(f"Alerts: {ALERT}")
