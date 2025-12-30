from scapy.all import *
from datetime import datetime

TARGET_IP = "192.168.204.130"
LOG_FILE = "firewall_logs.txt"

def monitor_traffic(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        
        if source_ip == TARGET_IP:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] 🛑 BLOCKED: {source_ip} attempted access\n"
            
            # Print to screen
            print(log_entry.strip())
            
            # Save to file
            with open(LOG_FILE, "a") as f:
                f.write(log_entry)
        else:
            print(f"✅ ALLOWED: {source_ip}")

print(f"--- Firewall Active. Logs saving to {LOG_FILE} ---")
sniff(prn=monitor_traffic, store=0)
