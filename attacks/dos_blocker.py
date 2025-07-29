import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

# Configuration
THRESHOLD = 40
IPTABLES_CMD = "iptables -A INPUT -s {ip} -j DROP"

print(f"[INFO] Packet rate threshold set to {THRESHOLD} packets/sec")


packet_count = defaultdict(int)
start_time = [time.time()]
blocked_ips = set()

def block_ip(ip, rate):

    os.system(IPTABLES_CMD.format(ip=ip))
    print(f"[BLOCKED] IP {ip} with rate {rate:.2f} packets/sec")
    blocked_ips.add(ip)

def packet_callback(packet):

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1.0:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                block_ip(ip, packet_rate)

        packet_count.clear()
        start_time[0] = current_time

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root.")
        sys.exit(1)

    print("[INFO] Monitoring network traffic... Press Ctrl+C to stop.")
    try:
        sniff(filter="ip", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Sniffing stopped.")
