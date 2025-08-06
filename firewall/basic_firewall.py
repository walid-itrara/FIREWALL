import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from datetime import datetime

THRESHOLD = 40  # Packets/sec
LOG_FILE = "logs/network_monitor.log"
BLOCK_COMMAND = "iptables -A INPUT -s {ip} -j DROP"
DRY_RUN = False  # Simule les blocages si True

print(f"[+] THRESHOLD SET TO {THRESHOLD} pkt/s")


def ensure_log_folder():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def log_event(message):
    ensure_log_folder()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log:
        log.write(f"[{timestamp}] {message}\n")


def block_ip(ip, reason=""):
    if DRY_RUN:
        print(f"[SIMULATION] Block {ip} - {reason}")
    else:
        os.system(BLOCK_COMMAND.format(ip=ip))
        print(f"[BLOCKED] {ip} - {reason}")
        log_event(f"Blocked {ip} - {reason}")


def read_ip_file(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, "r") as file:
        return {line.strip() for line in file if line.strip()}


def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = bytes(packet[TCP].payload).decode(errors="ignore")
        return "GET /scripts/root.exe" in payload
    return False


def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    # Whitelisted IPs are ignored
    if src_ip in whitelist_ips:
        return

    # Blacklisted IPs are blocked
    if src_ip in blacklist_ips and src_ip not in blocked_ips:
        block_ip(src_ip, "Listed in blacklist")
        blocked_ips.add(src_ip)
        return

    # Detect Nimda worm
    if is_nimda_worm(packet) and src_ip not in blocked_ips:
        block_ip(src_ip, "Nimda worm signature detected")
        blocked_ips.add(src_ip)
        return

    # Count packets
    packet_count[src_ip] += 1

    current_time = time.time()
    interval = current_time - start_time[0]

    if interval >= 1.0:
        for ip, count in packet_count.items():
            rate = count / interval
            if rate > THRESHOLD and ip not in blocked_ips:
                block_ip(ip, f"Packet rate = {rate:.2f} pkt/s")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Run as root")
        sys.exit(1)

    # Load IP lists
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("[*] Monitoring network traffic... (Press Ctrl+C to stop)")
    log_event("Monitoring started")
    try:
        sniff(filter="ip", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")
        log_event("Monitoring stopped")
