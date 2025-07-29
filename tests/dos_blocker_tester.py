import sys
import time
from scapy.all import Ether, IP, TCP, sendp, conf


TARGET_IP = "192.168.1.10"
INTERFACE = conf.iface
NUM_PACKETS = 100
DURATION = 5


def send_packets(target_ip, interface, num_packets, duration):
    packet = Ether() / IP(dst=target_ip) / TCP(dport=80, flags="S")
    end_time = time.time() + duration
    packet_count = 0

    print(f"[INFO] Envoi de paquets TCP vers {target_ip} via {interface}...")

    while time.time() < end_time and packet_count < num_packets:
        sendp(packet, iface=interface, verbose=False)
        packet_count += 1
        print(f"[+] Paquet {packet_count} envoyé")

    print(f"[✔] {packet_count} paquets envoyés.")


if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("Ce script nécessite Python 3.")
        sys.exit(1)

    send_packets(TARGET_IP, INTERFACE, NUM_PACKETS, DURATION)
