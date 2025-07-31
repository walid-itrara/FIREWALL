import sys
from scapy.all import ICMP, IP, sr1
from netaddr import IPNetwork

def ping_sweep(network, netmask):
    live_hosts = []
    ip_network = IPNetwork(f"{network}/{netmask}")
    hosts = list(ip_network.iter_hosts())
    total_hosts = len(hosts)

    print(f"Scanning {total_hosts} hosts in network {ip_network}...\n")

    scanned = 0
    for host in hosts:
        scanned += 1
        print(f"Scanning {scanned}/{total_hosts} - {host}", end="\r")
        reponse = sr1(IP(dst=str(host)) / ICMP(), timeout=1, verbose=0)
        if reponse:
            live_hosts.append(str(host))
            print(f"[+] Host {host} is online.")

    return live_hosts

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python ping_sweep.py <network> <netmask>")
        print("Example: python ping_sweep.py 192.168.1.0 24")
        sys.exit(1)

    network = sys.argv[1]
    netmask = sys.argv[2]

    live_hosts = ping_sweep(network, netmask)

    print("\n✅ Scan completed.")
    print(f"Live hosts ({len(live_hosts)}):")
    for host in live_hosts:
        print(f" - {host}")
