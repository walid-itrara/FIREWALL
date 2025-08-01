import sys
import ping_sweep_and_port_scanner
import os_fingerprint

def main():
    if len(sys.argv) != 3:
        print("Usage: python wrapper_scanner.py <subnet> <mask>")
        sys.exit(1)

    subnet = sys.argv[1]
    mask = sys.argv[2]

    live_hosts = ping_sweep_and_port_scanner.ping_sweep(subnet, mask)
    print("\nPing sweep completed.\n")

    for host in live_hosts:
        print(f"Scanning host: {host}")
        open_ports = ping_sweep_and_port_scanner.port_scan(host, list(range(1, 1024)))
        print(f"Open ports: {open_ports}\n")

        for port in open_ports:
            host_infos = os_fingerprint.scan_host(host, str(port))
            for info in host_infos:
                os_fingerprint.save_to_csv("scan_results.csv", info)
                print("Scan result:")
                for key, value in info.items():
                    print(f"{key}: {value}")
                print()

if __name__ == "__main__":
    main()
