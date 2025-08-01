import argparse
import nmap
import csv
import os
import sys

def scan_host(ip, ports):
    nm = nmap.PortScanner()
    nm.scan(ip, ports)
    results = []

    for proto in nm[ip].all_protocols():
        ports_list = nm[ip][proto].keys()
        for port in ports_list:
            service = nm[ip][proto][port]
            result = {
                'ip': ip,
                'os': nm[ip].get('osclass', {}).get('osfamily', 'Unknown'),
                'port': port,
                'name': service.get('name', ''),
                'product': service.get('product', ''),
                'version': service.get('version', '')
            }
            results.append(result)
    return results

def save_to_csv(filename, data):
    headers = ["ip", "os", "port", "name", "product", "version"]
    file_exists = os.path.isfile(filename)

    with open(filename, "a", newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

def main():
    parser = argparse.ArgumentParser(description="Scan a host for open ports and services")
    parser.add_argument("host", help="Target IP address")
    parser.add_argument("-p", "--ports", required=True, help="Ports to scan (e.g. 22,80,443)")
    parser.add_argument("-o", "--output", default="scan_results.csv", help="Output CSV file")

    args = parser.parse_args()
    ip = args.host
    ports = args.ports
    output = args.output

    print(f"Scanning {ip} on ports {ports}...\n")
    sys.stdout.write("Scanning "); sys.stdout.flush()

    results = scan_host(ip, ports)

    for result in results:
        save_to_csv(output, result)

    print("\n\n--- Scan Results ---")
    for r in results:
        print(f"IP: {r['ip']}")
        print(f"OS: {r['os']}")
        print(f"Port: {r['port']}")
        print(f"Service: {r['name']}")
        print(f"Product: {r['product']}")
        print(f"Version: {r['version']}\n")

if __name__ == "__main__":
    main()
