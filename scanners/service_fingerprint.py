import argparse
import socket

def get_service_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, int(port)))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
        sock.send(request.encode())
        banner = sock.recv(1024)
        sock.close()
        return banner.decode('utf-8', errors='ignore')
    except socket.timeout:
        return "Timeout: No response"
    except socket.error as e:
        return f"Connection error: {e}"
    except Exception as e:
        return f"Error: {e}"

def main():
    parser = argparse.ArgumentParser(description='Service Banner Scanner')
    parser.add_argument('ip', help='IP address to scan')
    parser.add_argument('-p', '--ports', required=True, help='Ports to scan (séparés par virgule)')

    args = parser.parse_args()
    ip = args.ip
    ports = args.ports.split(',')

    print(f"Scanning IP: {ip}")
    for port in ports:
        port = port.strip()
        if not port.isdigit():
            print(f"Invalid port: {port}")
            continue
        print(f"Scanning port {port}...")
        banner = get_service_banner(ip, port)
        print(f"Result for port {port}: {banner}\n")

if __name__ == "__main__":
    main()
