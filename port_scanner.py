"""
port_scanner.py
A simple multithreaded TCP port scanner for educational / authorized use only.

Usage:
    python port_scanner.py <target> [--start 1] [--end 1024] [--threads 100]

IMPORTANT: Only scan hosts you own or have explicit permission to test.
Scanning systems without authorization may be illegal in your jurisdiction.
"""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}


def scan_port(target: str, port: int, timeout: float = 0.5):
    """Attempt a TCP connection to a single port. Returns port if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                return port
    except socket.error:
        pass
    return None


def scan_range(target: str, start: int, end: int, max_threads: int = 100):
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port, target, port): port
            for port in range(start, end + 1)
        }
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)
    return sorted(open_ports)


def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--threads", type=int, default=100, help="Max concurrent threads")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {args.target}")
        return

    print(f"[*] Scanning {args.target} ({target_ip}) ports {args.start}-{args.end}")
    open_ports = scan_range(target_ip, args.start, args.end, args.threads)

    if not open_ports:
        print("[*] No open ports found.")
    else:
        print(f"[+] Found {len(open_ports)} open port(s):")
        for port in open_ports:
            service = COMMON_PORTS.get(port, "unknown")
            print(f"    {port}/tcp  open  {service}")


if __name__ == "__main__":
    main()
