"""
port_scanner.py
---------------
Multi-threaded TCP port scanner for network reconnaissance.
Identifies open ports and attempts basic service banner grabbing.

MITRE ATT&CK: T1046 - Network Service Discovery
Usage:
    python3 port_scanner.py --target 192.168.1.1 --ports 1-1024
    python3 port_scanner.py --target 10.0.0.5 --ports 22,80,443,3389
"""

import socket
import argparse
import threading
from datetime import datetime
from queue import Queue


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

open_ports = []
lock = threading.Lock()


def grab_banner(target, port, timeout=1):
    """Attempt to grab a service banner from an open port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(256).decode(errors='ignore').strip()
        s.close()
        return banner[:80] if banner else None
    except Exception:
        return None


def scan_port(target, port, timeout):
    """Scan a single TCP port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        s.close()
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = grab_banner(target, port)
            with lock:
                open_ports.append((port, service, banner))
    except socket.error:
        pass


def worker(target, queue, timeout):
    """Thread worker to process ports from the queue."""
    while not queue.empty():
        port = queue.get()
        scan_port(target, port, timeout)
        queue.task_done()


def parse_ports(port_string):
    """Parse port string into a list of integers."""
    ports = []
    for part in port_string.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def resolve_target(target):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve hostname: {target}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP port scanner."
    )
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--ports", default="1-1024", help="Port range e.g. 1-1024 or 22,80,443")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Connection timeout in seconds")
    args = parser.parse_args()

    ip = resolve_target(args.target)
    if not ip:
        return

    ports = parse_ports(args.ports)

    print("\n" + "="*60)
    print(f"  PORT SCANNER")
    print(f"  Target  : {args.target} ({ip})")
    print(f"  Ports   : {args.ports} ({len(ports)} total)")
    print(f"  Threads : {args.threads}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

    queue = Queue()
    for port in ports:
        queue.put(port)

    threads = []
    for _ in range(min(args.threads, len(ports))):
        t = threading.Thread(target=worker, args=(ip, queue, args.timeout))
        t.daemon = True
        t.start()
        threads.append(t)

    queue.join()

    open_ports.sort(key=lambda x: x[0])

    print(f"[+] Scan complete. {len(open_ports)} open port(s) found.\n")

    if open_ports:
        print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<15} {'BANNER'}")
        print("  " + "-"*70)
        for port, service, banner in open_ports:
            banner_str = banner if banner else ""
            print(f"  {port:<8} {'OPEN':<10} {service:<15} {banner_str}")
    else:
        print("  No open ports found in the specified range.")

    print(f"\n  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
