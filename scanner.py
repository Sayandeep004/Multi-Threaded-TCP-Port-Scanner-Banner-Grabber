"""
Multi-Threaded TCP Port Scanner & Service Banner Grabber.

Key Networking Concepts Demonstrated:
1. TCP 3-Way Handshake (SYN -> SYN-ACK -> ACK)
2. Socket connection states (Open = 0, Closed = RST/ECONNREFUSED, Filtered = Timeout)
3. Application-layer Banner Grabbing (identifying running software like SSH or Apache)
4. Concurrent connection pooling using ThreadPoolExecutor
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import socket
import sys
import time

# Common well-known ports and their associated service names
WELL_KNOWN_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web)",
    110: "POP3 (Mail)",
    143: "IMAP (Mail)",
    443: "HTTPS (Secure Web)",
    445: "SMB (File Sharing)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    6379: "Redis In-Memory Store",
    8080: "HTTP-Proxy / Alt-Web",
    8443: "HTTPS-Alt",
    9000: "SonarQube / Web Alt",
    9999: "NetBench / Custom Test",
}


def grab_banner(target_ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempts to read the application-layer banner from an open port.
    Many services (SSH, FTP, SMTP) send a welcome message immediately upon connection.
    Web servers reply with server headers when sent a basic HTTP request.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))

            # If it looks like a web port, send a lightweight HTTP HEAD request
            if port in [80, 8080, 8443, 8000]:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")

            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            # Clean up banner to show only first line or Server header
            for line in banner.splitlines():
                if line.lower().startswith("server:") or "ssh" in line.lower() or "ftp" in line.lower():
                    return line
            return banner.splitlines()[0] if banner else "No banner returned"
    except Exception:
        return "No banner returned"


def scan_port(target_ip: str, port: int, timeout: float = 0.8) -> dict:
    """
    Probes a single TCP port using a 3-way handshake.
    
    Returns a dictionary with:
    - 'port': int
    - 'status': 'OPEN', 'CLOSED', or 'FILTERED'
    - 'service': Name of standard service
    - 'banner': Application banner if open
    - 'latency_ms': Round-trip time to complete handshake
    """
    service_name = WELL_KNOWN_PORTS.get(port, "Unknown Service")
    result = {
        "port": port,
        "status": "CLOSED",
        "service": service_name,
        "banner": "",
        "latency_ms": 0.0,
    }

    # socket.AF_INET = IPv4, socket.SOCK_STREAM = TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    start_time = time.perf_counter()
    try:
        # connect_ex returns 0 if TCP handshake completed (SYN -> SYN-ACK -> ACK)
        code = s.connect_ex((target_ip, port))
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        result["latency_ms"] = elapsed_ms

        if code == 0:
            result["status"] = "OPEN"
            s.close()
            # Grab application banner
            result["banner"] = grab_banner(target_ip, port, timeout=0.8)
        else:
            result["status"] = "CLOSED"
    except socket.timeout:
        result["status"] = "FILTERED"  # Firewall dropped packet
    except OSError:
        result["status"] = "ERROR"
    finally:
        s.close()

    return result


def run_scanner(target_host: str, start_port: int, end_port: int, max_threads: int = 50):
    """Orchestrates multi-threaded scanning across the requested port range."""
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{target_host}'. Check spelling.")
        return

    ports_to_scan = list(range(start_port, end_port + 1))
    total_ports = len(ports_to_scan)

    print("=" * 72)
    print(f" Mini Nmap: Multi-Threaded TCP Port Scanner")
    print(f" Target Host  : {target_host} ({target_ip})")
    print(f" Port Range   : {start_port} - {end_port} ({total_ports} ports)")
    print(f" Worker Threads: {max_threads}")
    print(f" Started At   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 72)
    print(f"{'PORT':<9} {'STATE':<10} {'SERVICE':<22} {'LATENCY':<12} {'BANNER'}")
    print("-" * 72)

    open_ports = []
    start_time = time.perf_counter()

    # Use ThreadPoolExecutor for concurrent socket connections
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(scan_port, target_ip, port): port for port in ports_to_scan
        }

        for future in as_completed(future_to_port):
            res = future.result()
            if res["status"] == "OPEN":
                open_ports.append(res)
                print(
                    f"{res['port']:<9} "
                    f"[\033[92mOPEN\033[0m]     "
                    f"{res['service']:<22} "
                    f"{res['latency_ms']:5.1f} ms     "
                    f"{res['banner'][:30]}"
                )

    total_time = time.perf_counter() - start_time
    open_ports.sort(key=lambda x: x["port"])

    print("=" * 72)
    print(f" Scan Finished in {total_time:.2f} seconds.")
    print(f" Scanned {total_ports} ports: Found {len(open_ports)} OPEN port(s).")
    print("=" * 72)


if __name__ == "__main__":
    # Default target is localhost or pass from command line:
    # python scanner.py <host> <start_port> <end_port>
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    start_p = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_p = int(sys.argv[3]) if len(sys.argv) > 3 else 1024

    run_scanner(host, start_p, end_p)
