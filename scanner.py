import requests
import nmap
import sys
import re
from urllib.parse import urljoin


def check_headers(url):
    """Check HTTP headers for potential vulnerabilities."""
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        print(f"\n[+] Checking HTTP Headers for {url}")

        # Check for Server header (reveals server software)
        server = headers.get("Server", "Not disclosed")
        print(f"Server: {server}")
        if "Apache" in server or "nginx" in server:
            print("Warning: Server software disclosed. Consider hiding version info.")

        # Check for X-Powered-By header
        if "X-Powered-By" in headers:
            print(
                f"Warning: X-Powered-By header found: {headers['X-Powered-By']}. Remove to reduce information leakage.")

        # Check for missing security headers
        security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy"]
        for header in security_headers:
            if header not in headers:
                print(f"Warning: Missing {header} header.")

    except requests.RequestException as e:
        print(f"Error checking headers: {e}")


def scan_ports(target):
    """Scan common ports using nmap."""
    nm = nmap.PortScanner()
    print(f"\n[+] Scanning ports for {target}...")
    try:
        # Scan common ports
        nm.scan(target, arguments="-sS -p 80,443,22,21,3306")
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]["state"]
                    print(f"Port: {port}\tState: {state}")
    except Exception as e:
        print(f"Error scanning ports: {e}")


def check_directory_traversal(url):
    """Check for basic directory traversal vulnerability."""
    payloads = ["../etc/passwd", "../../etc/passwd"]
    print(f"\n[+] Checking for directory traversal on {url}")
    for payload in payloads:
        test_url = urljoin(url, payload)
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200 and "root:" in response.text:
                print(
                    f"Vulnerability: Directory traversal detected with {test_url}!")
            else:
                print(f"No issue found with payload: {payload}")
        except requests.RequestException as e:
            print(f"Error testing {test_url}: {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py <target_url_or_ip>")
        print("Example: python3 scanner.py http://127.0.0.1")
        sys.exit(1)

    target = sys.argv[1]
    # Ensure URL has protocol
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    print(f"[*] Starting vulnerability scan on {target}")
    check_headers(target)
    scan_ports(target.split("://")[-1].split("/")[0])  # Extract IP/hostname
    check_directory_traversal(target)


if __name__ == "__main__":
    main()
