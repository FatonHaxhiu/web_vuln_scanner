import requests


def check_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        print(f"\n[+] Checking HTTP Headers for {url}")

        server = headers.get("Server", "Not disclosed")
        print(f"Server: {server}")
        if "Apache" in server or "nginx" in server:
            print("Warning: Server software disclosed.")

        if "X-Powered-By" in headers:
            powered_by = headers["X-Powered-By"]
            print(f"Warning: X-Powered-By header found: {powered_by}")

        required_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy"
        ]

        for header in required_headers:
            if header not in headers:
                print(f"Warning: Missing {header} header.")

    except requests.RequestException as e:
        print(f"Error checking headers: {e}")
