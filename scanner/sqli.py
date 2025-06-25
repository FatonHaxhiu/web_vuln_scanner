import requests
from urllib.parse import urljoin


def check_sql_injection(url):
    print(f"\n[+] Checking for SQL injection on {url}")
    test_url = urljoin(url, "?id=1'")
    try:
        response = requests.get(test_url, timeout=5)
        if "sql syntax" in response.text.lower() or "mysql" in response.text.lower():
            print(f"Potential SQL injection vulnerability at {test_url}")
        else:
            print("No SQL injection detected")
    except requests.RequestException as e:
        print(f"Error testing {test_url}: {e}")
