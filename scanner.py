import sys
from scanner.headers import check_headers
from scanner.ports import scan_ports
from scanner.traversal import check_directory_traversal
from scanner.sqli import check_sql_injection


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py <target_url_or_ip>")
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    sys.stdout = open("scan_report.txt", "w")

    print(f"[*] Starting vulnerability scan on {target}")
    check_headers(target)
    scan_ports(target.split("://")[-1].split("/")[0])
    check_directory_traversal(target)
    check_sql_injection(target)


if __name__ == "__main__":
    main()
