import nmap


def scan_ports(target):
    print(f"\n[+] Scanning ports for {target}...")
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments="-p 80,443,22,21,3306")
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
