import nmap
from tabulate import tabulate
import socket 

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def run_scan(scanner, ip_addr, scan_type):
    print(f"\nNmap Version: {scanner.nmap_version()}")
    full_scan_type = f"{scan_type} -sV"
    scanner.scan(ip_addr, arguments=full_scan_type)
    print(scanner.scaninfo())
    print("IP Status:", scanner[ip_addr].state())
    print("Protocols:", scanner[ip_addr].all_protocols())
    table_data = []
    for protocol in scanner[ip_addr].all_protocols():
        for port, info in scanner[ip_addr][protocol].items():
            service_info = info.get('product', '') + ' ' + info.get('version', '')
            table_data.append([protocol.upper(), port, info['name'], service_info])
    headers = ["Protocol", "Port", "Service Name", "Service Version"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

def main():
    scanner = nmap.PortScanner()
    ip_addr = input("Enter the target IP address: ")
    while not is_valid_ip(ip_addr):
        print("Invalid IP address. Please enter a valid IP address.")
        ip_addr = input("Enter the target IP address: ")
    while True:
        response = input("""
            Please enter the type of scan you want to run:
            1) SYN ACK Scan
            2) TCP Connect Scan12.
            3) UDP Scan     
            4) Comprehensive Scan
            5) Regular Scan
            6) OS Detection
            7) Multiple IP inputs
            8) Ping Scan
            0) Exit\n""")
        if response == '0':
            break
        elif response == '1':
            run_scan(scanner, ip_addr, '-v -sS')
        elif response == '2':
            run_scan(scanner, ip_addr, '-v -sT')
        elif response == '3':
            run_scan(scanner, ip_addr, '-v -sU')
        elif response == '4':
            run_scan(scanner, ip_addr, '-v -sS -sC -A -O')  
        elif response == '5':
            run_scan(scanner, ip_addr, '') 
        elif response == '6':
            print(scanner.scan(ip_addr, arguments="-O")['scan'][ip_addr]['osmatch'][0])
        elif response == '7':
            ip_addr = input("Enter the target IP address: ")
        elif response == '8':
            scanner.scan(hosts=f'{ip_addr}', arguments='-n -sP')
            hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
            for host, status in hosts_list:
                print(f'{host}: {status}')
        else:
            print("Invalid option. Please choose a number from the options above.")

if __name__ == "__main__":
    main()
