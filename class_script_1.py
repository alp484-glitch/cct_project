import nmap
import sys
def scan_target(hosts='', ports='', args=''):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=hosts,ports=ports, arguments=args)
    except nmap.PortScannerError as e:
        print(e)
        return
    except Exception as e:
        print(e)
        return
    if not nm.all_hosts():
        print("[-] No hosts found")
        return

    if nm.all_hosts():
        for host in nm.all_hosts():
            print(host)
            for proto in nm[host].all_protocols():
                print(proto)

if __name__ == '__main__':
    scan_target()