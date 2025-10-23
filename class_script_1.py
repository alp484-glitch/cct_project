import nmap
import sys

def scan_target(hosts='151.101.128.81', ports='1-1024', args='-sT -Pn -T4'):
    nm = nmap.PortScanner()
    try:
        ## NOTE: use 'hosts' and 'ports' (not 'targets')
        nm.scan(hosts=hosts, ports=ports, arguments=args)
    except nmap.PortScannerError as e:
        print("nmap error:", e, file=sys.stderr)
        return
    except Exception as e:
        print("unexpected error:", e, file=sys.stderr)
        return

    # show scan results
    if not nm.all_hosts():
        print("No hosts returned by nmap. Raw scan data:")
        print(nm._scan_result)
        return

    for host in nm.all_hosts():
        print(f"Host: {host}  ({nm[host].hostname()})  State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f" Protocol: {proto}")
            ports_list = sorted(nm[host][proto].keys())
            if not ports_list:
                print("  (no ports found for this protocol)")
                continue
            for port in ports_list:
                state = nm[host][proto][port]['state']
                print(f"  Port {port}\tState: {state}")
        print("-" * 40)

if __name__ == "__main__":
    # We want to target 151.101.128.81
    scan_target(hosts='127.0.0.1', ports='1-1024', args='-sT -Pn -T4')
