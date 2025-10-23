#!/usr/bin/env python3
"""
nmap_scan_enhanced.py
A convenience wrapper around system Nmap providing structured JSON output.
"""

import argparse
import json
import sys

import nmap  # python-nmap wrapper

# ---------------- Helpers -----------------
def build_default_args(service_version=False, aggressive=False):
    """
    Build default nmap argument string.
    -sT : TCP connect scan (no root required)
    -Pn : skip host discovery
    -T4 : faster timing template
    """
    args = "-sT -Pn -T4"
    if service_version:
        args += " -sV"
    if aggressive:
        # increase version intensity or other optional flags
        args += " --version-intensity 5"
    return args

def parse_ports(ports_str):
    """
    Return port string for nmap (pass-through).
    """
    return ports_str

def parse_hosts(host_str):
    """
    Return host string for nmap (pass-through).
    """
    return host_str

def run_scan(hosts, ports, arguments):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=hosts, ports=ports, arguments=arguments)
    except Exception as e:
        raise RuntimeError(f"nmap scan failed: {e}")
    return nm

def parse_nmap_result(nm):
    """
    Convert python-nmap result to normalized JSON-friendly structure.
    """
    out = {"hosts": {}}
    for host in nm.all_hosts():
        host_entry = {}
        host_entry["state"] = nm[host].get("status", {}).get("state", "")
        host_entry["addresses"] = nm[host].get("addresses", {})
        protocols = {}
        for proto in nm[host].all_protocols():
            ports_list = []
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                port_data = nm[host][proto][port]
                # Extract known fields safely
                port_entry = {
                    "port": port,
                    "state": port_data.get("state", ""),
                    "name": port_data.get("name", ""),
                    "product": port_data.get("product", ""),
                    "version": port_data.get("version", ""),
                    "extrainfo": port_data.get("extrainfo", ""),
                    "reason": port_data.get("reason", ""),
                    "conf": port_data.get("conf", ""),
                    "script": port_data.get("script", {})
                }
                ports_list.append(port_entry)
            protocols[proto] = ports_list
        host_entry["protocols"] = protocols
        out["hosts"][host] = host_entry
    return out

def pretty_print(result):
    for host, info in result["hosts"].items():
        print(f"Host: {host} ({info.get('state','')})")
        for proto, ports in info.get("protocols", {}).items():
            print(f"  Protocol: {proto}")
            for p in ports:
                svc = p.get("name") or ""
                prod = p.get("product") or ""
                ver = p.get("version") or ""
                print(f"    {p['port']}/{proto} {p['state']} {svc} {prod} {ver}")

def main():
    parser = argparse.ArgumentParser(description="nmap wrapper - produce JSON results")
    parser.add_argument("-H", "--hosts", required=True, help="Hosts to scan (e.g., 192.168.1.0/28)")
    parser.add_argument("-P", "--ports", default="1-1024", help="Ports to scan (e.g., 22,80,443 or 1-1024)")
    parser.add_argument("-a", "--service-version", action="store_true", help="Enable service/version detection (-sV)")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive options")
    parser.add_argument("--extra-args", default="", help="Extra nmap args")
    parser.add_argument("--pretty", action="store_true", help="Pretty print to console")
    parser.add_argument("-o", "--output", default="", help="JSON output file")
    args = parser.parse_args()

    arguments = build_default_args(service_version=args.service_version, aggressive=args.aggressive)
    if args.extra_args:
        arguments += " " + args.extra_args

    nm = run_scan(args.hosts, args.ports, arguments)
    result = parse_nmap_result(nm)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
    if args.pretty or not args.output:
        pretty_print(result)

if __name__ == "__main__":
    main()
