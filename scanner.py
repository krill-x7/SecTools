#!/usr/bin/env python3

import subprocess
import os
import xml.etree.ElementTree as ET
import sys
import shutil
from pathlib import Path
import re
import argparse


'''

    Title: python script for automating your basic enumeration workflow
    Author: krill-x7 
'''


BANNER = "\033[91m" + "\n" + ("- " * 25) + "\n" + "\033[0m"


def print_banner(title: str):
    """Print a red banner with a title."""
    print(BANNER)
    print(f"\033[91m\n--- {title} ---\n\033[0m")
    print(BANNER)


def run_cmd(cmd: list[str]):
    """Run a shell command safely."""
    try:
        subprocess.run(cmd)
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")


# ---------------- Service Enumeration ---------------- #

def enum_ftp(port, target):
    print_banner("FTP Enumeration")
    run_cmd(["nmap", "-p", port, "--script", "ftp-anon", "-sCV", target], check=True)
    run_cmd(["nmap", "-p", port, "--script", "ftp-vsftpd-backdoor", "-sV", target])
    run_cmd([
        "hydra", "-C",
        "/usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
        f"ftp://{target}"
    ])


def enum_ssh(port, target):
    print_banner("SSH Enumeration")
    # placeholder — extend with version checks, brute-force, etc.


def enum_krb(port, target, domain):
    print_banner("Kerberos Enumeration")
    run_cmd([
        "kerbrute", "userenum", "-t", "40", "-d", domain, "--dc", target,
        "/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt"
    ])


def enum_ldap(port, target):
    print_banner("LDAP Enumeration")
    run_cmd([
        "nmap", "-n", "-sC", "--script", "ldap* and not brute", "-p", port, target, "-v", "-Pn"
    ])


def enum_smb(port, target):
    print_banner("SMB Enumeration")
    run_cmd(["smbclient", "-U", "%", "-L", f"//{target}"])
    run_cmd(["smbclient", "-U", "guest%", "-L", f"//{target}"])
    run_cmd(["smbmap", "-u", "", "-p", "", "-P", port, "-H", target])
    run_cmd(["smbmap", "-u", "guest", "-p", "", "-P", port, "-H", target])
    run_cmd(["enum4linux", "-a", "-u", "", "-p", "", target])


def enum_rpc(port, target):
    print_banner("RPC Enumeration")
    run_cmd(["rpcclient", "-N", target])


def enum_http(port, target):
    print_banner(f"HTTP Enumeration (port {port})")
    for wordlist in [
        "common.txt",
        "big.txt"
    ]:
        run_cmd([
            "feroxbuster", "-u", f"http://{target}:{port}",
            "-w", f"/usr/share/wordlists/seclists/Discovery/Web-Content/{wordlist}",
            "-x", ".html,.php,.php.save,.txt,.zip,.pdf"
        ])


def enum_nfs(port, target):
    print_banner("NFS Enumeration")
    run_cmd(["nmap", "--script", "nfs-ls,nfs-showmount,nfs-statfs", "-p", port, target, "-sCV"])
    run_cmd(["showmount", "-e", target])


# ---------------- Helper Functions ---------------- #

def parse_nmap_output(xml_path: Path):
    """Parse nmap XML output into a structured service list."""
    services = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for host in root.findall("host"):
        for port in host.find("ports").findall("port"):
            port_id = port.get("portid")
            protocol = port.get("protocol")
            state = port.find("state").get("state")

            service_element = port.find("service")
            service = service_element.get("name") if service_element is not None else None
            extrainfo = service_element.get("extrainfo") if service_element is not None else None

            if state != "open":
                continue

            services.append({
                "port": port_id,
                "protocol": protocol,
                "service": service or "unknown",
                "extrainfo": extrainfo
            })
    return services


def extract_domain(ldap_entries):
    """Extract domain name from LDAP service banner."""
    entry = ldap_entries[0].get("extrainfo")
    if entry:
        match = re.search(r"Domain:\s*([A-Za-z0-9.-]+?)(?:\d+\.)?,", entry)
        if match:
            return match.group(1)


# ---------------- Main Workflow ---------------- #

def main():
    parser = argparse.ArgumentParser(description="Automated Enumeration Script")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-o", "--output", default="/tmp/output", help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.output)
    if output_dir.is_dir():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run rustscan
    nmap_xml = output_dir / "nmap_output.xml"
    run_cmd([
        "rustscan", "-a", args.target, "--ulimit", "5000", "-r", "1-65535",
        "--", "-Pn", "-sCV", "-oX", str(nmap_xml)
    ])

    # Parse results
    services = parse_nmap_output(nmap_xml)

    rpc_done = False
    http_targets = []
    ldap_entries = [s for s in services if s["service"] == "ldap"]
    domain = extract_domain(ldap_entries) if ldap_entries else None

    for entry in services:
        port, service = entry["port"], entry["service"]

        print(f"\n[+] Enumerating {service.upper()} on port {port}...")

        if "ftp" in service:
            enum_ftp(port, args.target)
        elif "ssh" in service:
            enum_ssh(port, args.target)
        elif service in ["smb", "microsoft-ds"]:
            enum_smb(port, args.target)
        elif "rpc" in service and not rpc_done:
            enum_rpc(port, args.target)
            rpc_done = True
        elif "nfs" in service:
            enum_nfs(port, args.target)
        elif service in ["http", "https"]:
            http_targets.append(port)
        elif "kerberos" in service and domain:
            enum_krb(port, args.target, domain)
        elif "ldap" in service:
            enum_ldap(port, args.target)

    for port in http_targets:
        enum_http(port, args.target)

    print_banner("Reminder: Run UDP scan too")
    print(f"sudo nmap -sU -p- --min-rate=1000 -sCV -v {args.target}")


if __name__ == "__main__":
    main()
