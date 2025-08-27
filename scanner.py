#!/usr/bin/python 

import subprocess
import os
import xml.etree.ElementTree as ET
import sys
import shutil
from pathlib import Path
import re


'''

    Title: python script for automating your basic enumeration workflow
    Author: krill-x7 
'''


if len(sys.argv) < 2:
    print("Usage: python script.py <target_ip>")
    sys.exit(1)

target = sys.argv[1]



# Functions 

def enum_ftp(port, target):
    print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")
    try:
        print("\033[91m" + "\n- - - - - - FTP Anon Scan - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

        subprocess.run([
            'nmap','-p', port, '--script', 'ftp-anon','-sCV', target
            ], check=True)
        
        print("\033[91m" + "\n- - - - - - vsftpd backdoor exploit - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

        subprocess.run([
            'nmap', '-p', port, '--script', 'ftp-vsftpd-backdoor', '-sV', target  
        ])

        print("\033[91m" + "\n- - - - - - FTP default Creds bruteforce - - - - - - - - - - - - - - - - -\n" + "\033[0m")  
        
        subprocess.run([
            'hydra', '-C', '/usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt', f'ftp://{target}'
        ])
        print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")


        
def enum_ssh(port, target):
    print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")
    try:
        print("\033[91m" + "\n- - - - - - SSH - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

        subprocess.run([
        ])
        print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")       



def enum_krb(port,target,domain):
    print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")
    try:
        print("\033[91m" + "\n- - - - - - Kerberos - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

        subprocess.run([
            'kerbrute','userenum','-t','40','-d',domain, '--dc', target, '/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt' 
        ])
        print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")       
       
       
        
def enum_ldap(port,target):
    print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")
    try:
        print("\033[91m" + "\n- - - - - - Ldap - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

        subprocess.run([
            'nmap','-n','-sC','--script','ldap* and not brute','-p',port,target,'-v','-Pn'
        ])
        print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")       
            
       
        
def enum_smb(port, target):
    print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")
    try:
        print("\033[91m" + "\n- - - - - - SmbClient- - - - - - - - - - - - - - - - -\n" + "\033[0m")  

        subprocess.run([
            "smbclient", '-U','%','-L',f'//{target}'
        ])
        
        print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")

        subprocess.run([
            "smbclient", '-U','guest%','-L',f'//{target}'
        ])
        
        print("\033[91m" + "\n- - - - - - Smbmap - - - - - - - - - - - - - - - - -\n" + "\033[0m")  
        subprocess.run([
            'smbmap','-u','','-p','','-P',port,'-H',target
        ])
        
        subprocess.run([
            'smbmap','-u','guest','-p','','-P',port,'-H',target
        ])
        
        
        print("\033[91m" + "\n- - - - - - Enum4Linux - - - - - - - - - - - - - - - - -\n" + "\033[0m")  
        subprocess.run([
            'enum4linux', '-a', '-u','','-p','',target
        ])        
        
        print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")



def enum_rpc(port, target):
    print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")
    try:
        subprocess.run([
            'rpcclient','-N',target
        ])
        print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")
    
    
    
def enum_http(port, target):
    print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")  
    try: 
        subprocess.run([
            'feroxbuster','-u','http://'+target+':'+port,'-w', '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt','-x','.html,.php,.php.save,.txt,.zip,.pdf' 
        ])
        
        subprocess.run([
            'feroxbuster','-u','http://'+target+':'+port,'-w', '/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt','-x','.html,.php,.save,.php.save,.txt,.zip,.pdf' 
        ])
        print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")



def enum_nfs(port, target):
    print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")  
    try: 
        subprocess.run([
            'nmap','--script', 'nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse', '-p', port, target, '-sCV'
        ])
        print("\033[91m" + "\n- - - - - - Showmount- - - - - - - - - - - - - - - - -\n" + "\033[0m")  
        subprocess.run([
            'showmount','-e',target
        ])
        # Add feature to mount and list contents of remote shares
        
        print("\033[91m" + "\n- - - - - - - - - - - - - - - - - - - - - - -\n" + "\033[0m")  

    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")    
    


# Running rustscan on the target using subprocess
# rustscan -a <Target> --ulimit 5000


output_dir = "/tmp/output"
#'''
if Path(output_dir).is_dir():
    shutil.rmtree(output_dir)
os.makedirs(output_dir, 0o777)
os.chmod(output_dir, 0o777)


cmd = [
    "rustscan",
    "-a", target,
    "--ulimit", "5000",
    "-r", "1-65535",
    "--", "-Pn", "-sCV", "-oX", "/tmp/output/nmap_output.xml"
    ]

result = subprocess.run(cmd)

# Parsing scan output 

tree = ET.parse(f"{output_dir}/nmap_output.xml")
root = tree.getroot()


services_found = []

for host in root.findall("host"):
    ports = host.find("ports")
    for port in ports.findall("port"):
        port_id = port.get("portid")
        protocol = port.get("protocol")
        state = port.find("state").get("state")
        service_element = port.find("service")
        service = service_element.get("name") if service_element is not None else None
        extrainfo = service_element.get("extrainfo") if service_element is not None else None 
            
        if not service and state == "open":
            
            services_found.append({
                "port": port_id,
                "protocol": protocol,
                "service": "none"
        }) 
            
        elif service and  state == "open":               
            # print(f"Open port {port_id}/{protocol} running {service}")            
            services_found.append({
                "port": port_id,
                "protocol": protocol,
                "service": service,
                "extrainfo": extrainfo  
            })
                    
       
rpc_scan = False 
http_targets = []

ldap_entries = [entry for entry in services_found if entry['service'] == 'ldap']


def domain_name(ldap_entries):
    entry = ldap_entries[0]['extrainfo']
    if entry:
        match = re.search(r"Domain:\s*([A-Za-z0-9.-]+?)(?:\d+\.)?,", entry)
        if match:     
            return match.group(1)

if ldap_entries:
    dom_name = domain_name(ldap_entries)   


for entry  in services_found:
    port = entry["port"]
    service = entry["service"]
    extrainfo = entry["extrainfo"]
    
    print(f"\n[+] Enumerating {service.upper()} on port {port}...")
    
    if "ftp" in service:
        print(f"    -> Would run: anonymous login check on FTP port {port}") 
        enum_ftp(port, target)
    
    elif "ssh" in service:
        print(f"    -> Would run: SSH version grab or bruteforce user enum on port {port}")
        
    elif any(s in service for s in ["smb", "microsoft-ds"]):
        print(f"    -> Would run: enum4Linux or smbclient against port {port}")
        enum_smb(port, target)
    
    elif "rpc" in service:
        if rpc_scan == False:
            rpc_scan = True
            print(f"    -> Would run rpc Null-bind against port {port}")
            enum_rpc(port, target)
        else:
            print("      Scan done")
        
    elif "nfs" in service:
        print(f"      -> Running nfs stuff on port {port}")
        enum_nfs(port,target)
            
    elif any(s in service for s in ["http", "https"]):
        http_targets.append((port, service))
        print("        -> Delayed till the end")
    
    elif "kerberos" in service:
        print(f"       -> Don't forget to check for Pre-auth and also bruteforce for valid usernames")
        
    elif "ldap" in service:
        print(f"       -> Running Ldap sutff on port {port}")
        enum_ldap(port, target)
        
for port, service in http_targets:
    enum_http(port, target)

print("\033[91m" + "\n\n[+] Try running a UDP scan too \n" + "\033[0m")
print(f"sudo nmap -sU -p- --min-rate=1000 -sCV -v {target}")

