import subprocess
import os
from url_parser import URLParser


def run_nmap(target_input=None):
    if target_input is None:
        target_input = input("Enter the URL or Domain  to scan:")
    parser=URLParser(target_input)
    ip=parser.url_ip

    if ip:
        print(f"\n[+]Resolved IP:{ip}")
        print(f"[+]Launching:nmap -sV -sC {ip}\n")

        os.system(f"nmap -sV -sC  {ip}")
    
    else:
        print(f"[!] Error: Could not resolve IP for '{target_input}'. Check your connection or url")

if __name__=="__main__":
    run_nmap()