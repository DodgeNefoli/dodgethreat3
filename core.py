from url_parser import URLParser
from nmap import run_nmap
from gobuster import run_gobuster  
import os

def main():
    target_input = input("Enter Target: ").strip()
    bone = URLParser(target_input)

    #nmap
    # run_nmap(bone.url_ip)
    #gobuster
    results = run_gobuster(bone.url_domain)
    print(results)


if __name__ == "__main__":
    main()