from url_parser import URLParser
# from nmap import run_nmap
# from gobuster import run_gobuster  
# from who_is import run as run_whois
# from ssl_scan import run as run_ssl
from foot_printing import run as run_foot_printing
from version_engine import run as run_version
from dir_scan import run as run_dir
from recon_admin import run as run_reconadmin


def main(target_input=None):
    if target_input is None:
        target_input = input("Enter Target: ").strip()
    bone = URLParser(target_input)

    #nmap
    # run_nmap(bone.url_ip)

    #gobuster
    # dir_data = run_dir(bone.url_domain)

    #whois
    # run_whois(bone.url_domain)

    # ssl  scan
    # run_ssl(bone.url_domain)

    # Layer 1 foot_print
    foot_data = run_foot_printing(bone.url_domain)
    # Layer 2 Version
    version_data = run_version(bone.url_domain, foot_data)

    # Directory scan through the shared parser-based entry point
    run_reconadmin(bone.url_domain)

    # print(results)


if __name__ == "__main__":
    main()