import socket
import datetime
import sys
from typing import Optional


import dns.resolver
import dns.exception
import whois
from ipwhois import IPWhois
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.columns import Columns
 
from config import MODE
 
console = Console()
## cdn sign
CDN_SIGNATURES = [
    "cloudflare", "akamai", "fastly", "amazon", "cloudfront",
    "incapsula", "imperva", "sucuri", "stackpath", "maxcdn",
    "keycdn", "bunnycdn", "edgecast", "limelight", "cdn77",
    "azure", "microsoft", "google",
]
## ------

def _safe_query(domain: str, record_type: str) -> list:
    """Internal helper — query DNS safely, return list or empty."""
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        return [str(r) for r in answers]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    except Exception:
        return []
 
 
def get_dns_records(domain: str) -> dict:
    """
    Fetch A, AAAA, MX, NS, TXT records.
 
    Returns:
        {
            domain      : str,
            A           : list,
            AAAA        : list,
            MX          : list,
            NS          : list,
            TXT         : list,
            error       : str | None
        }
    """
    result = {
        "domain": domain,
        "A":      [],
        "AAAA":   [],
        "MX":     [],
        "NS":     [],
        "TXT":    [],
        "error":  None,
    }
    try:
        result["A"]    = _safe_query(domain, "A")
        result["AAAA"] = _safe_query(domain, "AAAA")
        result["MX"]   = _safe_query(domain, "MX")
        result["NS"]   = _safe_query(domain, "NS")
        result["TXT"]  = _safe_query(domain, "TXT")
    except Exception as e:
        result["error"] = str(e)
    return result
 
 
def get_whois_info(domain: str) -> dict:
    """
    Fetch registrar, creation date, expiry, domain age.
 
    Returns:
        {
            domain          : str,
            registrar       : str | None,
            creation_date   : str | None,
            expiration_date : str | None,
            domain_age_days : int | None,
            name_servers    : list,
            status          : list,
            error           : str | None
        }
    """
    result = {
        "domain":           domain,
        "registrar":        None,
        "creation_date":    None,
        "expiration_date":  None,
        "domain_age_days":  None,
        "name_servers":     [],
        "status":           [],
        "error":            None,
    }
    try:
        w = whois.whois(domain)
        result["registrar"] = w.registrar or None
 
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime.datetime):
            result["creation_date"]   = creation.strftime("%Y-%m-%d")
            result["domain_age_days"] = (datetime.datetime.utcnow() - creation).days
 
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if isinstance(expiry, datetime.datetime):
            result["expiration_date"] = expiry.strftime("%Y-%m-%d")
 
        ns = w.name_servers
        if isinstance(ns, list):
            result["name_servers"] = [str(n).lower() for n in ns]
        elif isinstance(ns, str):
            result["name_servers"] = [ns.lower()]
 
        status = w.status
        if isinstance(status, list):
            result["status"] = status
        elif isinstance(status, str):
            result["status"] = [status]
 
    except Exception as e:
        result["error"] = str(e)
    return result
 
 
def detect_cdn(domain: str) -> dict:
    """
    Detect CDN via CNAME chain and ASN/org lookup.
 
    Returns:
        {
            domain          : str,
            cdn_detected    : bool,
            cdn_name        : str | None,
            cname_chain     : list,
            ip_address      : str | None,
            asn             : str | None,
            asn_description : str | None,
            error           : str | None
        }
    """
    result = {
        "domain":          domain,
        "cdn_detected":    False,
        "cdn_name":        None,
        "cname_chain":     [],
        "ip_address":      None,
        "asn":             None,
        "asn_description": None,
        "error":           None,
    }
    try:
## cname chek 
        try:
            answers = dns.resolver.resolve(domain, "CNAME", lifetime=5)
            for r in answers:
                cname = str(r.target).lower()
                result["cname_chain"].append(cname)
                for sig in CDN_SIGNATURES:
                    if sig in cname:
                        result["cdn_detected"] = True
                        result["cdn_name"]     = sig.capitalize()
                        break
        except Exception:
            pass
        ##ip and ASN lookup 
        try:
            ip = socket.gethostbyname(domain)
            result["ip_address"] = ip
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)
            asn_desc = res.get("asn_description", "") or ""
            result["asn"]             = res.get("asn", None)
            result["asn_description"] = asn_desc
            if not result["cdn_detected"]:
                for sig in CDN_SIGNATURES:
                    if sig in asn_desc.lower():
                        result["cdn_detected"] = True
                        result["cdn_name"]     = sig.capitalize()
                        break
        except Exception as e:
            result["error"] = f"IP/ASN lookup failed: {str(e)}"
 
    except Exception as e:
        result["error"] = str(e)
    return result
def check_dnssec(domain: str) -> dict:
    """
    Check if DNSSEC is enabled via DNSKEY and RRSIG records.
 
    Returns:
        {
            domain         : str,
            dnssec_enabled : bool,
            dnskey_found   : bool,
            rrsig_found    : bool,
            dnskey_count   : int,
            error          : str | None
        }
    """
    result = {
        "domain":         domain,
        "dnssec_enabled": False,
        "dnskey_found":   False,
        "rrsig_found":    False,
        "dnskey_count":   0,
        "error":          None,
    }
    try:
        try:
            keys = list(dns.resolver.resolve(domain, "DNSKEY", lifetime=5))
            if keys:
                result["dnskey_found"] = True
                result["dnskey_count"] = len(keys)
        except Exception:
            pass
 
        try:
            sigs = list(dns.resolver.resolve(domain, "RRSIG", lifetime=5))
            if sigs:
                result["rrsig_found"] = True
        except Exception:
            pass
 
        result["dnssec_enabled"] = result["dnskey_found"]
 
    except Exception as e:
        result["error"] = str(e)
    return result
 
 
def get_all_data(domain: str) -> dict:
    """
    Master worker — runs all 4 checks, returns one combined dict.
    This is what cli_display() and web_based() both use.
    """
    return {
        "domain":     domain,
        "dns":        get_dns_records(domain),
        "whois":      get_whois_info(domain),
        "cdn":        detect_cdn(domain),
        "dnssec":     check_dnssec(domain),
    }
def cli_display(domain: str) -> None:
    """Fetch all data and display beautifully in terminal."""
 
    console.print(f"\n[bold cyan][ DODGETHREAT3 ][/bold cyan] [white]Scanning:[/white] [bold yellow]{domain}[/bold yellow]\n")
 
    data = get_all_data(domain)

## DNS records
    dns_data = data["dns"]
    dns_table = Table(
        title="DNS Records",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
    )
    dns_table.add_column("Type",    style="bold yellow", width=8)
    dns_table.add_column("Records", style="white")
 
    for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
        records = dns_data.get(record_type, [])
        if records:
            dns_table.add_row(record_type, "\n".join(records))
        else:
            dns_table.add_row(record_type, "[dim]No records found[/dim]")
 
    console.print(dns_table)
    console.print()
 ## whois 
    whois_data = data["whois"]
    whois_table = Table(
        title="WHOIS Information",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
    )
    whois_table.add_column("Field",  style="bold yellow", width=20)
    whois_table.add_column("Value",  style="white")
 
    # Domain age formatting
    age_days = whois_data.get("domain_age_days")
    if age_days is not None:
        years  = age_days // 365
        months = (age_days % 365) // 30
        age_str = f"{years} years, {months} months ({age_days} days)"
    else:
        age_str = "Unknown"
 
    whois_table.add_row("Registrar",       whois_data.get("registrar")       or "Unknown")
    whois_table.add_row("Creation Date",   whois_data.get("creation_date")   or "Unknown")
    whois_table.add_row("Expiration Date", whois_data.get("expiration_date") or "Unknown")
    whois_table.add_row("Domain Age",      age_str)
    whois_table.add_row(
        "Name Servers",
        "\n".join(whois_data.get("name_servers", [])) or "Unknown"
    )
    whois_table.add_row(
        "Status",
        "\n".join(whois_data.get("status", [])) or "Unknown"
    )
 
    console.print(whois_table)
    console.print()

    ##DNSEC
    dnssec_data = data["dnssec"]
    dnssec_enabled = dnssec_data.get("dnssec_enabled", False)
    dnssec_table = Table(
        title="DNSSEC Check",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
    )
    dnssec_table.add_column("Field",  style="bold yellow", width=20)
    dnssec_table.add_column("Value",  style="white")
 
    dnssec_status = (
        "[bold green]ENABLED ✔[/bold green]"
        if dnssec_enabled
        else "[bold red]DISABLED ✘[/bold red]"
    )
    dnssec_table.add_row("DNSSEC Status", dnssec_status)
    dnssec_table.add_row("DNSKEY Found",  "Yes" if dnssec_data.get("dnskey_found") else "No")
    dnssec_table.add_row("RRSIG Found",   "Yes" if dnssec_data.get("rrsig_found")  else "No")
    dnssec_table.add_row("DNSKEY Count",  str(dnssec_data.get("dnskey_count", 0)))
 
    console.print(dnssec_table)
    console.print()
 
    console.print("[bold cyan][ DODGETHREAT3 ][/bold cyan] [bold green]Scan Complete.[/bold green]\n")
 
# future 
# def web_based(domain: str) -> dict:
#     """
#     Fetch all data and return as clean JSON dict for web/database.
#     core_web.py calls this when MODE = "web"
#     """
#     return get_all_data(domain)
 


# reads config file 
def run(domain: str):
    """
    Entry point for core.py and core_web.py.
    Reads MODE from config.py and calls the right function.
    """
    if MODE == "cli":
        cli_display(domain)
    elif MODE == "web":
        pass  # web_based(domain) — uncomment in Phase 2
    else:
        console.print(f"[bold red]Unknown MODE '{MODE}' in config.py[/bold red]")


if __name__ == "__main__":
    from url_parser import URLParser
 
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter target domain/URL: ")
    parser = URLParser(target)
    domain = parser.url_domain
 
    if not domain:
        console.print("[bold red]Could not parse domain from input.[/bold red]")
        sys.exit(1)
 
    run(domain)