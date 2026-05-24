import re
import sys
import socket
import requests
from rich.console import Console
from rich.table import Table
from rich import box
 
from config import MODE
 
console = Console()
requests.packages.urllib3.disable_warnings()
 
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


# workers
def _get(url: str, timeout: int = 6) -> requests.Response | None:
    """Safe GET — returns response or None."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
        return r if r.status_code == 200 else None
    except Exception:
        return None
 
 
def _regex(pattern: str, text: str) -> str | None:
    """Run regex, return first group or None."""
    m = re.search(pattern, text, re.I)
    return m.group(1).strip() if m else None

# Cms 
def probe_wordpress(domain: str) -> str | None:
    base = f"http://{domain}"
    # Method 1 — readme.html
    r = _get(f"{base}/readme.html")
    if r:
        v = _regex(r'[Vv]ersion\s+([\d.]+)', r.text)
        if v: return v
    # Method 2 — RSS feed
    r = _get(f"{base}/?feed=rss2")
    if r:
        v = _regex(r'<generator>.*?WordPress\s+([\d.]+)', r.text)
        if v: return v
    # Method 3 — meta generator
    r = _get(base)
    if r:
        v = _regex(r'<meta[^>]+generator[^>]+WordPress\s*([\d.]+)', r.text)
        if v: return v
    return None

def probe_joomla(domain: str) -> str | None:
    base = f"http://{domain}"
    # Method 1 — XML manifest
    r = _get(f"{base}/administrator/manifests/files/joomla.xml")
    if r:
        v = _regex(r'<version>([\d.]+)</version>', r.text)
        if v: return v
    # Method 2 — language file
    r = _get(f"{base}/language/en-GB/en-GB.xml")
    if r:
        v = _regex(r'<version>([\d.]+)</version>', r.text)
        if v: return v
    return None
 
 
def probe_drupal(domain: str) -> str | None:
    base = f"http://{domain}"
    # Method 1 — CHANGELOG
    r = _get(f"{base}/CHANGELOG.txt")
    if r:
        v = _regex(r'Drupal\s+([\d.]+)', r.text)
        if v: return v
    # Method 2 — meta generator
    r = _get(base)
    if r:
        v = _regex(r'<meta[^>]+generator[^>]+Drupal\s*([\d.]+)', r.text)
        if v: return v
    return None
 
 
def probe_magento(domain: str) -> str | None:
    base = f"http://{domain}"
    r = _get(f"{base}/magento_version")
    if r:
        v = _regex(r'Magento/([\d.]+)', r.text)
        if v: return v
    r = _get(f"{base}/RELEASE_NOTES.txt")
    if r:
        v = _regex(r'([\d]+\.[\d]+\.[\d]+)', r.text)
        if v: return v
    return None
 
 
def probe_shopify(domain: str) -> str | None:
    r = _get(f"http://{domain}")
    if r and "cdn.shopify.com" in r.text:
        return "Hosted (version not exposed)"
    return None
 
 
def probe_laravel(domain: str) -> str | None:
    r = _get(f"http://{domain}/vendor/laravel/framework/composer.json")
    if r:
        v = _regex(r'"version":\s*"v?([\d.]+)"', r.text)
        if v: return v
    return None
 
 
def probe_django(domain: str) -> str | None:
    r = _get(f"http://{domain}/django-admin/")
    if r:
        v = _regex(r'Django\s+([\d.]+)', r.text)
        if v: return v
    return None


# service banner probes

def probe_ssh(domain: str, port: int = 22) -> str | None:
    try:
        s = socket.socket()
        s.settimeout(4)
        s.connect((domain, port))
        banner = s.recv(256).decode(errors="ignore").strip()
        s.close()
        v = _regex(r'SSH-[\d.]+-OpenSSH_([\d.]+\w*)', banner)
        return f"OpenSSH {v}" if v else (banner[:40] if banner else None)
    except Exception:
        return None
 
 
def probe_mysql(domain: str, port: int = 3306) -> str | None:
    try:
        s = socket.socket()
        s.settimeout(4)
        s.connect((domain, port))
        banner = s.recv(256).decode(errors="ignore")
        s.close()
        v = _regex(r'([\d]+\.[\d]+\.[\d]+)', banner)
        return f"MySQL {v}" if v else None
    except Exception:
        return None
 
 
def probe_redis(domain: str, port: int = 6379) -> str | None:
    try:
        s = socket.socket()
        s.settimeout(4)
        s.connect((domain, port))
        s.send(b"INFO server\r\n")
        data = s.recv(1024).decode(errors="ignore")
        s.close()
        v = _regex(r'redis_version:([\d.]+)', data)
        return f"Redis {v}" if v else None
    except Exception:
        return None
    
# pro dispatcher
PROBE_MAP = {
    "WordPress": probe_wordpress,
    "Joomla":    probe_joomla,
    "Drupal":    probe_drupal,
    "Magento":   probe_magento,
    "Shopify":   probe_shopify,
    "Laravel":   probe_laravel,
    "Django":    probe_django,
}
 
SERVICE_PROBES = {
    "SSH":   probe_ssh,
    "MySQL": probe_mysql,
    "Redis": probe_redis,
}
 
 
def get_all_versions(domain: str, foot_data: dict) -> dict:
    """
    Takes foot_printing.get_all_data() output.
    Probes each detected technology for exact version.
 
    Returns:
        {
            "versions":  {"WordPress": "6.4.2", "Nginx": "1.24.0", ...},
            "not_found": ["Joomla", ...]
        }
    """

# starts with already founded CMS in footprint.py 
    versions  = dict(foot_data.get("all_versions", {}))
    not_found = []
#-------------------------------------------from layer 1
    detected_cms = foot_data.get("cms", {}).get("detected", [])
    detected_fw  = foot_data.get("frameworks", {}).get("detected", [])
 
    for tech in detected_cms + detected_fw:
        if tech in versions:
            continue  # already found by foot_printing
        probe_fn = PROBE_MAP.get(tech)
        if probe_fn:
            v = probe_fn(domain)
            if v:
                versions[tech] = v
            else:
                not_found.append(tech)
 
    # Always probe services regardless
    for service, probe_fn in SERVICE_PROBES.items():
        if service not in versions:
            v = probe_fn(domain)
            if v:
                versions[service] = v
 
    return {
        "versions":  versions,
        "not_found": not_found,
    }

# cli display
def cli_display(domain: str, foot_data: dict) -> dict:
    console.print(f"\n[bold cyan][ DODGETHREAT3 ][/bold cyan] [white]Version Engine:[/white] [bold yellow]{domain}[/bold yellow]\n")
 
    data = get_all_versions(domain, foot_data)
 
    table = Table(
        title="  Version Fingerprint — Layer 2",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
        min_width=60,
    )
    table.add_column("Technology", style="bold yellow", width=18)
    table.add_column("Version",    style="white",       width=25)
    table.add_column("Status",     style="white")
 
    for tech, version in data["versions"].items():
        table.add_row(
            tech,
            f"[bold green]{version}[/bold green]",
            "[bold green]Confirmed ✔[/bold green]"
        )
 
    for tech in data["not_found"]:
        table.add_row(
            tech,
            "[dim]Not detected[/dim]",
            "[yellow]Unknown ⚠[/yellow]"
        )
 
    if not data["versions"] and not data["not_found"]:
        table.add_row("[dim]No technologies detected[/dim]", "", "")
 
    console.print(table)
    console.print()
    console.print("[bold cyan][ DODGETHREAT3 ][/bold cyan] [bold green]Version Engine Complete.[/bold green]\n")
 
    return data  # passes to Layer 3 cve_lookup


# web part 



# Run
def run(domain: str, foot_data: dict) -> dict:
    """
    Entry point.
    Called by core.py and foot_printing.py directly.
    Returns version dict for Layer 3.
    """
    if MODE == "cli":
        return cli_display(domain, foot_data)
    elif MODE == "web":
        pass  # return web_based(domain, foot_data)
    else:
        console.print(f"[bold red]Unknown MODE '{MODE}' in config.py[/bold red]")
    return {}

# direct run 
if __name__ == "__main__":
    import foot_printing
    from url_parser import URLParser
 
    target    = sys.argv[1] if len(sys.argv) > 1 else input("Enter target: ")
    domain    = URLParser(target).url_domain
    if not domain:
        console.print("[bold red]Could not parse domain.[/bold red]")
        sys.exit(1)
 
    foot_data = foot_printing.run(domain)
    run(domain, foot_data)