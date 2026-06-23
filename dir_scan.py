import sys
import requests
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich import box
 
from config import MODE
 
console = Console()
requests.packages.urllib3.disable_warnings()

# ⭐ CONNECTION POOLING - HUGE SPEED BOOST
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=50,  # Keep 50 connections alive
    pool_maxsize=100,     # Max 100 connections
    max_retries=0
)
session.mount("http://", adapter)
session.mount("https://", adapter)
 
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/124.0",
]

def _get_headers():
    """Return random user agent in headers dict"""
    import random
    return {"User-Agent": random.choice(USER_AGENTS)}

#status codes 
GOOD_CODES    = [200, 201, 204, 301, 302, 307, 401, 403, 405, 500]

#path of  wordlist
SECLISTS_DIR  = "/usr/share/seclists/Discovery/Web-Content/common.txt"

FALLBACK_DIRS = [
    "admin", "login", "dashboard", "wp-admin", "administrator",
    "api", "v1", "v2", "upload", "uploads", "backup", "backups",
    "config", "configs", "assets", "static", "media", "images",
    "js", "css", "includes", "inc", "src", "dev", "test", "beta",
    "old", "bak", ".git", ".env", "robots.txt", "sitemap.xml",
    "phpinfo.php", "info.php", "readme.html", "CHANGELOG.txt",
    "wp-login.php", "wp-config.php", "xmlrpc.php", "shell.php",
    "server-status", "server-info", "console", "phpmyadmin",
    "pma", "mysql", "database", "db", "sql", "panel", "portal",
    "manage", "management", "secret", "private", "hidden",
    "internal", "staging", "prod", "production", "store",
]

FALLBACK_VHOSTS = [
    "admin", "staging", "dev", "development", "test", "beta",
    "api", "portal", "internal", "mail", "webmail", "ftp",
    "vpn", "remote", "dashboard", "monitor", "status",
    "shop", "store", "blog", "forum", "support", "help",
    "docs", "documentation", "cdn", "static", "assets",
    "old", "backup", "secure", "login", "auth",
]


def _load_wordlist(path: str) -> list:
    """Load wordlist from file or fall back to built-in list."""
    try:
        with open(path, "r", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        console.print(f"[dim]Wordlist loaded: {path} ({len(words)} words)[/dim]")
        return words
    except FileNotFoundError:
        console.print(f"[dim]Seclists not found — using built-in wordlist ({len(FALLBACK_DIRS)} words)[/dim]")
        return FALLBACK_DIRS
 
 
def _get_baseline(base_url: str) -> tuple:
    """Fetch a random non-existent path to get baseline response."""
    try:
        r = session.get(  # ⭐ Use session instead of requests
            f"{base_url}/dodgethreat3_baseline_xyz_404",
            headers=_get_headers(), timeout=5, verify=False, allow_redirects=False
        )
        return r.status_code, len(r.content)
    except Exception:
        return 404, 0
 
 
def _detect_excluded_length(responses: list) -> int | None:
    """Auto detect excluded length - noise filtering."""
    if not responses:
        return None
    lengths = [r["size"] for r in responses]
    counter = Counter(lengths)
    most_common_len, count = counter.most_common(1)[0]
    if count / len(lengths) > 0.4 and len(lengths) > 5:
        return most_common_len
    return None
 
 
def dir_scan(domain: str, threads: int = 50) -> dict:  # ⭐ Increased default to 50
    """
    Run directory brute force scan with performance optimizations.
    
    Optimizations:
    - ThreadPoolExecutor instead of manual threading
    - Connection pooling (reuse connections)
    - Reduced lock contention with batch processing
    - Progress bar for user feedback
    """
    result = {
        "domain":          domain,
        "base_url":        None,
        "results":         [],
        "excluded_length": None,
        "total_requests":  0,
        "error":           None,
    }
 
    # Figure out base URL
    for scheme in ["http", "https"]:
        try:
            r = session.get(f"{scheme}://{domain}", headers=_get_headers(), timeout=5, verify=False)
            result["base_url"] = f"{scheme}://{domain}"
            break
        except Exception:
            continue
 
    if not result["base_url"]:
        result["error"] = "Could not connect to target"
        return result
 
    base_url = result["base_url"]
 
    # Get baseline
    baseline_code, baseline_len = _get_baseline(base_url)
 
    # Load wordlist
    wordlist = _load_wordlist(SECLISTS_DIR)
 
    found      = []
    all_resps  = []
    lock       = threading.Lock()  # ⭐ Keep lock but use it less

    def check(word):
        """Check a single path - minimal locking"""
        url = f"{base_url}/{word}"
        try:
            r = session.get(  # ⭐ Use session (connection pooling)
                url, headers=_get_headers(),
                timeout=5, verify=False, allow_redirects=False
            )
            size = len(r.content)
            
            # Capture redirect
            redirect_to = None
            if r.status_code in [301, 302, 303, 307, 308]:
                redirect_to = r.headers.get("Location", None)
            
            entry = {
                "url":    url,
                "path":   f"/{word}",
                "status": r.status_code,
                "size":   size,
                "redirect": redirect_to,
            }
            
            # ⭐ Only lock when we have something interesting (reduced contention)
            if r.status_code in GOOD_CODES and size != baseline_len:
                with lock:
                    found.append(entry)
                    all_resps.append(entry)
            else:
                all_resps.append(entry)
                
            return entry
        except Exception as e:
            return None
 
    # ⭐ USE ThreadPoolExecutor INSTEAD OF MANUAL THREADING
    # This is WAY faster than creating thousands of threads manually
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task(f"[cyan]Scanning...", total=len(wordlist))
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check, word) for word in wordlist]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
                progress.update(task, advance=1)
 
    # Auto detect excluded length
    excluded = _detect_excluded_length(all_resps)
    if excluded:
        found = [r for r in found if r["size"] != excluded]
        result["excluded_length"] = excluded
 
    result["results"]        = sorted(found, key=lambda x: x["status"])
    result["total_requests"] = len(wordlist)
 
    return result
 
 
def vhost_scan(domain: str, threads: int = 50) -> dict:  # ⭐ Increased default
    """
    Run vhost enumeration with performance optimizations.
    """
    result = {
        "domain":          domain,
        "results":         [],
        "excluded_length": None,
        "error":           None,
    }

    base_url = f"http://{domain}"
 
    # Get baseline
    try:
        r = session.get(  # ⭐ Use session
            base_url, headers={**_get_headers(), "Host": f"dodgethreat3nonexistent.{domain}"},
            timeout=5, verify=False
        )
        baseline_len = len(r.content)
        baseline_code = r.status_code
    except Exception:
        result["error"] = "Could not get vhost baseline"
        return result
    
    try:
        words = _load_wordlist("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    except Exception:
        words = FALLBACK_VHOSTS
 
    found = []
    lock  = threading.Lock()

    def check_vhost(word):
        """Check a single vhost"""
        vhost = f"{word}.{domain}"
        try:
            r = session.get(  # ⭐ Use session
                base_url,
                headers={**_get_headers(), "Host": vhost},
                timeout=5, verify=False, allow_redirects=False
            )
            size = len(r.content)
            
            if size != baseline_len or r.status_code != baseline_code:
                return {
                    "vhost":  vhost,
                    "status": r.status_code,
                    "size":   size,
                }
        except Exception:
            pass
        return None

    # ⭐ USE ThreadPoolExecutor
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task(f"[cyan]VHost scanning...", total=len(words))
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_vhost, word) for word in words]
            
            for future in as_completed(futures):
                try:
                    result_item = future.result()
                    if result_item:
                        found.append(result_item)
                except Exception:
                    pass
                progress.update(task, advance=1)

    result["results"] = found
    return result


def get_all_data(domain: str) -> dict:
    """Master worker - run scans."""
    dir_data   = dir_scan(domain)
    vhost_data = None
 
    if len(dir_data["results"]) < 3:
        vhost_data = vhost_scan(domain)
 
    return {
        "domain":    domain,
        "dir_scan":  dir_data,
        "vhost_scan": vhost_data,
    }

# CLI display
def _status_color(code: int) -> str:
    """Color code HTTP status."""
    if code == 200:                    return f"[bold green]{code}[/bold green]"
    elif code in [301, 302, 307]:      return f"[bold yellow]{code}[/bold yellow]"
    elif code in [401, 403]:           return f"[bold red]{code}[/bold red]"
    elif code == 500:                  return f"[bold magenta]{code}[/bold magenta]"
    else:                              return f"[white]{code}[/white]"
 
 
def cli_display(domain: str) -> dict:
    console.print(f"\n[bold cyan][ DODGETHREAT3 ][/bold cyan] [white]Directory Scanner:[/white] [bold yellow]{domain}[/bold yellow]\n")
 
    data = get_all_data(domain)
    dir_data = data["dir_scan"]

    console.print(f"[dim]Scanned {dir_data['total_requests']} paths on {dir_data['base_url']}[/dim]")
 
    if dir_data.get("excluded_length"):
        console.print(f"[dim]Auto excluded length: {dir_data['excluded_length']} bytes (noise filtered)[/dim]\n")
 
    if dir_data.get("error"):
        console.print(f"[bold red]Error: {dir_data['error']}[/bold red]")
        return data
 
    dir_table = Table(
        title="  Directory Scan Results",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
        min_width=80,
    )
    dir_table.add_column("Status", width=8)
    dir_table.add_column("Size",   width=10, style="dim")
    dir_table.add_column("Path",   width=25, style="white")
    dir_table.add_column("Redirect", style="bold yellow")
 
    if dir_data["results"]:
        for r in dir_data["results"]:
            redirect_str = f"[--> {r['redirect']}]" if r.get("redirect") else ""
            dir_table.add_row(
                _status_color(r["status"]),
                f"{r['size']} B",
                r["path"],
                redirect_str,
            )
    else:
        dir_table.add_row("[dim]—[/dim]", "", "[dim]No interesting paths found[/dim]", "")
 
    console.print(dir_table)
    console.print()
 
 # VHOST if ran
    vhost_data = data.get("vhost_scan")
    if vhost_data:
        console.print("[dim]Dir scan returned few results — running VHost enumeration...[/dim]\n")
 
        vhost_table = Table(
            title="  VHost Enumeration Results",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold magenta",
            show_lines=True,
            min_width=65,
        )
        vhost_table.add_column("Status", width=8)
        vhost_table.add_column("Size",   width=10, style="dim")
        vhost_table.add_column("VHost",  style="white")
 
        if vhost_data["results"]:
            for r in vhost_data["results"]:
                vhost_table.add_row(
                    _status_color(r["status"]),
                    f"{r['size']} B",
                    r["vhost"],
                )
        else:
            vhost_table.add_row("[dim]—[/dim]", "", "[dim]No vhosts found[/dim]")
 
        console.print(vhost_table)
        console.print()

    #summary
    total_found = len(dir_data["results"])
    vhost_found = len(vhost_data["results"]) if vhost_data else 0
 
    interesting = [r for r in dir_data["results"] if r["status"] == 200]
    auth_needed = [r for r in dir_data["results"] if r["status"] in [401, 403]]
    redirects = [r for r in dir_data["results"] if r.get("redirect")]
 
    if total_found > 0 or vhost_found > 0:
        summary = ""
        if interesting:
            paths = ", ".join(r["path"] for r in interesting[:5])
            summary += f"[bold green]✔ Open paths:[/bold green] {paths}\n"
        if redirects:
            paths = ", ".join(f"{r['path']} [--> {r['redirect']}]" for r in redirects[:3])
            summary += f"[bold yellow]⚠ Redirects:[/bold yellow] {paths}\n"
        if auth_needed:
            paths = ", ".join(r["path"] for r in auth_needed[:5])
            summary += f"[bold red]✘ Auth required:[/bold red] {paths}\n"
        if vhost_found > 0:
            vhosts = ", ".join(r["vhost"] for r in vhost_data["results"][:3])
            summary += f"[bold yellow]⚠ VHosts found:[/bold yellow] {vhosts}\n"
 
        console.print(Panel(
            summary.strip(),
            title="[bold red]  ⚠ Findings[/bold red]",
            border_style="red", padding=(1, 2),
        ))
    else:
        console.print(Panel(
            "[bold green]✔ No interesting directories or vhosts found[/bold green]",
            title="[bold green]  Scan Summary[/bold green]",
            border_style="green", padding=(1, 2),
        ))
 
    console.print()
    console.print("[bold cyan][ DODGETHREAT3 ][/bold cyan] [bold green]Directory Scan Complete.[/bold green]\n")
 
    return data


def run(domain: str) -> dict:
    if MODE == "cli":
        return cli_display(domain)
    elif MODE == "web":
        pass
    else:
        console.print(f"[bold red]Unknown MODE '{MODE}' in config.py[/bold red]")
    return {}


if __name__ == "__main__":
    from url_parser import URLParser
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter target: ")
    domain = URLParser(target).url_domain or target.strip()
    if not domain:
        console.print("[bold red]Could not parse domain.[/bold red]")
        sys.exit(1)
    run(domain)