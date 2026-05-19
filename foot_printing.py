import sys
import re
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
 
from config import MODE
 
console = Console()
requests.packages.urllib3.disable_warnings()
 
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


VERSION_PATTERNS = {
    "WordPress": r'content=["\']WordPress ([\d.]+)',
    "Drupal":    r'content=["\']Drupal ([\d.]+)',
    "Joomla":    r'content=["\']Joomla! ([\d.]+)',
    "jQuery":    r'jquery[/-]([\d.]+)(\.min)?\.js',
    "React":     r'react[/@]([\d.]+)',
    "Vue":       r'vue[/@]([\d.]+)',
    "Angular":   r'angular[/@]([\d.]+)',
    "Bootstrap": r'bootstrap[/-]([\d.]+)',
    "PHP":       r'PHP/([\d.]+)',
    "Nginx":     r'nginx/([\d.]+)',
    "Apache":    r'Apache/([\d.]+)',
    "IIS":       r'Microsoft-IIS/([\d.]+)',
}

# signature database 
CMS_SIGS = {
    "WordPress":  ["/wp-content/", "/wp-includes/", "wp-emoji"],
    "Joomla":     ["/components/com_", "/media/jui/", "Joomla!"],
    "Drupal":     ["/sites/default/files/", "Drupal.settings", "X-Generator: Drupal"],
    "Magento":    ["/skin/frontend/", "Mage.Cookies", "/mage/"],
    "Shopify":    ["cdn.shopify.com", "Shopify.theme"],
    "Ghost":      ["/ghost/", "content=\"Ghost"],
}
 
FRAMEWORK_SIGS = {
    "Laravel":    ["laravel_session", "X-Powered-By: PHP"],
    "Django":     ["csrfmiddlewaretoken", "csrftoken"],
    "Express":    ["X-Powered-By: Express"],
    "Rails":      ["X-Powered-By: Phusion", "_rails_session"],
    "ASP.NET":    ["X-AspNet-Version", "__VIEWSTATE", "ASP.NET_SessionId"],
    "Next.js":    ["__NEXT_DATA__", "_next/static"],
    "Nuxt.js":    ["__nuxt", "__NUXT_DATA__"],
}
 
JS_SIGS = {
    "React":      ["react.min.js", "react-dom", "data-reactroot"],
    "Vue":        ["vue.min.js", "data-v-", "__vue__"],
    "jQuery":     ["jquery", "jQuery v", "jquery.min.js"],
    "Angular":    ["ng-version", "angular.min.js", "ng-app"],
    "Bootstrap":  ["bootstrap.min.js", "bootstrap.min.css"],
}
 
SERVER_SIGS = {
    "Nginx":      ["nginx"],
    "Apache":     ["Apache", "apache"],
    "IIS":        ["Microsoft-IIS", "IIS"],
    "LiteSpeed":  ["LiteSpeed"],
    "Caddy":      ["Caddy"],
    "Cloudflare": ["cloudflare"],
}



# working code 
def _fetch(domain: str) -> tuple:
    """Fetch page — returns (headers dict, html str, cookies dict)."""
    try:
        r = requests.get(
            f"https://{domain}", headers=HEADERS,
            timeout=5, verify=False, allow_redirects=True
        )
        return dict(r.headers), r.text, dict(r.cookies)
    except Exception:
        try:
            r = requests.get(
                f"http://{domain}", headers=HEADERS,
                timeout=5, verify=False, allow_redirects=True
            )
            return dict(r.headers), r.text, dict(r.cookies)
        except Exception:
            return {}, "", {}
 
 
def _match(sigs: dict, haystack: str) -> list:
    """Check haystack string against signature dict, return matched names."""
    found = []
    for name, patterns in sigs.items():
        if any(p.lower() in haystack.lower() for p in patterns):
            found.append(name)
    return found
 
 
def _probe_path(domain: str, path: str) -> bool:
    """Check if a specific path exists on the target."""
    try:
        r = requests.get(
            f"https://{domain}{path}", headers=HEADERS,
            timeout=3, verify=False, allow_redirects=False
        )
        return r.status_code in [200, 301, 302, 403]
    except Exception:
        try:
            r = requests.get(
                f"http://{domain}{path}", headers=HEADERS,
                timeout=3, verify=False, allow_redirects=False
            )
            return r.status_code in [200, 301, 302, 403]
        except Exception:
            return False
 
 
def _get_jquery_version(html: str) -> str | None:
    """Extract jQuery version from HTML source."""
    match = re.search(r'jquery[/-](\d+\.\d+[\.\d]*)(\.min)?\.js', html, re.I)
    if match:
        return match.group(1)
    match = re.search(r'jQuery v(\d+\.\d+[\.\d]*)', html)
    return match.group(1) if match else None
 
 
def get_server_info(headers: dict) -> dict:
    """Detect web server from response headers."""
    server_raw = headers.get("Server", "") or headers.get("server", "")
    powered     = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
    via         = headers.get("Via", "") or ""
    haystack    = f"{server_raw} {powered} {via}"
    detected    = _match(SERVER_SIGS, haystack)
    #Extracting version from headers
    versions={}
    header_str = f"{server_raw} {powered}"
    for tech in ["Nginx", "Apache", "IIS", "PHP"]:
        m = re.search(VERSION_PATTERNS[tech], header_str, re.I)
        if m:
            versions[tech] = m.group(1)

    return {
        "raw":       server_raw or "Hidden",
        "powered_by": powered   or None,
        "detected":  detected,
        "verisons": versions,
    }
 
 
def get_cms(html: str, headers: dict, domain: str) -> dict:
    """Detect CMS from HTML + headers + path probing."""
    header_str = " ".join(f"{k}: {v}" for k, v in headers.items())
    haystack   = html + header_str
    detected   = _match(CMS_SIGS, haystack)
 
    # Extra WordPress path probe if not already found
    if "WordPress" not in detected and _probe_path(domain, "/wp-login.php"):
        detected.append("WordPress")
    if "Joomla" not in detected and _probe_path(domain, "/administrator/"):
        detected.append("Joomla")
    #Extract cms version.
    versions = {}
    for tech in ["WordPress", "Drupal", "Joomla"]:
        m = re.search(VERSION_PATTERNS[tech], html, re.I)
        if m:
            versions[tech] = m.group(1)
 
    return {"detected": detected, "versions": versions}
 
 
def get_frameworks(html: str, headers: dict, cookies: dict) -> dict:
    """Detect backend frameworks from HTML + headers + cookies."""
    header_str = " ".join(f"{k}: {v}" for k, v in headers.items())
    cookie_str = " ".join(cookies.keys())
    haystack   = html + header_str + cookie_str
    return {"detected": _match(FRAMEWORK_SIGS, haystack)}
 
 
def get_js_libs(html: str) -> dict:
    detected = _match(JS_SIGS, html)
    versions = {}

    for tech in ["jQuery", "React", "Vue", "Angular", "Bootstrap"]:
        m = re.search(VERSION_PATTERNS[tech], html, re.I)
        if m:
            versions[tech] = m.group(1)

    # jQuery fallback already in old code
    if "jQuery" in detected and "jQuery" not in versions:
        m = re.search(r'jquery[/-](\d+\.\d+[\.\d]*)(\.min)?\.js', html, re.I)
        if m:
            versions["jQuery"] = m.group(1)

    return {"detected": detected, "versions": versions}
 
 
def get_all_data(domain: str) -> dict:
    """Master worker — runs all checks, returns combined dict."""
    headers, html, cookies = _fetch(domain)
    server     = get_server_info(headers)
    cms        = get_cms(html, headers, domain)
    frameworks = get_frameworks(html, headers, cookies)
    js_libs    = get_js_libs(html)

    # Combine ALL versions into one flat dict for cve_lookup.py
    all_versions = {}
    all_versions.update(server.get("versions", {}))
    all_versions.update(cms.get("versions", {}))
    all_versions.update(js_libs.get("versions", {}))
    return {
        "domain":      domain,
        "server":      server,
        "cms":         cms,
        "frameworks":  frameworks,
        "js_libs":     js_libs,
        "all_versions": all_versions,
    }



# cli____________________________ 
def cli_display(domain: str) -> None:
    console.print(f"\n[bold cyan][ DODGETHREAT3 ][/bold cyan] [white]Footprinting:[/white] [bold yellow]{domain}[/bold yellow]\n")
 
    data = get_all_data(domain)
 
    table = Table(
        title="  Technology Fingerprint",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
        min_width=60,
    )
    table.add_column("Category",  style="bold yellow", width=18)
    table.add_column("Detected",  style="white")
 
    # Server
    s = data["server"]
    server_str = s["raw"]
    if s["detected"]:
        server_str += f"  [dim]→ {', '.join(s['detected'])}[/dim]"
    if s["powered_by"]:
        server_str += f"\n[dim]Powered by: {s['powered_by']}[/dim]"
    if s.get("versions"):
        ver_str = ", ".join([f"{k} {v}" for k, v in s["versions"].items()])
        server_str += f"\n[dim]Versions: {ver_str}[/dim]"
    table.add_row("Web Server", server_str)
 
    # CMS
    cms = data["cms"]["detected"]
    cms_str = "[bold green]" + ", ".join(cms) + "[/bold green]" if cms else "[dim]Not detected[/dim]"
    if cms and data["cms"].get("versions"):
        ver_str = ", ".join([f"{k} {v}" for k, v in data["cms"]["versions"].items()])
        cms_str += f"\n[dim]Versions: {ver_str}[/dim]"
    table.add_row("CMS", cms_str)


    #framework
    fw = data["frameworks"]["detected"]
    table.add_row(
        "Framework",
        "[bold green]" + ", ".join(fw) + "[/bold green]" if fw
        else "[dim]Not detected[/dim]"
    )
 
    # JS libs
    js = data["js_libs"]
    if js["detected"]:
        libs = js["detected"].copy()
        for i, lib in enumerate(libs):
            if lib in js["versions"]:
                libs[i] = f"{lib} v{js['versions'][lib]}"
        js_str = "[bold green]" + ", ".join(libs) + "[/bold green]"
    else:
        js_str = "[dim]Not detected[/dim]"
    table.add_row("JS Libraries", js_str)
 
    console.print(table)
 
    # Summary panel
    all_found = (
        data["cms"]["detected"] +
        data["frameworks"]["detected"] +
        data["js_libs"]["detected"]
    )
    if all_found:
        console.print(Panel(
            f"[bold yellow]Attack surface:[/bold yellow] [white]{', '.join(all_found)}[/white]\n"
            f"[dim]Each detected technology is a potential attack vector.[/dim]",
            title="[bold red]  ⚠ Technologies Exposed[/bold red]",
            border_style="red", padding=(1, 2),
        ))
    else:
        console.print(Panel(
            "[bold green]✔ No major technology signatures detected[/bold green]",
            title="[bold green]  Footprint Summary[/bold green]",
            border_style="green", padding=(1, 2),
        ))
 
    console.print()
    console.print("[bold cyan][ DODGETHREAT3 ][/bold cyan] [bold green]Footprinting Complete.[/bold green]\n")



#config_________________
 
def run(domain: str):
    if MODE == "cli":
        cli_display(domain)
    elif MODE == "web":
        pass  # web_based(domain) — uncomment Phase 2
    else:
        console.print(f"[bold red]Unknown MODE '{MODE}' in config.py[/bold red]") 



if __name__ == "__main__":
    from url_parser import URLParser
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter target: ")
    domain = URLParser(target).url_domain
    if not domain:
        console.print("[bold red]Could not parse domain.[/bold red]")
        sys.exit(1)
    run(domain)