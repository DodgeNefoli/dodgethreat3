import re
import sys
import socket
import datetime
import requests
from rich.console import Console
from rich.table import Table
from rich import box

from config import MODE

console = Console()
requests.packages.urllib3.disable_warnings()

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
ADMIN_SIGNATURES = {
    "WordPress Admin": ["wp-login", "wordpress", "lost your password"],
    "phpMyAdmin":      ["phpmyadmin", "pma_", "pmahomepage"],
    "Adminer":         ["adminer", "adminer.org"],
    "cPanel":          ["cpanel", "whostmgr"],
    "Plesk":           ["plesk", "parallels"],
    "Webmin":          ["webmin", "miniserv"],
    "Django Admin":    ["django administration", "site administration"],
    "Laravel Admin":   ["laravel", "nova", "backpack"],
    "Joomla Admin":    ["joomla administration", "com_login"],
    "Drupal Admin":    ["drupal", "user/login"],
    "Grafana":         ["grafana", "grafana.com"],
    "Jenkins":         ["jenkins", "hudson"],
    "Kibana":          ["kibana", "elastic"],
}

# ─────────────────────────────────────────────
# CMS-specific version paths  ← NEW
# ─────────────────────────────────────────────
CMS_VERSION_PATHS = {
    "WordPress Admin": [
        ("/readme.html",                              r'[Vv]ersion\s+([\d.]+)'),
        ("/?feed=rss2",                               r'<generator>.*?/([\d.]+)'),
        ("/wp-includes/version.php",                  r"\$wp_version\s*=\s*'([\d.]+)'"),
    ],
    "Joomla Admin": [
        ("/administrator/manifests/files/joomla.xml", r'<version>([\d.]+)</version>'),
        ("/language/en-GB/en-GB.xml",                 r'<version>([\d.]+)</version>'),
    ],
    "Drupal Admin": [
        ("/CHANGELOG.txt",                            r'Drupal\s+([\d.]+)'),
        ("/core/CHANGELOG.txt",                       r'Drupal\s+([\d.]+)'),
    ],
    "phpMyAdmin": [
        ("/README",                                   r'phpMyAdmin\s+([\d.]+)'),
        ("/ChangeLog",                                r'([\d]+\.[\d]+\.[\d]+)'),
    ],
    "Jenkins": [
        ("/login",                                    r'Jenkins\s+ver\.\s+([\d.]+)'),
        ("/api/json",                                 r'"version"\s*:\s*"([\d.]+)"'),
    ],
    "Grafana": [
        ("/api/health",                               r'"version"\s*:\s*"([\d.]+)"'),
    ],
}

# ─────────────────────────────────────────────
# workers
# ─────────────────────────────────────────────
def _get(url: str, timeout: int = 6) -> requests.Response | None:
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
        return r if r.status_code == 200 else None
    except Exception:
        return None


def _regex(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.I)
    return m.group(1).strip() if m else None


# ─────────────────────────────────────────────
# version sources  ← ALL NEW
# ─────────────────────────────────────────────
def get_version_from_headers(headers: dict) -> tuple[str | None, str]:
    """Check response headers for version info. Returns (version, source)."""
    checks = [
        ("Server",       r'([\d]+\.[\d]+[\.\d]*)'),
        ("X-Powered-By", r'([\d]+\.[\d]+[\.\d]*)'),
        ("X-Generator",  r'(.+)'),
    ]
    for header, pattern in checks:
        val = headers.get(header, "")
        if val:
            m = re.search(pattern, val, re.I)
            if m:
                return m.group(1).strip(), f"header:{header}"
            # return the raw value even without version number (e.g. "JSP/2.1")
            return val[:40], f"header:{header}"
    return None, ""


def get_version_from_cms_paths(domain: str, panel: str) -> tuple[str | None, str]:
    """Hit CMS-specific known paths to get exact version. Returns (version, source)."""
    paths = CMS_VERSION_PATHS.get(panel, [])
    for path, pattern in paths:
        for scheme in ["https", "http"]:
            r = _get(f"{scheme}://{domain}{path}")
            if r:
                v = _regex(pattern, r.text)
                if v:
                    return v, f"cms_path:{path}"
    return None, ""


def get_version_from_assets(html: str) -> tuple[str | None, str]:
    """Extract version from JS/CSS asset URLs in page source. Returns (version, source)."""
    patterns = [
        (r'[?&]ver=([\d]+\.[\d]+[\.\d]*)',       "asset_url:?ver="),
        (r'[?&]v=([\d]+\.[\d]+[\.\d]*)',          "asset_url:?v="),
        (r'jquery[.-]([\d]+\.[\d]+[\.\d]*)\.js', "asset_url:jquery"),
        (r'bootstrap[.-]([\d]+\.[\d]+[\.\d]*)',  "asset_url:bootstrap"),
    ]
    for pattern, source in patterns:
        m = re.search(pattern, html, re.I)
        if m:
            return m.group(1), source
    return None, ""


def get_version_from_api(domain: str) -> tuple[str | None, str]:
    """Check common JSON API endpoints for version info. Returns (version, source)."""
    api_paths = ["/api/version", "/api/v1/version", "/version.json",
                 "/api/health", "/status", "/info"]
    for path in api_paths:
        for scheme in ["https", "http"]:
            r = _get(f"{scheme}://{domain}{path}")
            if r:
                try:
                    data = r.json()
                    for key in ["version", "app_version", "build", "release"]:
                        if key in data:
                            return str(data[key]), f"api:{path}"
                except Exception:
                    v = _regex(r'"version"\s*:\s*"([\d.]+)"', r.text)
                    if v:
                        return v, f"api:{path}"
    return None, ""


def resolve_version(domain: str, panel: str | None,
                    html: str, headers: dict) -> tuple[str | None, str, str]:
    """
    Priority chain — tries every source in order.
    Returns (version, source, confidence)
    confidence: high / medium / low
    """
    # 1. headers — fastest, no extra request
    v, src = get_version_from_headers(headers)
    if v:
        return v, src, "high"

    # 2. CMS-specific paths — most accurate
    if panel:
        v, src = get_version_from_cms_paths(domain, panel)
        if v:
            return v, src, "high"

    # 3. asset URLs in HTML
    v, src = get_version_from_assets(html)
    if v:
        return v, src, "medium"

    # 4. JSON API endpoints
    v, src = get_version_from_api(domain)
    if v:
        return v, src, "medium"

    # 5. safe HTML patterns — last resort, low confidence
    safe_patterns = [
        (r'<meta[^>]+generator[^>]+([\d]+\.[\d]+[\.\d]*)', "html:meta_generator"),
        (r'[?&]ver=([\d]+\.[\d]+[\.\d]*)',                  "html:ver_param"),
        (r'"version"\s*:\s*"([\d.]+)"',                     "html:json_inline"),
    ]
    for pattern, src in safe_patterns:
        v = _regex(pattern, html)
        if v and len(v) < 15:
            return v, src, "low"

    return None, "", "none"





# ─────────────────────────────────────────────
# CMS probes (unchanged)
# ─────────────────────────────────────────────
def probe_wordpress(domain: str) -> str | None:
    base = f"http://{domain}"
    r = _get(f"{base}/readme.html")
    if r:
        v = _regex(r'[Vv]ersion\s+([\d.]+)', r.text)
        if v: return v
    r = _get(f"{base}/?feed=rss2")
    if r:
        v = _regex(r'<generator>.*?WordPress\s+([\d.]+)', r.text)
        if v: return v
    r = _get(base)
    if r:
        v = _regex(r'<meta[^>]+generator[^>]+WordPress\s*([\d.]+)', r.text)
        if v: return v
    return None

def probe_joomla(domain: str) -> str | None:
    base = f"http://{domain}"
    r = _get(f"{base}/administrator/manifests/files/joomla.xml")
    if r:
        v = _regex(r'<version>([\d.]+)</version>', r.text)
        if v: return v
    r = _get(f"{base}/language/en-GB/en-GB.xml")
    if r:
        v = _regex(r'<version>([\d.]+)</version>', r.text)
        if v: return v
    return None

def probe_drupal(domain: str) -> str | None:
    base = f"http://{domain}"
    r = _get(f"{base}/CHANGELOG.txt")
    if r:
        v = _regex(r'Drupal\s+([\d.]+)', r.text)
        if v: return v
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


# ─────────────────────────────────────────────
# service banner probes (unchanged)
# ─────────────────────────────────────────────
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


# ─────────────────────────────────────────────
# dispatchers (unchanged)
# ─────────────────────────────────────────────
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
    versions  = dict(foot_data.get("all_versions", {}))
    not_found = []

    detected_cms = foot_data.get("cms", {}).get("detected", [])
    detected_fw  = foot_data.get("frameworks", {}).get("detected", [])

    for tech in detected_cms + detected_fw:
        if tech in versions:
            continue
        probe_fn = PROBE_MAP.get(tech)
        if probe_fn:
            v = probe_fn(domain)
            if v:
                versions[tech] = v
            else:
                not_found.append(tech)

    for service, probe_fn in SERVICE_PROBES.items():
        if service not in versions:
            v = probe_fn(domain)
            if v:
                versions[service] = v

    return {
        "versions":     versions,
        "not_found":    not_found,
    }


# ─────────────────────────────────────────────
# CLI display  ← UPDATED to show new fields
# ─────────────────────────────────────────────
def cli_display(domain: str, foot_data: dict) -> dict:
    data = get_all_versions(domain, foot_data)

    console.print(f"\n[bold cyan][ DODGETHREAT3 ][/bold cyan] "
                  f"[white]Version Engine:[/white] [bold yellow]{domain}[/bold yellow]\n")

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
    console.print("[bold cyan][ DODGETHREAT3 ][/bold cyan] "
                  "[bold green]Version Engine Complete.[/bold green]\n")

    return data


# ─────────────────────────────────────────────
# entry point
# ─────────────────────────────────────────────
def run(domain: str, foot_data: dict) -> dict:
    if MODE == "cli":
        return cli_display(domain, foot_data)
    elif MODE == "web":
        pass
    else:
        console.print(f"[bold red]Unknown MODE '{MODE}' in config.py[/bold red]")
    return {}


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