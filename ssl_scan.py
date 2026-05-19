import ssl
import socket
import datetime
import sys
import requests
 
import OpenSSL.SSL as ossl
import OpenSSL.crypto as ocrypto
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box
 
from config import MODE
 
console = Console()

#weak  cipher

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "anon", "ADH", "AECDH", "RC2", "IDEA", "SEED",
]
 
WEAK_TLS_VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
STRONG_TLS_VERSIONS = ["TLSv1.2", "TLSv1.3"]

#-------- doesnot chnage for both cil and web
def get_certificate_info(domain: str, port: int = 443) -> dict:
    """
    Fetch full certificate details:
    expiry, issuer, subject, self-signed, chain, OCSP Must-Staple.
 
    Returns:
        {
            domain              : str,
            subject             : dict,
            issuer              : dict,
            serial_number       : str,
            not_before          : str,
            not_after           : str,
            days_remaining      : int | None,
            is_expired          : bool,
            is_self_signed      : bool,
            chain_valid         : bool,
            chain_depth         : int,
            ocsp_must_staple    : bool,
            san                 : list,
            signature_algorithm : str | None,
            error               : str | None
        }
    """
    result = {
        "domain":              domain,
        "subject":             {},
        "issuer":              {},
        "serial_number":       None,
        "not_before":          None,
        "not_after":           None,
        "days_remaining":      None,
        "is_expired":          False,
        "is_self_signed":      False,
        "chain_valid":         False,
        "chain_depth":         0,
        "ocsp_must_staple":    False,
        "san":                 [],
        "signature_algorithm": None,
        "error":               None,
    }
 
    try:
        # ── Connect and get full chain via pyOpenSSL ──────────
        ctx = ossl.Context(ossl.TLS_CLIENT_METHOD)
        ctx.set_verify(ossl.VERIFY_NONE, lambda *a: True)
 
        conn = ossl.Connection(ctx, socket.create_connection((domain, port), timeout=10))
        conn.set_tlsext_host_name(domain.encode())
        conn.set_connect_state()
        conn.do_handshake()
 
        cert = conn.get_peer_certificate()
        chain = conn.get_peer_cert_chain()
        conn.close()

        # sub
        subj = cert.get_subject()
        result["subject"] = {
            "CN": subj.CN or "",
            "O":  subj.O  or "",
            "C":  subj.C  or "",
        }
        #issure
        iss = cert.get_issuer()
        result["issuer"] = {
            "CN": iss.CN or "",
            "O":  iss.O  or "",
            "C":  iss.C  or "",
        }
        #serial
        result["serial_number"] = str(cert.get_serial_number())
        #validity dates
        not_before_raw = cert.get_notBefore().decode()
        not_after_raw  = cert.get_notAfter().decode()
 
        fmt = "%Y%m%d%H%M%SZ"
        not_before_dt = datetime.datetime.strptime(not_before_raw, fmt)
        not_after_dt  = datetime.datetime.strptime(not_after_raw,  fmt)
 
        result["not_before"] = not_before_dt.strftime("%Y-%m-%d")
        result["not_after"]  = not_after_dt.strftime("%Y-%m-%d")
 
        now = datetime.datetime.utcnow()
        delta = not_after_dt - now
        result["days_remaining"] = delta.days
        result["is_expired"]     = delta.days < 0
 
        # ── Self-signed detection 
        result["is_self_signed"] = (
            cert.get_subject().CN == cert.get_issuer().CN
        )        
        # ── Chain depth ───────────────────────────────────────
        result["chain_depth"] = len(chain) if chain else 0
        result["chain_valid"] = result["chain_depth"] > 1
 
        # ── Signature algorithm ───────────────────────────────
        result["signature_algorithm"] = cert.get_signature_algorithm().decode()
 
        # ── SAN (Subject Alternative Names) ───────────────────
        san_list = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                san_list = [
                    s.strip().replace("DNS:", "")
                    for s in str(ext).split(",")
                ]
            # ── OCSP Must-Staple ──────────────────────────────
            if ext.get_short_name() == b"tlsfeature":
                result["ocsp_must_staple"] = "status_request" in str(ext).lower()
 
        result["san"] = san_list
 
    except Exception as e:
        result["error"] = str(e)
 
    return result
 
 
def get_tls_versions(domain: str, port: int = 443) -> dict:
    """
    Test which TLS/SSL versions the server supports.
 
    Returns:
        {
            domain   : str,
            versions : {
                "TLSv1.3" : bool,
                "TLSv1.2" : bool,
                "TLSv1.1" : bool,
                "TLSv1"   : bool,
            },
            weak_versions_enabled  : list,
            strong_versions_enabled: list,
            error : str | None
        }
    """
    result = {
        "domain":                 domain,
        "versions":               {},
        "weak_versions_enabled":  [],
        "strong_versions_enabled": [],
        "error":                  None,
    }
 
    version_map = {
        "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
        "TLSv1":   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None,
    }
 
    for version_name, version_const in version_map.items():
        if version_const is None:
            result["versions"][version_name] = False
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = version_const
            ctx.maximum_version = version_const
            with socket.create_connection((domain, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    result["versions"][version_name] = True
        except Exception:
            result["versions"][version_name] = False
 
    for v, supported in result["versions"].items():
        if supported:
            if v in WEAK_TLS_VERSIONS:
                result["weak_versions_enabled"].append(v)
            else:
                result["strong_versions_enabled"].append(v)
 
    return result
 
 
def get_cipher_info(domain: str, port: int = 443) -> dict:
    """
    Get negotiated cipher suite and detect weak ciphers.
 
    Returns:
        {
            domain              : str,
            negotiated_cipher   : str | None,
            negotiated_protocol : str | None,
            cipher_bits         : int | None,
            is_weak             : bool,
            weak_reason         : str | None,
            error               : str | None
        }
    """
    result = {
        "domain":              domain,
        "negotiated_cipher":   None,
        "negotiated_protocol": None,
        "cipher_bits":         None,
        "is_weak":             False,
        "weak_reason":         None,
        "error":               None,
    }
 
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
 
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher_name, protocol, bits = ssock.cipher()
                result["negotiated_cipher"]   = cipher_name
                result["negotiated_protocol"] = protocol
                result["cipher_bits"]         = bits
 
                for weak in WEAK_CIPHERS:
                    if weak.upper() in cipher_name.upper():
                        result["is_weak"]     = True
                        result["weak_reason"] = f"Contains weak component: {weak}"
                        break
 
                if bits and bits < 128:
                    result["is_weak"]     = True
                    result["weak_reason"] = f"Key size too small: {bits} bits"
 
    except Exception as e:
        result["error"] = str(e)
 
    return result
 
 
def check_hsts(domain: str) -> dict:
    """
    Check if HSTS (HTTP Strict Transport Security) header is present.
 
    Returns:
        {
            domain          : str,
            hsts_enabled    : bool,
            max_age         : int | None,
            include_subdomains: bool,
            preload         : bool,
            raw_header      : str | None,
            error           : str | None
        }
    """
    result = {
        "domain":              domain,
        "hsts_enabled":        False,
        "max_age":             None,
        "include_subdomains":  False,
        "preload":             False,
        "raw_header":          None,
        "error":               None,
    }
 
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=10,
            allow_redirects=True,
            verify=False,
        )
        hsts = resp.headers.get("Strict-Transport-Security", None)
 
        if hsts:
            result["hsts_enabled"] = True
            result["raw_header"]   = hsts
 
            for part in hsts.split(";"):
                part = part.strip().lower()
                if part.startswith("max-age="):
                    try:
                        result["max_age"] = int(part.split("=")[1])
                    except Exception:
                        pass
                if part == "includesubdomains":
                    result["include_subdomains"] = True
                if part == "preload":
                    result["preload"] = True
 
    except Exception as e:
        result["error"] = str(e)
 
    return result
 
 
def get_all_data(domain: str) -> dict:
    """
    Master worker — runs all 4 checks, returns one combined dict.
    This is what cli_display() and web_based() both use.
    """
    return {
        "domain":      domain,
        "certificate": get_certificate_info(domain),
        "tls":         get_tls_versions(domain),
        "cipher":      get_cipher_info(domain),
        "hsts":        check_hsts(domain),
    }
 
 
# ─────────────────────────────────────────────────────────────
# PART 2 — CLI DISPLAY
# Uses Rich. Only called when MODE = "cli" in config.py
# ─────────────────────────────────────────────────────────────
 
def _status(ok: bool, yes_text: str = "YES", no_text: str = "NO") -> str:
    """Helper — returns green YES or red NO for Rich display."""
    if ok:
        return f"[bold green]{yes_text}[/bold green]"
    return f"[bold red]{no_text}[/bold red]"
 
 
def _days_color(days: int) -> str:
    """Helper — color code days remaining by urgency."""
    if days < 0:
        return f"[bold red]EXPIRED ({abs(days)} days ago)[/bold red]"
    elif days <= 14:
        return f"[bold red]{days} days — CRITICAL[/bold red]"
    elif days <= 30:
        return f"[bold yellow]{days} days — WARNING[/bold yellow]"
    elif days <= 90:
        return f"[yellow]{days} days — MONITOR[/yellow]"
    else:
        return f"[bold green]{days} days — HEALTHY[/bold green]"
 
 
def cli_display(domain: str) -> None:
    """Fetch all SSL/TLS data and display beautifully in terminal."""
 
    console.print(f"\n[bold cyan][ DODGETHREAT3 ][/bold cyan] [white]SSL/TLS Scan:[/white] [bold yellow]{domain}[/bold yellow]\n")
 
    data = get_all_data(domain)
 
    # ── CERTIFICATE INFO ──────────────────────────────────────
    cert = data["certificate"]
 
    cert_table = Table(
        title="  Certificate Information",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
        min_width=60,
    )
    cert_table.add_column("Field",  style="bold yellow", width=22)
    cert_table.add_column("Value",  style="white")
 
    subj = cert.get("subject", {})
    iss  = cert.get("issuer",  {})
 
    cert_table.add_row("Common Name (CN)", subj.get("CN") or "Unknown")
    cert_table.add_row("Organisation",     subj.get("O")  or "Unknown")
    cert_table.add_row("Country",          subj.get("C")  or "Unknown")
    cert_table.add_row("Issuer CN",        iss.get("CN")  or "Unknown")
    cert_table.add_row("Issuer Org",       iss.get("O")   or "Unknown")
    cert_table.add_row("Valid From",       cert.get("not_before") or "Unknown")
    cert_table.add_row("Valid Until",      cert.get("not_after")  or "Unknown")
 
    days = cert.get("days_remaining")
    cert_table.add_row(
        "Days Remaining",
        _days_color(days) if days is not None else "[dim]Unknown[/dim]"
    )
 
    cert_table.add_row(
        "Expired",
        _status(not cert.get("is_expired", True), "NO ✔", "YES ✘")
    )
    cert_table.add_row(
        "Self-Signed",
        _status(not cert.get("is_self_signed", False), "NO ✔ (CA Signed)", "YES ✘ (Untrusted)")
    )
    cert_table.add_row(
        "Chain Valid",
        _status(cert.get("chain_valid", False), "YES ✔", "NO ✘")
    )
    cert_table.add_row("Chain Depth",        str(cert.get("chain_depth", 0)))
    cert_table.add_row(
        "OCSP Must-Staple",
        _status(cert.get("ocsp_must_staple", False), "ENABLED ✔", "DISABLED ✘")
    )
    cert_table.add_row(
        "Signature Algorithm",
        cert.get("signature_algorithm") or "Unknown"
    )
    cert_table.add_row("Serial Number",      cert.get("serial_number") or "Unknown")
 
    san = cert.get("san", [])
    cert_table.add_row(
        "SANs",
        "\n".join(san[:5]) + (f"\n[dim]...+{len(san)-5} more[/dim]" if len(san) > 5 else "")
        if san else "[dim]None[/dim]"
    )
 
    if cert.get("error"):
        cert_table.add_row("[red]Error[/red]", f"[red]{cert['error']}[/red]")
 
    console.print(cert_table)
    console.print()
 
    # ── TLS VERSIONS ─────────────────────────────────────────
    tls = data["tls"]
 
    tls_table = Table(
        title="  TLS Version Support",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
        min_width=60,
    )
    tls_table.add_column("Version",   style="bold yellow", width=12)
    tls_table.add_column("Supported", style="white",       width=20)
    tls_table.add_column("Security",  style="white")
 
    version_security = {
        "TLSv1.3": ("bold green", "SECURE ✔ — Recommended"),
        "TLSv1.2": ("green",      "SECURE ✔ — Acceptable"),
        "TLSv1.1": ("bold red",   "WEAK ✘ — Deprecated"),
        "TLSv1":   ("bold red",   "WEAK ✘ — Deprecated"),
    }
 
    for ver, supported in tls.get("versions", {}).items():
        color, security_label = version_security.get(ver, ("white", "Unknown"))
        supported_str = (
            f"[{color}]YES[/{color}]" if supported
            else "[dim]NO[/dim]"
        )
        security_str = (
            f"[{color}]{security_label}[/{color}]" if supported
            else "[dim]—[/dim]"
        )
        tls_table.add_row(ver, supported_str, security_str)
 
    weak = tls.get("weak_versions_enabled", [])
    if weak:
        tls_table.add_row(
            "[bold red]⚠ WARNING[/bold red]",
            "",
            f"[bold red]Weak versions active: {', '.join(weak)}[/bold red]"
        )
 
    console.print(tls_table)
    console.print()
 
    # ── CIPHER INFO ───────────────────────────────────────────
    cipher = data["cipher"]
 
    cipher_table = Table(
        title="  Cipher Suite Analysis",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
        min_width=60,
    )
    cipher_table.add_column("Field",  style="bold yellow", width=22)
    cipher_table.add_column("Value",  style="white")
 
    cipher_table.add_row(
        "Negotiated Cipher",
        cipher.get("negotiated_cipher") or "[dim]Unknown[/dim]"
    )
    cipher_table.add_row(
        "Protocol",
        cipher.get("negotiated_protocol") or "[dim]Unknown[/dim]"
    )
    bits = cipher.get("cipher_bits")
    cipher_table.add_row(
        "Key Bits",
        f"[bold green]{bits} bits[/bold green]" if bits and bits >= 128
        else f"[bold red]{bits} bits — WEAK[/bold red]" if bits
        else "[dim]Unknown[/dim]"
    )
    cipher_table.add_row(
        "Cipher Strength",
        _status(not cipher.get("is_weak", True), "STRONG ✔", "WEAK ✘")
    )
    if cipher.get("weak_reason"):
        cipher_table.add_row(
            "[bold red]Weak Reason[/bold red]",
            f"[bold red]{cipher['weak_reason']}[/bold red]"
        )
 
    console.print(cipher_table)
    console.print()
 
    # ── HSTS ─────────────────────────────────────────────────
    hsts = data["hsts"]
 
    hsts_table = Table(
        title="  HSTS (HTTP Strict Transport Security)",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
        show_lines=True,
        min_width=60,
    )
    hsts_table.add_column("Field",  style="bold yellow", width=22)
    hsts_table.add_column("Value",  style="white")
 
    hsts_table.add_row(
        "HSTS Enabled",
        _status(hsts.get("hsts_enabled", False), "YES ✔", "NO ✘ — MISSING")
    )
 
    max_age = hsts.get("max_age")
    if max_age is not None:
        days_age = max_age // 86400
        age_color = "bold green" if days_age >= 180 else "bold yellow"
        hsts_table.add_row(
            "Max-Age",
            f"[{age_color}]{max_age} seconds ({days_age} days)[/{age_color}]"
        )
    else:
        hsts_table.add_row("Max-Age", "[dim]N/A[/dim]")
 
    hsts_table.add_row(
        "includeSubDomains",
        _status(hsts.get("include_subdomains", False), "YES ✔", "NO")
    )
    hsts_table.add_row(
        "Preload",
        _status(hsts.get("preload", False), "YES ✔", "NO")
    )
    if hsts.get("raw_header"):
        hsts_table.add_row("Raw Header", hsts["raw_header"])
 
    console.print(hsts_table)
    console.print()
 
    # ── SUMMARY PANEL ─────────────────────────────────────────
    issues = []
    if cert.get("is_expired"):
        issues.append("[bold red]✘ Certificate is EXPIRED[/bold red]")
    if cert.get("is_self_signed"):
        issues.append("[bold red]✘ Certificate is SELF-SIGNED (untrusted)[/bold red]")
    if not cert.get("chain_valid"):
        issues.append("[bold red]✘ Certificate chain is INVALID[/bold red]")
    if not cert.get("ocsp_must_staple"):
        issues.append("[yellow]⚠ OCSP Must-Staple not enabled[/yellow]")
    if tls.get("weak_versions_enabled"):
        issues.append(f"[bold red]✘ Weak TLS versions active: {', '.join(tls['weak_versions_enabled'])}[/bold red]")
    if cipher.get("is_weak"):
        issues.append(f"[bold red]✘ Weak cipher in use: {cipher.get('weak_reason')}[/bold red]")
    if not hsts.get("hsts_enabled"):
        issues.append("[bold red]✘ HSTS is NOT enabled[/bold red]")
    if days is not None and 0 < days <= 30:
        issues.append(f"[bold yellow]⚠ Certificate expires in {days} days[/bold yellow]")
 
    if issues:
        summary_text = "\n".join(issues)
        console.print(Panel(
            summary_text,
            title="[bold red]  ⚠ Issues Found[/bold red]",
            border_style="red",
            padding=(1, 2),
        ))
    else:
        console.print(Panel(
            "[bold green]✔ No major SSL/TLS issues detected[/bold green]",
            title="[bold green]  SSL/TLS Summary[/bold green]",
            border_style="green",
            padding=(1, 2),
        ))
 
    console.print()
    console.print("[bold cyan][ DODGETHREAT3 ][/bold cyan] [bold green]SSL/TLS Scan Complete.[/bold green]\n")


    #web part--------------

    

    # Reads config.py
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


#url parseer 
if __name__ == "__main__":
    from url_parser import URLParser
 
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter target domain/URL: ")
    parser = URLParser(target)
    domain = parser.url_domain
 
    if not domain:
        console.print("[bold red]Could not parse domain from input.[/bold red]")
        sys.exit(1)
 
    run(domain)