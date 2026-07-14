import argparse
import concurrent.futures
import sys
import threading
import time
from datetime import datetime
from urllib.parse import urljoin
 
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
 
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
 
print_lock = threading.Lock()
 
# ANSI colors for quick visual triage in the terminal (purely cosmetic)
COLORS = {
    "2": "\033[92m",  # green  - 2xx
    "3": "\033[94m",  # blue   - 3xx
    "4": "\033[93m",  # yellow - 4xx
    "5": "\033[91m",  # red    - 5xx
    "reset": "\033[0m",
}
 
 
def color_for(status_code):
    return COLORS.get(str(status_code)[0], "")
 
 
def load_wordlist(path):
    try:
        with open(path, "r", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return words
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {path}")
        sys.exit(1)
 
 
def build_targets(base_url, words, extensions):
    """Yield every path to test, including extension variants."""
    for w in words:
        w = w.lstrip("/")
        yield urljoin(base_url + "/", w)
        for ext in extensions:
            ext = ext.strip().lstrip(".")
            if ext:
                yield urljoin(base_url + "/", f"{w}.{ext}")
 
 
def scan_url(session, url, timeout, follow_redirects, headers):
    try:
        resp = session.get(
            url,
            timeout=timeout,
            allow_redirects=follow_redirects,
            verify=False,
            headers=headers,
        )
        return url, resp.status_code, len(resp.content), resp.headers.get("Location", "")
    except requests.exceptions.RequestException as e:
        return url, "ERR", 0, str(e).split("\n")[0][:80]
 
 
def run_scan(args):
    base_url = args.domain
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"
 
    words = load_wordlist(args.wordlist)
    extensions = args.ext.split(",") if args.ext else []
    targets = list(build_targets(base_url.rstrip("/"), words, extensions))
    total = len(targets)
 
    print(f"[*] Target        : {base_url}")
    print(f"[*] Wordlist      : {args.wordlist} ({len(words)} words)")
    print(f"[*] Extensions    : {extensions if extensions else 'none'}")
    print(f"[*] Total requests: {total}")
    print(f"[*] Threads       : {args.threads}")
    print(f"[*] Filter        : {'status in ' + args.filter if args.filter else 'NONE (showing everything)'}")
    print(f"[*] Started       : {datetime.now().isoformat(timespec='seconds')}")
    print("-" * 70)
 
    filter_codes = set()
    if args.filter:
        filter_codes = {c.strip() for c in args.filter.split(",")}
 
    headers = {"User-Agent": args.user_agent}
    session = requests.Session()
 
    found = []
    start = time.time()
 
    outfile = open(args.output, "w") if args.output else None
 
    def worker(url):
        return scan_url(session, url, args.timeout, args.follow_redirects, headers)
 
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(worker, url): url for url in targets}
        done_count = 0
        for future in concurrent.futures.as_completed(futures):
            url, code, size, extra = future.result()
            done_count += 1
 
            if args.filter and str(code) not in filter_codes:
                continue
 
            line = f"[{code}] {url} (size={size})"
            if extra:
                line += f" -> {extra}"
 
            with print_lock:
                c = color_for(code) if code != "ERR" else ""
                print(f"{c}{line}{COLORS['reset']}")
                if outfile:
                    outfile.write(line + "\n")
                    outfile.flush()
 
            if code != "ERR":
                found.append((url, code, size))
 
            if args.progress and done_count % 200 == 0:
                with print_lock:
                    print(f"    ... {done_count}/{total} requests done", file=sys.stderr)
 
    elapsed = time.time() - start
    print("-" * 70)
    print(f"[*] Finished in {elapsed:.1f}s - {len(found)} responses logged out of {total} requests")
    if outfile:
        outfile.close()
        print(f"[*] Results saved to {args.output}")
 
 
def parse_args():
    p = argparse.ArgumentParser(
        description="Threaded directory / admin-panel brute-force scanner (authorized testing only)."
    )
    p.add_argument("-d", "--domain", required=True, help="Target domain or base URL, e.g. example.com")
    p.add_argument(
        "-w",
        "--wordlist",
        default="/usr/share/seclists/Discovery/Web-Content/common.txt",
        help="Path to wordlist (default: SecLists common.txt path)",
    )
    p.add_argument("-t", "--threads", type=int, default=30, help="Number of concurrent threads (default: 30)")
    p.add_argument("--timeout", type=float, default=6.0, help="Per-request timeout in seconds (default: 6)")
    p.add_argument("--ext", default="", help="Comma-separated extra extensions to try, e.g. php,bak,zip,old")
    p.add_argument(
        "--filter",
        default="",
        help="Comma-separated status codes to SHOW (default: show everything, no filtering)",
    )
    p.add_argument("-o", "--output", default="", help="File to save results to")
    p.add_argument(
        "--follow-redirects",
        action="store_true",
        help="Follow redirects instead of showing the raw 3xx status",
    )
    p.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (X11; Linux x86_64) panelscan/1.0",
        help="Custom User-Agent header",
    )
    p.add_argument("--progress", action="store_true", help="Print periodic progress updates to stderr")
    return p.parse_args()
 
 
if __name__ == "__main__":
    try:
        run_scan(parse_args())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)