import socket
import sys
from urllib.parse import urlparse


class URLParser:
    def __init__(self,input_target):
        self.raw_input=input_target.strip()
        self.parsed=self._parse_it()
    
    def _parse_it(self):
        temp_url=self.raw_input
        if not temp_url.startswith(("http://","https://")): 
            temp_url="http://"+ temp_url
        return urlparse(temp_url)
         
    @property
    def url_ip(self):
        "Returns ip for neeeded tools"
        try:
            return socket.gethostbyname(self.parsed.hostname)
        except Exception:
            return None


    @property
    def url_domain(self):
        """Returns base URL for scanning tools"""
        scheme = self.parsed.scheme if self.parsed.scheme else "http"
        return f"{scheme}://{self.parsed.netloc}"

    @property
    def parsed_url(self):
        """parsed url with out http: and all """
        scheme=self.parsed.scheme  if self.parsed.scheme else "http"
        return f"{scheme}://{self.parsed.netloc}{self.parsed.path}"
    


def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
    elif not sys.stdin.isatty():
        target = sys.stdin.read().strip()
    else:
        target = input("Enter Target URL/Domain: ")

    if not target:
        print("No target provided.")
        return
    parser=URLParser(target)

    print(f"IP:{parser.url_ip}")
    print(f"IP:{parser.parsed_url}")


if __name__ == "__main__":
    main()