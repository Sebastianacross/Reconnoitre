import aiohttp
import asyncio
import socket
import ssl
import whois
import json
import csv
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import requests

class ReconScanner:
    def __init__(self, base_url, output_fn, custom_sub_path=None, custom_dir_path=None):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.output = output_fn
        self.custom_sub_path = custom_sub_path
        self.custom_dir_path = custom_dir_path

        self.COMMON_SUBDOMAINS = self.load_wordlist(custom_sub_path) or ['www', 'mail', 'ftp', 'dev', 'test', 'blog', 'portal']
        self.COMMON_DIRS = self.load_wordlist(custom_dir_path) or ['admin', 'login', 'uploads', 'images', 'api', '.git', '.env']
        self.SECURITY_HEADERS = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]

        self.results = {
            "robots_txt": "",
            "links": [],
            "subdomains": [],
            "directories": [],
            "whois": {},
            "ip": "",
            "ssl": {},
            "headers": {},
            "titles": [],
            "cms": "",
            "broken_links": [],
            "directory_indexing": []
        }

    def load_wordlist(self, path):
        if path:
            try:
                with open(path, "r") as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception:
                self.output(f"[-] Failed to load wordlist: {path}")
        return None

    async def fetch_head(self, session, url):
        try:
            async with session.head(url, timeout=10, allow_redirects=True) as response:
                return url, response.status
        except Exception:
            return url, None

    async def scan_subdomains(self):
        self.output("\\n🔍 Checking subdomains...")
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_head(session, f"http://{sub}.{self.domain}") for sub in self.COMMON_SUBDOMAINS]
            results = await asyncio.gather(*tasks)
            for url, status in results:
                if status and status < 400:
                    self.output(f"[+] Active subdomain: {url} (Status {status})")
                    self.results["subdomains"].append({"url": url, "status": status})

    async def scan_directories(self):
        self.output("\\n🔍 Checking directories...")
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_head(session, urljoin(self.base_url, d)) for d in self.COMMON_DIRS]
            results = await asyncio.gather(*tasks)
            for url, status in results:
                if status and status < 400:
                    self.output(f"[+] Found directory: {url} (Status {status})")
                    self.results["directories"].append({"url": url, "status": status})

    def scan_robots(self):
        self.output("\\n🔍 Fetching robots.txt...")
        try:
            r = requests.get(urljoin(self.base_url, "/robots.txt"), timeout=5)
            if r.status_code == 200:
                self.results["robots_txt"] = r.text.strip()
                self.output("[robots.txt] Found:")
                self.output(self.results["robots_txt"])
            else:
                self.output("[robots.txt] Not found.")
        except Exception:
            self.output("[robots.txt] Error fetching.")

    def scan_homepage(self):
        self.output("\\n🔍 Scraping homepage...")
        try:
            r = requests.get(self.base_url, timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')
            links = set(a['href'] for a in soup.find_all('a', href=True))
            self.results["links"] = list(links)
            self.output(f"[+] Found {len(links)} links:")
            for link in links:
                self.output(f"  - {link}")
        except:
            self.output("[-] Failed to scrape homepage.")

    def scan_whois(self):
        self.output("\\n🔍 WHOIS Info:")
        try:
            info = whois.whois(self.domain)
            self.results["whois"] = {
                "domain_name": str(info.domain_name),
                "registrar": info.registrar,
                "creation_date": str(info.creation_date),
                "expiration_date": str(info.expiration_date)
            }
            self.output(json.dumps(self.results["whois"], indent=2))
        except:
            self.output("[-] WHOIS lookup failed.")

    def scan_ip(self):
        self.output("\\n🔍 IP Lookup:")
        try:
            ip = socket.gethostbyname(self.domain)
            self.results["ip"] = ip
            self.output(f"[+] {self.domain} resolves to {ip}")
        except:
            self.output("[-] IP resolution failed.")

    def scan_ssl(self):
        self.output("\\n🔍 SSL Certificate Info:")
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(5.0)
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                self.results["ssl"] = {
                    "issuer": cert.get('issuer'),
                    "subject": cert.get('subject'),
                    "valid_from": cert.get('notBefore'),
                    "valid_until": cert.get('notAfter')
                }
                self.output(json.dumps(self.results["ssl"], indent=2))
        except:
            self.output("[-] SSL check failed.")

    def scan_security_headers(self):
        self.output("\\n🔍 Security Header Check:")
        try:
            r = requests.get(self.base_url, timeout=5)
            headers = r.headers
            self.results["headers"] = dict(headers)
            for h in self.SECURITY_HEADERS:
                if h not in headers:
                    self.output(f"[-] Missing: {h}")
                else:
                    self.output(f"[+] Found: {h}")
        except:
            self.output("[-] Failed to fetch headers.")

    def scan_cms(self):
        self.output("\\n🔍 CMS Detection:")
        try:
            r = requests.get(self.base_url, timeout=5).text
            if "wp-content" in r or "wp-login" in r:
                self.results["cms"] = "WordPress"
            elif "Joomla" in r:
                self.results["cms"] = "Joomla"
            elif "Drupal" in r:
                self.results["cms"] = "Drupal"
            else:
                self.results["cms"] = "Unknown"
            self.output(f"[+] Detected CMS: {self.results['cms']}")
        except:
            self.output("[-] CMS detection failed.")

    def scan_title(self):
        self.output("\\n🔍 Fetching page title...")
        try:
            r = requests.get(self.base_url, timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')
            title = soup.title.string.strip() if soup.title else "No title"
            self.results["titles"].append({"url": self.base_url, "title": title})
            self.output(f"[+] Page Title: {title}")
        except:
            self.output("[-] Title fetch failed.")

    def scan_broken_links(self):
        self.output("\\n🔍 Broken Link Detection:")
        try:
            r = requests.get(self.base_url, timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')
            broken = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urljoin(self.base_url, href)
                try:
                    res = requests.head(full_url, timeout=5)
                    if res.status_code >= 400:
                        self.output(f"[-] Broken link: {full_url} ({res.status_code})")
                        broken.append(full_url)
                except:
                    broken.append(full_url)
            self.results["broken_links"] = broken
        except:
            self.output("[-] Failed to check broken links.")

    def scan_directory_indexing(self):
        self.output("\\n🔍 Directory Indexing Check:")
        for d in self.COMMON_DIRS:
            url = urljoin(self.base_url, d + "/")
            try:
                r = requests.get(url, timeout=5)
                if re.search("Index of", r.text, re.IGNORECASE):
                    self.output(f"[!] Directory indexing enabled: {url}")
                    self.results["directory_indexing"].append(url)
            except:
                continue

    def run(self, selected):
        if selected["robots"]: self.scan_robots()
        if selected["scrape"]: self.scan_homepage()
        if selected["whois"]: self.scan_whois()
        if selected["ip"]: self.scan_ip()
        if selected["ssl"]: self.scan_ssl()
        if selected["sec_headers"]: self.scan_security_headers()
        if selected["cms"]: self.scan_cms()
        if selected["title"]: self.scan_title()
        if selected["broken"]: self.scan_broken_links()
        if selected["indexing"]: self.scan_directory_indexing()
        if selected["subdomains"]: asyncio.run(self.scan_subdomains())
        if selected["directories"]: asyncio.run(self.scan_directories())

    def export_results(self, fmt):
        fname = f"recon_results_{self.domain.replace('.', '_')}"
        if fmt == "json":
            with open(f"{fname}.json", "w") as f:
                json.dump(self.results, f, indent=2)
            self.output(f"\ Results saved to {fname}.json")
        elif fmt == "csv":
            with open(f"{fname}_summary.csv", "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Type", "Data"])
                writer.writerow(["IP", self.results["ip"]])
                writer.writerow(["robots.txt", self.results["robots_txt"]])
                writer.writerow(["CMS", self.results["cms"]])
                for item in self.results["whois"].items():
                    writer.writerow(["WHOIS - " + item[0], item[1]])
            self.output(f"\ Results saved to {fname}_summary.csv")
