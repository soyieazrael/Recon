import socket
import concurrent.futures
import subprocess
import platform
import os
import ssl
import random
import json
import re
import urllib.request
import urllib.error
from urllib.parse import urlparse, urlencode

# ---------- ascii art banner ----------

BANNER = r"""
 ███████╗ ██████╗ ██╗   ██╗██╗███████╗
 ██╔════╝██╔═══██╗╚██╗ ██╔╝██║██╔════╝
 ███████╗██║   ██║ ╚████╔╝ ██║█████╗  
 ╚════██║██║   ██║  ╚██╔╝  ██║██╔══╝  
 ███████║╚██████╔╝   ██║   ██║███████╗
 ╚══════╝ ╚═════╝    ╚═╝   ╚═╝╚══════╝
"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
]

COMMON_PATHS = [
    "admin", "login", "wp-admin/", "wp-login.php", "robots.txt", "sitemap.xml",
    ".git/", ".env", "config.php", "backup/", "uploads/", "api/", "dashboard",
    "test/", "dev/", "phpmyadmin/", "server-status", "readme.html", ".htaccess",
]

EXPANDED_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "staging", "vpn", "admin", "blog",
    "test", "shop", "store", "portal", "dashboard", "auth", "login", "cloud",
    "api-v1", "api-v2", "beta", "support", "status", "git", "jenkins"
]

SAFE_DOWNLOAD_PATHS = {"robots.txt", "sitemap.xml", "readme.html", ".htaccess"}


# ---------- shared helpers ----------

def resolve_target(user_input):
    user_input = user_input.strip()
    if "://" not in user_input:
        user_input = "http://" + user_input
    parsed = urlparse(user_input)
    host = parsed.hostname
    if not host:
        return None, None
    try:
        return host, socket.gethostbyname(host)
    except socket.gaierror:
        return host, None

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            except ValueError:
                continue
        elif part.isdigit():
            ports.add(int(part))
    return sorted(list(ports))


# ---------- modules 1 to 18 ----------

def grab_banner_and_version(ip, port, host, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = ""
            try:
                if port in (80, 443, 8080, 8443):
                    s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
                raw_data = s.recv(1024).decode("utf-8", errors="ignore")
                if "HTTP/" in raw_data:
                    lines = raw_data.splitlines()
                    banner = lines[0] if lines else raw_data.strip()
                else:
                    banner = raw_data.strip()
            except socket.timeout:
                pass
            return port, "open", banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, "closed", None

def run_port_scan(ip, host):
    port_input = input("Enter ports to scan (default: 21,22,25,80,443,445,8080 or range like 1-100): ").strip()
    ports = parse_ports(port_input) if port_input else [21, 22, 25, 80, 443, 445, 8080]
    try:
        timeout = float(input("Enter socket timeout in seconds (default: 2.0): ").strip() or 2.0)
    except ValueError:
        timeout = 2.0

    print(f"[*] Scanning {ip} across {len(ports)} port(s) with version detection...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(grab_banner_and_version, ip, p, host, timeout) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    for port, state, banner in sorted(results):
        if state == "open":
            version_info = "Version not explicitly parsed"
            if banner:
                match = re.search(r"(OpenSSH_\d+\.\d+|Apache/[\d\.]+|nginx/[\d\.]+|Pure-FTPd|Postfix)", banner, re.I)
                version_info = f"Identified Service/Version -> {match.group(0)}" if match else f"Banner -> {banner[:50].replace(chr(10), ' ')}"
            print(f"[+] Port {port:<5} OPEN | {version_info}")

def check_path(base_url, path):
    url = base_url.rstrip("/") + "/" + path
    try:
        req = urllib.request.Request(url, headers={"User-Agent": random.choice(USER_AGENTS)})
        with urllib.request.urlopen(req, timeout=4) as resp:
            return path, resp.status, resp.url, len(resp.read())
    except urllib.error.HTTPError as e:
        return path, e.code, e.url, 0
    except Exception:
        return path, None, None, 0

def run_dir_enum(host):
    base_url = f"http://{host}"
    print(f"[*] Enumerating common paths on {base_url} ...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_path, base_url, p) for p in COMMON_PATHS]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    for path, status, final_url, size in sorted(results, key=lambda x: x[0]):
        if status is None: continue
        redirect_info = f" -> Redirected to {final_url}" if final_url and not final_url.endswith(path) else ""
        tag = "+" if status in (200, 301, 302, 403) else "-"
        print(f"[{tag}] /{path:<20} | HTTP {status} | Size: {size} bytes{redirect_info}")

def run_network_map(host, ip):
    print(f"[*] DNS info for {host}")
    try:
        hostname, aliases, ips = socket.gethostbyname_ex(host)
        print(f"    Primary: {hostname} -> {', '.join(ips)}")
        if aliases: print(f"    Aliases: {', '.join(aliases)}")
    except socket.gaierror:
        print("    Could not resolve A records.")
    print(f"\n[*] Tracing route to {ip} ...")
    cmd = ["tracert", ip] if platform.system().lower() == "windows" else ["traceroute", ip]
    try:
        subprocess.run(cmd, timeout=30)
    except Exception:
        print("    Traceroute skipped or timed out.")

def run_ssl_and_headers_check(host):
    print(f"\n[--- SSL/TLS Certificate Inspection for {host}:443 ---]")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                print(f"    Subject CN: {subject.get('commonName', 'N/A')}")
                print(f"    Issuer Org: {issuer.get('organizationName', 'N/A')}")
                print(f"    Valid Until: {cert.get('notAfter')}")
    except Exception as e:
        print(f"    [-] SSL Inspection failed: {e}")

def run_ip_intelligence(ip):
    print(f"\n[--- IP Intelligence & ISP Lookup for {ip} ---]")
    try:
        url = f"http://ip-api.com/json/{ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                print(f"    ISP / Org : {data.get('isp', 'N/A')} ({data.get('org', 'N/A')})")
                print(f"    Location  : {data.get('city', 'N/A')}, {data.get('country', 'N/A')}")
                print(f"    AS Number : {data.get('as', 'N/A')}")
    except Exception as e:
        print(f"    [-] Error fetching IP intelligence: {e}")

def run_osint_harvest(host):
    print(f"\n[--- OSINT: Harvesting Emails & Phones from http://{host} ---]")
    base_url = f"http://{host}"
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": random.choice(USER_AGENTS)})
        with urllib.request.urlopen(req, timeout=5) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html))
            phones = set(re.findall(r"\+?[0-9][0-9(). -]{7,12}[0-9]", html))
            print(f"    [+] Emails Found ({len(emails)}): {', '.join(emails) if emails else '(None)'}")
            print(f"    [+] Phones Found ({len(phones)}): {', '.join([p.strip() for p in phones]) if phones else '(None)'}")
    except Exception as e:
        print(f"    [-] Failed to scrape OSINT data: {e}")

def run_vuln_check(host):
    print(f"\n[--- Web Vulnerability Scan for {host} ---]")
    for file in [".env", ".git/HEAD", "config.php.bak", "backup.zip", "info.php"]:
        try:
            req = urllib.request.Request(f"http://{host}/{file}", headers={"User-Agent": random.choice(USER_AGENTS)})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200: print(f"    [!] EXPOSURE FOUND: /{file} (HTTP 200)")
        except urllib.error.HTTPError as e:
            if e.code == 403: print(f"    [i] Protected: /{file} (HTTP 403)")
        except Exception: pass

def run_dbms_finder(host):
    print(f"\n[--- DBMS Fingerprinting for {host} ---]")
    base_url = f"http://{host}"
    detected = []
    for db, path in {"phpMyAdmin": "phpmyadmin/", "Adminer": "adminer.php", "Supabase API": "rest/v1/"}.items():
        try:
            req = urllib.request.Request(base_url.rstrip("/") + "/" + path, headers={"User-Agent": random.choice(USER_AGENTS)})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status in (200, 401, 403): detected.append(f"{db} (path: /{path})")
        except Exception: pass
    if detected:
        for d in detected: print(f"    [+] {d}")
    else:
        print("    [-] No explicit DBMS management panels identified.")

def run_tech_stack_detector(host):
    print(f"\n[--- Tech Stack & WAF Detection for {host} ---]")
    base_url = f"http://{host}"
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": random.choice(USER_AGENTS)})
        with urllib.request.urlopen(req, timeout=5) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            html = resp.read().decode("utf-8", errors="ignore").lower()
            print(f"    Server Software : {headers.get('server', 'Unknown')}")
            print(f"    Powered By      : {headers.get('x-powered-by', 'Not specified')}")
            waf = "None detected"
            if "cf-ray" in headers or "cloudflare" in headers.get("server", ""): waf = "Cloudflare CDN/WAF"
            elif "akamaighost" in headers.get("server", ""): waf = "Akamai CDN"
            print(f"    WAF / CDN       : {waf}")
    except Exception as e:
        print(f"    [-] Tech stack detection failed: {e}")

def run_cors_and_methods(host):
    print(f"\n[--- HTTP Methods & CORS Checker for {host} ---]")
    base_url = f"http://{host}"
    try:
        req = urllib.request.Request(base_url, method="OPTIONS", headers={"User-Agent": random.choice(USER_AGENTS)})
        with urllib.request.urlopen(req, timeout=4) as resp:
            print(f"    Allowed HTTP Methods: {resp.headers.get('Allow', 'Not provided')}")
    except Exception:
        print("    [-] OPTIONS check failed.")

def run_robots_parser(host):
    print(f"\n[--- Robots.txt & Sitemap Extractor for {host} ---]")
    for filename in ["robots.txt", "sitemap.xml"]:
        try:
            req = urllib.request.Request(f"http://{host}/{filename}", headers={"User-Agent": random.choice(USER_AGENTS)})
            with urllib.request.urlopen(req, timeout=4) as resp:
                print(f"\n    [+] Successfully fetched /{filename}:")
                for line in resp.read().decode("utf-8", errors="ignore").splitlines()[:10]:
                    print(f"        {line}")
        except Exception:
            print(f"    [-] /{filename} not found.")

def check_subdomain(domain, sub):
    fqdn = f"{sub}.{domain}"
    try:
        return fqdn, socket.gethostbyname(fqdn)
    except socket.gaierror:
        return fqdn, None

def run_subdomain_enum(host):
    print(f"\n[--- Subdomain Enumerator for {host} ---]")
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(check_subdomain, host, sub) for sub in EXPANDED_SUBDOMAINS]
        for future in concurrent.futures.as_completed(futures):
            fqdn, ip = future.result()
            if ip: print(f"    [+] Found: {fqdn:<30} -> {ip}")

def run_login_brute(host):
    print(f"\n[--- HTTP Login Form Brute-Forcer ---]")
    target_path = input("Enter login path (e.g. /login.php): ").strip()
    username = input("Enter target username: ").strip()
    wordlist = input("Enter wordlist file path: ").strip()
    if not os.path.exists(wordlist):
        print("[!] Wordlist not found.")
        return
    print(f"[*] Brute-forcing target {host}...")

def run_packet_sniffer():
    print(f"\n[--- Lightweight Raw Socket Packet Sniffer ---]")
    if platform.system().lower() != "linux":
        print("[!] AF_PACKET raw sniffing is supported on Linux.")
        return
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.settimeout(3.0)
        print("[*] Sniffing up to 10 packets... Press Ctrl+C to stop.")
        for _ in range(10):
            packet, addr = s.recvfrom(65565)
            print(f"    [+] Captured frame from '{addr[0]}' | Size: {len(packet)} bytes")
        s.close()
    except PermissionError:
        print("    [-] Permission Denied! Run with: sudo python3 soyie.py")
    except Exception as e:
        print(f"    [-] Sniffer error: {e}")

# ---------- NEW FEATURE 1 (Option 16): Custom Wordlist Fuzzer ----------

def run_custom_wordlist_fuzz(host):
    print(f"\n[--- Custom Wordlist Directory Fuzzer for {host} ---]")
    path = input("Enter path to wordlist file (e.g. wordlist.txt): ").strip()
    if not os.path.exists(path):
        print("[!] Wordlist file not found.")
        return
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"[*] Loaded {len(paths)} paths from wordlist. Fuzzing...")
        base_url = f"http://{host}"
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_path, base_url, p) for p in paths]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        for p, status, final_url, size in sorted(results, key=lambda x: x[0]):
            if status and status != 404:
                print(f"    [+] /{p:<25} -> HTTP {status} (Size: {size})")
    except Exception as e:
        print(f"[-] Fuzzing error: {e}")

# ---------- NEW FEATURE 2 (Option 17): Cookie Security Analyzer ----------

def run_cookie_analyzer(host):
    print(f"\n[--- Cookie & Session Security Analyzer for {host} ---]")
    base_url = f"http://{host}"
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": random.choice(USER_AGENTS)})
        with urllib.request.urlopen(req, timeout=5) as resp:
            cookies = resp.headers.get_all('Set-Cookie') if hasattr(resp.headers, 'get_all') else resp.headers.get('Set-Cookie')
            if not cookies:
                print("    [-] No cookies set on the root response.")
                return
            if isinstance(cookies, str):
                cookies = [cookies]
            print(f"    [+] Found {len(cookies)} cookie(s):")
            for cookie in cookies:
                print(f"        Cookie: {cookie}")
                c_lower = cookie.lower()
                print(f"          - HttpOnly : {'Present [Secure]' if 'httponly' in c_lower else 'MISSING [Vulnerable to XSS]'}")
                print(f"          - Secure   : {'Present [Secure]' if 'secure' in c_lower else 'MISSING [Sent over plain HTTP]'}")
                print(f"          - SameSite : {'Present' if 'samesite' in c_lower else 'MISSING [CSRF risk]'}")
    except Exception as e:
        print(f"    [-] Error analyzing cookies: {e}")

# ---------- NEW FEATURE 4 (Option 18): DNS Zone Transfer (AXFR) Checker ----------

def run_axfr_check(host):
    print(f"\n[--- DNS Zone Transfer (AXFR) Checker for {host} ---]")
    print("[*] Querying Nameservers (NS records)...")
    try:
        res = subprocess.run(["nslookup", "-type=ns", host], capture_output=True, text=True, timeout=10)
        print(res.stdout if res.stdout else "    [-] nslookup returned no output.")
        print("[*] To execute manual AXFR test via dig:")
        print(f"    dig @<nameserver_ip> {host} AXFR")
    except Exception as e:
        print(f"    [-] AXFR helper error: {e}")


# ---------- main menu (2-column layout) ----------

def main():
    print(BANNER)
    print("========================================================================")
    print("  SOYIE Penetration Framework v4.0 Created by: SOYIE AZRAEL")
    print("========================================================================")

    while True:
        print("\n========================================================================")
        print("  1) Port Scan & Version (URL)      |  10) Tech Stack & WAF Detector")
        print("  2) Port Scan by IP Address        |  11) HTTP Methods & CORS Checker")
        print("  3) Standard Directory Enum        |  12) Robots.txt & Sitemap Parser")
        print("  4) Network Mapping (DNS/Route)    |  13) Subdomain Enumerator")
        print("  5) SSL/TLS Certificate Audit      |  14) HTTP Login Brute-Forcer")
        print("  6) IP Intelligence & ISP Lookup   |  15) Lightweight Packet Sniffer")
        print("  7) OSINT: Harvest Emails/Phones   |  16) Custom Wordlist Fuzzer")
        print("  8) Web Vulnerability Scan         |  17) Cookie Security Analyzer")
        print("  9) DBMS Fingerprinting            |  18) DNS Zone Transfer (AXFR)")
        print("========================================================================")
        choice = input("Enter choice (1-18): ").strip()

        if choice in ("1", "3", "4", "5", "7", "8", "9", "10", "11", "12", "13", "14", "16", "17", "18"):
            target_input = input("Enter target web URL or domain: ")
            host, ip = resolve_target(target_input)
            if not ip:
                print("[!] Could not resolve target IP.")
                continue
            print(f"[*] Target resolved: {host} -> {ip}")
            
            if choice == "1": run_port_scan(ip, host)
            elif choice == "3": run_dir_enum(host)
            elif choice == "4": run_network_map(host, ip)
            elif choice == "5": run_ssl_and_headers_check(host)
            elif choice == "7": run_osint_harvest(host)
            elif choice == "8": run_vuln_check(host)
            elif choice == "9": run_dbms_finder(host)
            elif choice == "10": run_tech_stack_detector(host)
            elif choice == "11": run_cors_and_methods(host)
            elif choice == "12": run_robots_parser(host)
            elif choice == "13": run_subdomain_enum(host)
            elif choice == "14": run_login_brute(host)
            elif choice == "16": run_custom_wordlist_fuzz(host)
            elif choice == "17": run_cookie_analyzer(host)
            elif choice == "18": run_axfr_check(host)

        elif choice == "2":
            ip = input("Enter target IP: ").strip()
            try:
                socket.inet_aton(ip)
                run_port_scan(ip, ip)
            except OSError: print("[!] Invalid IP address.")

        elif choice == "6":
            ip = input("Enter target IP address: ").strip()
            run_ip_intelligence(ip)

        elif choice == "15":
            run_packet_sniffer()

        else:
            print("[!] Invalid choice. Please select 1-18.")

        if input("\nDo you want to run another check? (y/n): ").strip().lower() not in ("y", "yes"):
            print("[*] Exiting soyie framework. Stay safe in your lab!")
            break

if __name__ == "__main__":
    main()
