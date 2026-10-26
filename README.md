# Recon

**Recon** is a small, menu-driven Python network and web reconnaissance utility intended for learning, authorized penetration testing, and security checks on systems you own or have explicit permission to assess.

> **Authorization notice:** Only scan systems, networks, and websites that you own or are explicitly authorized to test. Some checks generate network traffic, and packet capture may expose sensitive traffic on your own network. Follow applicable laws, engagement rules, and your organization's testing scope.

## Features in the current code

The current `soyie.py` menu offers the following checks:

1. TCP port scan with basic service/banner inspection (common ports or a user-entered list/range).
2. TCP port scan against an IP address.
3. Common web-path enumeration.
4. DNS resolution details and a traceroute/tracert attempt.
5. SSL/TLS certificate inspection attempt.
6. IP/ISP intelligence lookup through the external `ip-api.com` service.
7. Email-address and phone-like string extraction from a site's root page.
8. Checks for selected potentially exposed files and paths.
9. Checks for common database/admin-panel paths.
10. Basic server-header and CDN/WAF indicator inspection.
11. HTTP `OPTIONS` method check.
12. `robots.txt` and sitemap retrieval.
13. Lookup of a built-in list of common subdomains.
14. Login brute-forcer menu placeholder (not implemented as a working brute-force routine in this version).
15. A short Linux raw-socket packet capture (requires elevated privileges).
16. Directory/path fuzzing using a supplied wordlist.
17. Cookie attribute inspection.
18. DNS nameserver lookup and AXFR manual-test helper (prints a suggested `dig` command; it does not itself perform an AXFR transfer).

## Requirements

- Linux is recommended (Kali Linux, Debian, or Ubuntu).
- Python 3.
- `sudo` access for the launcher; raw packet capture requires suitable privileges.
- Optional system utilities: `traceroute` on Linux or `tracert` on Windows, and `nslookup` for the DNS helper. Install missing tools using your operating system's package manager.
- Internet access for checks that contact external services or remote targets.

The program currently imports only Python standard-library modules, so **no third-party Python packages are required**. `requirements.txt` is included for a consistent setup workflow and future dependencies.

## Installation (Kali Linux / Debian / Ubuntu)

### 1. Install system packages

```bash
sudo apt update
sudo apt install -y python3 python3-pip git
```

Optional utilities:

```bash
sudo apt install -y traceroute dnsutils
```

### 2. Get the repository

Replace `<YOUR-REPOSITORY-URL>` with the URL of your GitHub repository:

```bash
git clone <YOUR-REPOSITORY-URL>
cd <YOUR-REPOSITORY-DIRECTORY>
```

Alternatively, download the repository ZIP from GitHub, extract it, and open a terminal in the extracted directory.

### 3. Make the scripts executable

```bash
chmod +x install.sh start.sh
```

### 4. Install requirements

```bash
./install.sh
```

If your distribution blocks system-wide `pip` installs, that is expected on some modern Linux distributions. This project has no third-party Python dependencies, so you can simply use the system Python packages and proceed; do not force a system-wide pip installation.

### 5. Start SoyieSec

```bash
./start.sh
```

The launcher clears the terminal, displays a startup message, and starts the program using:

```bash
sudo python3 soyie.py
```

You can also launch it directly from the project directory:

```bash
sudo python3 soyie.py
```

## Usage

1. Start the program with `./start.sh`.
2. Select an item from the numbered menu.
3. Enter the target domain, URL, or IP address requested by the selected module.
4. Follow the prompts for ports, timeouts, or wordlists where applicable.
5. Choose whether to run another check when prompted.

Use a lab target such as a deliberately vulnerable local VM or a test server you administer. Start with a small port range and a reasonable timeout. Do not run broad scans against public targets without explicit authorization.

### Wordlist-based path checks

For menu item 16, provide the path to a plain-text wordlist containing one path per line. Blank lines and lines beginning with `#` are ignored. Use only a wordlist and target that are within your authorized scope.

### Packet capture

Menu item 15 captures up to 10 frames on Linux and requires elevated privileges. Captured traffic can contain sensitive information; use this only on systems and networks where you have permission to capture traffic.

## Important limitations to know

This README describes the code as it currently exists; it does not claim every menu item is a complete or production-grade security test.

- **Login brute-forcer:** the menu handler currently asks for a path, username, and wordlist, then prints a message. It does not implement login attempts.
- **SSL/TLS inspection:** the current implementation disables certificate verification before reading the certificate. As a result, certificate fields may be unavailable, and this should not be treated as a reliable certificate validation audit.
- **HTTP/HTTPS handling:** several web checks build `http://` URLs directly, so HTTPS-only sites may not be checked correctly.
- **CORS:** the current module checks the `OPTIONS` response's `Allow` header; it does not comprehensively test CORS policy.
- **DNS AXFR:** the module lists nameserver information and prints a manual `dig` command; it does not perform the transfer test itself.
- **Vulnerability checks:** the checks are limited path/exposure probes, not a comprehensive vulnerability scanner. A response status alone does not prove a vulnerability.
- **IP intelligence:** the lookup sends the requested IP to a third-party service (`ip-api.com`) and depends on that service being reachable.
- **Output:** results are printed to the terminal; this version does not provide a report-export workflow.

Treat results as preliminary indicators and verify findings manually. Do not rely on this tool alone for a security decision.

## Troubleshooting

### `Permission denied` when running a script

```bash
chmod +x install.sh start.sh
./start.sh
```

### `python3: command not found`

```bash
sudo apt update
sudo apt install -y python3
```

### `traceroute` or `nslookup` is missing

```bash
sudo apt install -y traceroute dnsutils
```

The related network-mapping or DNS helper may skip its optional step if a utility is unavailable.

### A target does not resolve

Check the domain spelling, DNS connectivity, VPN settings, and whether the target is reachable from your network. A DNS lookup failure does not necessarily mean the host is offline.

## Project files

```text
SoyieSec/
├── soyie.py          # Main menu-driven tool
├── requirements.txt  # Python dependency list (stdlib only at present)
├── install.sh        # Setup helper
├── start.sh           # Clears terminal and starts with sudo
└── README.md          # Documentation and installation guide
```
### Created By Soyie Azrael
## Disclaimer

SoyieSec is provided for education and authorized security testing. You are responsible for obtaining permission, respecting scope, protecting collected data, and complying with applicable laws. The author and contributors are not responsible for misuse or damage caused by this software.
