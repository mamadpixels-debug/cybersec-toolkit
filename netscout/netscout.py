#!/usr/bin/env python3
"""
███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██║   ██║   ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██║   ██║   ██║
██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝

NetScout v1.0 — Advanced Network Scanner & Vulnerability Mapper
Author: For educational/authorized use only
"""

import socket
import threading
import ipaddress
import subprocess
import platform
import json
import csv
import sys
import os
import time
import struct
import random
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ─────────────────────────────────────────────
# ANSI COLORS
# ─────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def color(text, *codes):
    return "".join(codes) + str(text) + C.RESET

# ─────────────────────────────────────────────
# KNOWN VULNERABILITY DATABASE (CVE snippets)
# ─────────────────────────────────────────────
VULN_DB = {
    21:  [{"id": "CVE-2010-4221", "desc": "ProFTPD 1.3.2rc3 - 1.3.3b remote code exec via TELNET IAC buffer overflow", "severity": "CRITICAL"}],
    22:  [{"id": "CVE-2023-38408", "desc": "OpenSSH < 9.3p2 remote code exec via ssh-agent forwarding", "severity": "CRITICAL"},
          {"id": "CVE-2018-15473",  "desc": "OpenSSH username enumeration (timing side-channel)", "severity": "MEDIUM"}],
    23:  [{"id": "CVE-2011-4862",  "desc": "Telnet daemon buffer overflow — plaintext auth risk", "severity": "HIGH"}],
    25:  [{"id": "CVE-2020-7247",  "desc": "OpenSMTPD < 6.6.2 remote root code execution", "severity": "CRITICAL"}],
    53:  [{"id": "CVE-2020-1350",  "desc": "Windows DNS Server SIGRed — heap overflow (CVSS 10.0)", "severity": "CRITICAL"}],
    80:  [{"id": "CVE-2021-41773", "desc": "Apache 2.4.49 path traversal & RCE", "severity": "CRITICAL"},
          {"id": "CVE-2022-31813", "desc": "Apache mod_proxy X-Forwarded-For bypass", "severity": "MEDIUM"}],
    110: [{"id": "CVE-2003-0989",  "desc": "Cyrus IMAP/POP3 buffer overflow via long string", "severity": "HIGH"}],
    135: [{"id": "CVE-2003-0352",  "desc": "MS03-026 DCOM RPC buffer overflow (Blaster worm)", "severity": "CRITICAL"}],
    139: [{"id": "CVE-2017-0143",  "desc": "EternalBlue — SMBv1 remote code exec (WannaCry)", "severity": "CRITICAL"}],
    143: [{"id": "CVE-2021-38647", "desc": "OMIGOD — OMID agent privilege escalation", "severity": "CRITICAL"}],
    443: [{"id": "CVE-2014-0160",  "desc": "Heartbleed — OpenSSL memory disclosure", "severity": "CRITICAL"},
          {"id": "CVE-2022-0778",  "desc": "OpenSSL infinite loop in BN_mod_sqrt()", "severity": "HIGH"}],
    445: [{"id": "CVE-2017-0144",  "desc": "EternalBlue SMB RCE — MS17-010", "severity": "CRITICAL"},
          {"id": "CVE-2021-36942", "desc": "PetitPotam — NTLM relay via EFS", "severity": "HIGH"}],
    1433:[{"id": "CVE-2020-0618",  "desc": "SQL Server Reporting Services remote code exec", "severity": "HIGH"}],
    3306:[{"id": "CVE-2012-2122",  "desc": "MySQL auth bypass via timing flaw", "severity": "HIGH"}],
    3389:[{"id": "CVE-2019-0708",  "desc": "BlueKeep — RDP pre-auth RCE (CVSS 9.8)", "severity": "CRITICAL"},
          {"id": "CVE-2020-0609",  "desc": "Windows RD Gateway RCE", "severity": "CRITICAL"}],
    5432:[{"id": "CVE-2019-9193",  "desc": "PostgreSQL COPY TO/FROM PROGRAM arbitrary code exec", "severity": "HIGH"}],
    6379:[{"id": "CVE-2022-0543",  "desc": "Redis Lua sandbox escape — remote code exec", "severity": "CRITICAL"}],
    8080:[{"id": "CVE-2021-44228", "desc": "Log4Shell — Apache Log4j JNDI injection (CVSS 10.0)", "severity": "CRITICAL"}],
    27017:[{"id": "CVE-2019-2389", "desc": "MongoDB no auth by default — data exposure risk", "severity": "HIGH"}],
}

# Common port names
PORT_NAMES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 111:"RPCbind", 135:"MS-RPC",
    139:"NetBIOS", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    993:"IMAPS", 995:"POP3S", 1433:"MSSQL", 1521:"Oracle",
    3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 5900:"VNC",
    6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
    9200:"Elasticsearch", 27017:"MongoDB",
}

# ─────────────────────────────────────────────
# BANNER GRABBER
# ─────────────────────────────────────────────
PROBES = {
    21:  b"",
    22:  b"",
    25:  b"EHLO netscout\r\n",
    80:  b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"",
    143: b"",
    3306:b"",
    6379:b"INFO\r\n",
}

def grab_banner(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            probe = PROBES.get(port, b"")
            if probe:
                s.sendall(probe)
            banner = s.recv(1024).decode(errors="replace").strip()
            return banner[:200] if banner else None
    except:
        return None

# ─────────────────────────────────────────────
# OS FINGERPRINT (TTL-based, ping)
# ─────────────────────────────────────────────
def ping_host(ip: str) -> tuple[bool, Optional[int]]:
    """Returns (alive, ttl)"""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3
        )
        output = result.stdout + result.stderr
        alive = result.returncode == 0
        ttl = None
        match = re.search(r"ttl[=\s](\d+)", output, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
        return alive, ttl
    except:
        return False, None

def guess_os(ttl: Optional[int]) -> str:
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux / Unix / Android"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Cisco / Network Device"
    return "Unknown"

# ─────────────────────────────────────────────
# PORT SCANNER
# ─────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except:
        return False

def scan_host(ip: str, ports: list[int], timeout: float = 1.0,
              threads: int = 100, grab: bool = True) -> dict:
    """Full scan of a single host."""
    result = {
        "ip": ip,
        "alive": False,
        "os_guess": "Unknown",
        "ttl": None,
        "open_ports": [],
        "scan_time": datetime.now().isoformat(),
    }

    alive, ttl = ping_host(ip)
    result["alive"] = alive
    result["ttl"] = ttl
    result["os_guess"] = guess_os(ttl)

    if not alive:
        # Try TCP probe anyway (ping may be blocked)
        pass

    open_ports = []
    lock = threading.Lock()

    def check(port):
        if scan_port(ip, port, timeout):
            with lock:
                open_ports.append(port)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        ex.map(check, ports)

    open_ports.sort()

    for port in open_ports:
        entry = {
            "port": port,
            "service": PORT_NAMES.get(port, "Unknown"),
            "banner": None,
            "vulns": VULN_DB.get(port, []),
        }
        if grab:
            entry["banner"] = grab_banner(ip, port)
        result["open_ports"].append(entry)

    if open_ports:
        result["alive"] = True

    return result

# ─────────────────────────────────────────────
# NETWORK SCANNER (CIDR range)
# ─────────────────────────────────────────────
def scan_network(cidr: str, ports: list[int], timeout: float = 1.0,
                 host_threads: int = 50, port_threads: int = 100) -> list[dict]:
    """Scan all IPs in a CIDR block."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(color(f"[!] Invalid network: {e}", C.RED))
        return []

    hosts = list(network.hosts())
    if len(hosts) > 1024:
        print(color(f"[!] Large range ({len(hosts)} hosts). This will take time...", C.YELLOW))

    print(color(f"[*] Scanning {len(hosts)} hosts in {cidr}", C.CYAN))
    results = []
    lock = threading.Lock()
    done = [0]

    def scan_one(ip):
        r = scan_host(str(ip), ports, timeout, port_threads, grab=True)
        with lock:
            done[0] += 1
            if r["open_ports"]:
                print(color(f"  ✓ {str(ip):15s}", C.GREEN) +
                      f" — {len(r['open_ports'])} open ports | OS: {r['os_guess']}")
            results.append(r)

    with ThreadPoolExecutor(max_workers=host_threads) as ex:
        futures = {ex.submit(scan_one, ip): ip for ip in hosts}
        for _ in as_completed(futures):
            pass

    return results

# ─────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────
def severity_color(s: str) -> str:
    m = {"CRITICAL": C.RED+C.BOLD, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.GREEN}
    return m.get(s, C.WHITE)

def print_report(results: list[dict]):
    total_vulns = 0
    print("\n" + "═"*65)
    print(color(" SCAN REPORT", C.BOLD + C.CYAN))
    print("═"*65)

    for r in results:
        if not r["open_ports"]:
            continue

        alive_str = color("ALIVE", C.GREEN) if r["alive"] else color("POSSIBLY ALIVE", C.YELLOW)
        print(f"\n{color(r['ip'], C.BOLD+C.WHITE)} [{alive_str}]")
        print(f"  OS Guess : {color(r['os_guess'], C.CYAN)}")
        print(f"  TTL      : {r['ttl'] or 'N/A'}")
        print(f"  Time     : {r['scan_time']}")
        print(f"  {'─'*55}")

        for p in r["open_ports"]:
            svc = p["service"]
            banner = p["banner"] or ""
            banner_short = (banner[:60] + "…") if len(banner) > 60 else banner
            banner_line = f"  {color('│', C.DIM)} Banner   : {color(banner_short, C.DIM)}" if banner else ""

            print(f"  {color('PORT', C.BOLD)} {color(str(p['port']).ljust(6), C.GREEN)} "
                  f"{color(svc, C.CYAN)}")
            if banner_line:
                print(banner_line)

            for v in p["vulns"]:
                total_vulns += 1
                sc = severity_color(v["severity"])
                print(f"  {color('│', C.DIM)} {color('⚠ ' + v['id'], sc)} "
                      f"{color('['+v['severity']+']', sc)}")
                print(f"  {color('│', C.DIM)}   {color(v['desc'], C.DIM)}")

    print("\n" + "═"*65)
    print(color(f" Total Vulnerabilities Found: {total_vulns}", C.RED+C.BOLD if total_vulns else C.GREEN+C.BOLD))
    print("═"*65 + "\n")

def save_json(results: list[dict], path: str):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(color(f"[+] JSON report saved: {path}", C.GREEN))

def save_csv(results: list[dict], path: str):
    rows = []
    for r in results:
        for p in r["open_ports"]:
            for v in p["vulns"]:
                rows.append({
                    "IP": r["ip"],
                    "OS": r["os_guess"],
                    "Port": p["port"],
                    "Service": p["service"],
                    "Banner": (p["banner"] or "")[:100],
                    "CVE": v["id"],
                    "Severity": v["severity"],
                    "Description": v["desc"],
                })
            if not p["vulns"]:
                rows.append({
                    "IP": r["ip"],
                    "OS": r["os_guess"],
                    "Port": p["port"],
                    "Service": p["service"],
                    "Banner": (p["banner"] or "")[:100],
                    "CVE": "", "Severity": "", "Description": "",
                })

    if not rows:
        print(color("[!] No data to write to CSV.", C.YELLOW))
        return

    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    print(color(f"[+] CSV report saved: {path}", C.GREEN))

# ─────────────────────────────────────────────
# PRESET PORT LISTS
# ─────────────────────────────────────────────
PORT_PRESETS = {
    "top20": [21,22,23,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5432,6379,8080,27017],
    "top100": [
        21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
        1025,1026,1027,1028,1029,1433,1521,1720,1723,3306,3389,
        5432,5900,6379,8080,8443,8888,9200,27017,
        # Fill to ~100 with common extras
        20,26,37,79,88,113,119,161,179,389,636,873,
        1080,1194,1443,2049,2082,2083,2222,2376,2377,
        4443,4848,5000,5001,5672,6000,6443,7001,7080,
        7443,8008,8081,8082,8161,8181,8888,9000,9090,
        9300,9418,10000,11211,15672,25565,27018,50000,
    ],
    "web": [80, 443, 8080, 8443, 8888, 3000, 4000, 5000, 9000],
    "db":  [1433, 1521, 3306, 5432, 6379, 9200, 27017, 5984, 7474],
    "smb": [135, 137, 138, 139, 445],
}

# ─────────────────────────────────────────────
# CLI / INTERACTIVE
# ─────────────────────────────────────────────
LOGO = f"""
{C.CYAN}{C.BOLD}
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██║   ██║   ██║   
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██║   ██║   ██║   
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝   ╚═╝   
{C.RESET}{C.DIM}  Network Scanner & Vulnerability Mapper v1.0
  [ For authorized and educational use only ]{C.RESET}
"""

MENU = f"""
{C.BOLD}  COMMANDS:{C.RESET}
  {C.GREEN}scan <ip>{C.RESET}             — scan single IP (top20 ports)
  {C.GREEN}scan <ip> -p <ports>{C.RESET}  — e.g. scan 192.168.1.1 -p 22,80,443
  {C.GREEN}scan <ip> -P top100{C.RESET}   — use preset (top20/top100/web/db/smb)
  {C.GREEN}net  <cidr>{C.RESET}           — scan network range e.g. 192.168.1.0/24
  {C.GREEN}net  <cidr> -P web{C.RESET}    — network scan with preset
  {C.GREEN}save json <file>{C.RESET}      — save last scan as JSON
  {C.GREEN}save csv  <file>{C.RESET}      — save last scan as CSV
  {C.GREEN}help{C.RESET}                  — show this menu
  {C.GREEN}exit{C.RESET}                  — quit
"""

def parse_ports(port_str: str) -> list[int]:
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ports.extend(range(int(a), int(b)+1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def interactive():
    print(LOGO)
    print(MENU)
    print(color("  ⚠  Only scan systems you own or have explicit permission to test.\n", C.YELLOW+C.BOLD))

    last_results = []

    while True:
        try:
            raw = input(color("netscout> ", C.CYAN + C.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print(color("\n[*] Exiting.", C.CYAN))
            break

        if not raw:
            continue

        parts = raw.split()
        cmd = parts[0].lower()

        # ── EXIT ──
        if cmd in ("exit", "quit", "q"):
            print(color("[*] Goodbye.", C.CYAN))
            break

        # ── HELP ──
        elif cmd == "help":
            print(MENU)

        # ── SINGLE HOST SCAN ──
        elif cmd == "scan" and len(parts) >= 2:
            ip = parts[1]
            ports = PORT_PRESETS["top20"]

            if "-p" in parts:
                idx = parts.index("-p")
                ports = parse_ports(parts[idx+1])
            elif "-P" in parts:
                idx = parts.index("-P")
                key = parts[idx+1].lower()
                ports = PORT_PRESETS.get(key, PORT_PRESETS["top20"])
                print(color(f"[*] Using preset '{key}' ({len(ports)} ports)", C.CYAN))

            print(color(f"\n[*] Scanning {ip} — {len(ports)} ports ...\n", C.CYAN))
            t0 = time.time()
            r = scan_host(ip, ports)
            elapsed = time.time() - t0
            last_results = [r]
            print_report([r])
            print(color(f"[*] Done in {elapsed:.1f}s\n", C.DIM))

        # ── NETWORK SCAN ──
        elif cmd == "net" and len(parts) >= 2:
            cidr = parts[1]
            ports = PORT_PRESETS["top20"]

            if "-P" in parts:
                idx = parts.index("-P")
                key = parts[idx+1].lower()
                ports = PORT_PRESETS.get(key, PORT_PRESETS["top20"])
                print(color(f"[*] Using preset '{key}' ({len(ports)} ports)", C.CYAN))

            confirm = input(color(f"[?] Scan {cidr} ({len(ports)} ports each)? [y/N] ", C.YELLOW)).strip().lower()
            if confirm != "y":
                print(color("[*] Cancelled.", C.DIM))
                continue

            t0 = time.time()
            results = scan_network(cidr, ports)
            elapsed = time.time() - t0
            last_results = results
            alive = [r for r in results if r["open_ports"]]
            print_report(alive)
            print(color(f"[*] Done in {elapsed:.1f}s — {len(alive)}/{len(results)} hosts had open ports\n", C.DIM))

        # ── SAVE ──
        elif cmd == "save" and len(parts) >= 3:
            fmt = parts[1].lower()
            path = parts[2]
            if not last_results:
                print(color("[!] No scan results to save.", C.YELLOW))
            elif fmt == "json":
                save_json(last_results, path)
            elif fmt == "csv":
                save_csv(last_results, path)
            else:
                print(color(f"[!] Unknown format '{fmt}'. Use json or csv.", C.RED))

        else:
            print(color(f"[!] Unknown command: '{raw}'. Type 'help' for usage.", C.RED))

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # Quick non-interactive mode: python netscout.py <ip> [ports]
    if len(sys.argv) >= 2 and sys.argv[1] not in ("--interactive", "-i"):
        ip = sys.argv[1]
        ports = PORT_PRESETS["top20"]
        if len(sys.argv) >= 3:
            try:
                ports = parse_ports(sys.argv[2])
            except:
                key = sys.argv[2].lower()
                ports = PORT_PRESETS.get(key, PORT_PRESETS["top20"])
        print(LOGO)
        print(color(f"[*] Quick scan: {ip} — {len(ports)} ports\n", C.CYAN))
        r = scan_host(ip, ports)
        print_report([r])
    else:
        interactive()
