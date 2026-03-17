#!/usr/bin/env python3
"""
██████╗ ███╗   ██╗███████╗    ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
██╔══██╗████╗  ██║██╔════╝    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
██║  ██║██╔██╗ ██║███████╗    ███████╗██║     ██║   ██║██║   ██║   ██║
██║  ██║██║╚██╗██║╚════██║    ╚════██║██║     ██║   ██║██║   ██║   ██║
██████╔╝██║ ╚████║███████║    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝   ╚═╝

DNSScout v1.0 — Advanced DNS Enumeration & Subdomain Finder
Pure stdlib — no pip needed.
For authorized/educational use only.
"""

import socket
import struct
import os
import sys
import time
import json
import csv
import random
import argparse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ─────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────
class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    BLUE="\033[94m"; MAGENTA="\033[95m"; CYAN="\033[96m"
    WHITE="\033[97m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

def c(text, *codes): return "".join(codes) + str(text) + C.RESET
def hr(ch="─", n=62): return ch * n

# ─────────────────────────────────────────────
# DNS RECORD TYPES
# ─────────────────────────────────────────────
DNS_TYPES = {
    "A":     1,
    "NS":    2,
    "CNAME": 5,
    "SOA":   6,
    "MX":    15,
    "TXT":   16,
    "AAAA":  28,
    "SRV":   33,
    "CAA":   257,
}

TYPE_NAMES = {v: k for k, v in DNS_TYPES.items()}

# ─────────────────────────────────────────────
# RAW DNS QUERY (pure stdlib, no dnspython)
# ─────────────────────────────────────────────
def build_dns_query(domain: str, qtype: int, txid: int = None) -> bytes:
    if txid is None:
        txid = random.randint(0, 65535)
    # Header
    flags = 0x0100  # Standard query, recursion desired
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    # Question
    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question

def parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse DNS name with pointer support."""
    labels = []
    visited = set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # Pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            name, _ = parse_name(data, pointer)
            labels.append(name)
            offset += 2
            return ".".join(labels), offset
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode(errors="replace"))
            offset += length
    return ".".join(labels), offset

def parse_dns_response(data: bytes) -> list[dict]:
    """Parse DNS response into list of records."""
    records = []
    try:
        txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
        rcode = flags & 0x0F
        if rcode != 0:
            return []

        offset = 12
        # Skip questions
        for _ in range(qdcount):
            _, offset = parse_name(data, offset)
            offset += 4  # type + class

        # Parse answers
        for _ in range(ancount + nscount + arcount):
            if offset >= len(data):
                break
            name, offset = parse_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            rdata = data[offset:offset+rdlength]
            offset += rdlength

            record = {
                "name": name,
                "type": TYPE_NAMES.get(rtype, str(rtype)),
                "ttl": ttl,
                "value": parse_rdata(rtype, rdata, data),
            }
            records.append(record)
    except Exception:
        pass
    return records

def parse_rdata(rtype: int, rdata: bytes, full: bytes) -> str:
    try:
        if rtype == 1:  # A
            return socket.inet_ntoa(rdata)
        elif rtype == 28:  # AAAA
            return socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (2, 5, 12):  # NS, CNAME, PTR
            name, _ = parse_name(full, len(full) - len(rdata))
            # Fallback: try parsing rdata directly
            try:
                n, _ = parse_name(rdata + full, 0)
                return n
            except:
                return rdata.decode(errors="replace")
        elif rtype == 15:  # MX
            pref = struct.unpack(">H", rdata[:2])[0]
            try:
                name, _ = parse_name(rdata + full, 2)
            except:
                name = rdata[2:].decode(errors="replace")
            return f"{pref} {name}"
        elif rtype == 16:  # TXT
            parts = []
            i = 0
            while i < len(rdata):
                l = rdata[i]; i += 1
                parts.append(rdata[i:i+l].decode(errors="replace"))
                i += l
            return " ".join(parts)
        elif rtype == 6:  # SOA
            try:
                mname, off = parse_name(rdata + full, 0)
                rname, off = parse_name(rdata + full, off)
                serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", rdata[off-len(rdata):off-len(rdata)+20])
                return f"mname={mname} rname={rname} serial={serial}"
            except:
                return rdata.decode(errors="replace")
        else:
            return rdata.hex()
    except:
        return "?"

def dns_query(domain: str, qtype_name: str = "A",
              server: str = "8.8.8.8", port: int = 53,
              timeout: float = 3.0) -> list[dict]:
    """Send DNS query and return parsed records."""
    qtype = DNS_TYPES.get(qtype_name.upper(), 1)
    query = build_dns_query(domain, qtype)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (server, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return parse_dns_response(data)
    except:
        return []

# ─────────────────────────────────────────────
# FALLBACK: socket-based resolution
# ─────────────────────────────────────────────
def resolve_simple(domain: str) -> list[str]:
    """Simple A record resolution using system resolver."""
    try:
        results = socket.getaddrinfo(domain, None)
        ips = list(set(r[4][0] for r in results))
        return ips
    except:
        return []

# ─────────────────────────────────────────────
# FULL DNS ENUMERATION
# ─────────────────────────────────────────────
DNS_SERVERS = {
    "Google":      "8.8.8.8",
    "Cloudflare":  "1.1.1.1",
    "OpenDNS":     "208.67.222.222",
}

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

def enumerate_domain(domain: str, server: str = "8.8.8.8") -> dict:
    """Full DNS record enumeration for a domain."""
    result = {
        "domain": domain,
        "server": server,
        "timestamp": datetime.now().isoformat(),
        "records": {},
        "ip_addresses": [],
        "mail_servers": [],
        "nameservers": [],
        "txt_records": [],
        "zone_transfer": None,
    }

    for rtype in RECORD_TYPES:
        records = dns_query(domain, rtype, server)
        if records:
            result["records"][rtype] = records

            if rtype == "A":
                result["ip_addresses"] = [r["value"] for r in records if r["type"] == "A"]
            elif rtype == "MX":
                result["mail_servers"] = [r["value"] for r in records if r["type"] == "MX"]
            elif rtype == "NS":
                result["nameservers"] = [r["value"] for r in records if r["type"] == "NS"]
            elif rtype == "TXT":
                result["txt_records"] = [r["value"] for r in records if r["type"] == "TXT"]

    # Fallback if raw DNS fails
    if not result["ip_addresses"]:
        result["ip_addresses"] = resolve_simple(domain)

    # Zone transfer attempt
    result["zone_transfer"] = attempt_zone_transfer(domain, result["nameservers"])

    return result

def attempt_zone_transfer(domain: str, nameservers: list[str]) -> Optional[dict]:
    """Attempt AXFR zone transfer (usually fails — but worth trying)."""
    for ns in nameservers[:3]:
        ns_clean = ns.rstrip(".")
        try:
            ns_ips = resolve_simple(ns_clean)
            if not ns_ips:
                continue
            ns_ip = ns_ips[0]

            # Build AXFR query
            qtype = 252  # AXFR
            query = build_dns_query(domain, qtype)
            # AXFR uses TCP
            length_prefix = struct.pack(">H", len(query))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((ns_ip, 53))
            sock.sendall(length_prefix + query)
            # Read response
            raw = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
            sock.close()

            if len(raw) > 2:
                return {
                    "ns": ns_clean,
                    "ns_ip": ns_ip,
                    "status": "SUCCESS — Zone transfer allowed!",
                    "size": len(raw),
                }
        except:
            pass
    return {"status": "REFUSED (expected — most servers block AXFR)"}

# ─────────────────────────────────────────────
# SUBDOMAIN BRUTE FORCE
# ─────────────────────────────────────────────

# Built-in wordlist (500 common subdomains)
SUBDOMAIN_WORDLIST = [
    "www","mail","ftp","localhost","webmail","smtp","pop","ns1","ns2","ns3",
    "ns4","webdisk","cpanel","whm","autodiscover","autoconfig","m","imap",
    "test","portal","ns","ww1","host","support","dev","web","bbs","wap",
    "forum","forums","smtp2","vpn","ftp2","admin","api","cdn","img","images",
    "static","assets","media","download","downloads","upload","uploads","blog",
    "shop","store","app","apps","mobile","beta","staging","stage","uat","qa",
    "sandbox","demo","preview","old","new","backup","bak","db","database",
    "mysql","sql","mongodb","redis","elasticsearch","kibana","grafana","jenkins",
    "jira","confluence","gitlab","github","bitbucket","git","svn","ci","cd",
    "build","deploy","monitor","monitoring","logs","log","syslog","status",
    "health","ping","alive","info","intranet","internal","private","corp",
    "corporate","office","remote","rdp","ssh","vpn2","proxy","firewall","fw",
    "router","gateway","mx","mx1","mx2","smtp1","relay","mail2","webmail2",
    "owa","exchange","lync","skype","teams","zoom","meet","video","stream",
    "live","tv","radio","music","media2","img2","images2","cdn2","assets2",
    "s3","storage","files","file","docs","doc","wiki","kb","help","helpdesk",
    "ticket","tickets","crm","erp","hr","finance","accounting","billing",
    "payment","payments","checkout","cart","order","orders","track","tracking",
    "report","reports","analytics","stats","statistics","metrics","dashboard",
    "panel","control","manage","manager","management","admin2","administrator",
    "root","system","sys","server","servers","host2","hosting","cloud","aws",
    "azure","gcp","heroku","digitalocean","linode","vultr","ovh","hetzner",
    "mx3","ns5","ns6","pop3","imap2","smtp3","mail3","mail4","email","e",
    "update","updates","patch","patches","release","releases","version","v",
    "v1","v2","v3","api2","api3","rest","graphql","grpc","soap","wsdl",
    "webhook","webhooks","callback","auth","authentication","login","signin",
    "signup","register","logout","signout","oauth","sso","saml","ldap","ad",
    "dc","dc1","dc2","pdc","bdc","exchange2","sharepoint","sp","onedrive",
    "teams2","slack","discord","chat","messaging","notification","notifications",
    "push","socket","ws","websocket","rtc","webrtc","turn","stun","coturn",
    "asterisk","sip","voip","pbx","fax","print","printer","printers","scan",
    "scanner","camera","cctv","nvr","dvr","iot","smart","device","devices",
    "sensor","sensors","hub","bridge","edge","fog","datacenter","dc3","rack",
    "switch","switches","ap","accesspoint","wifi","wireless","wlan","lan",
    "network","net","networking","it","helpdesk2","support2","service","services",
    "servicedesk","itsm","cmdb","asset","assets2","inventory","warehouse",
    "logistics","supply","chain","procurement","vendor","vendors","partner",
    "partners","affiliate","affiliates","reseller","resellers","customer",
    "customers","client","clients","user","users","member","members","account",
    "accounts","profile","profiles","avatar","avatars","photo","photos","image",
    "gallery","galleries","album","albums","video2","videos","audio","podcast",
    "feed","rss","atom","sitemap","robots","ads","advertising","adserver",
    "tracker","tracking2","pixel","beacon","analytics2","tag","tags","gtm",
    "segment","mixpanel","amplitude","hotjar","fullstory","logrocket","sentry",
    "bugsnag","rollbar","datadog","newrelic","splunk","elk","kibana2","grafana2",
    "prometheus","alertmanager","pagerduty","opsgenie","statuspage","uptime",
    "cronjob","worker","workers","queue","jobs","task","tasks","scheduler",
    "cron","batch","etl","pipeline","spark","kafka","rabbitmq","activemq",
    "redis2","memcached","varnish","haproxy","nginx","apache","tomcat","jboss",
    "wildfly","weblogic","websphere","glassfish","payara","jetty","undertow",
]

def brute_subdomain(domain: str, wordlist: list[str] = None,
                    threads: int = 50, timeout: float = 2.0,
                    server: str = "8.8.8.8") -> list[dict]:
    """Brute force subdomains."""
    if wordlist is None:
        wordlist = SUBDOMAIN_WORDLIST

    found = []
    lock = threading.Lock()
    done = [0]
    total = len(wordlist)

    def check(sub):
        fqdn = f"{sub}.{domain}"
        # Try raw DNS first
        records = dns_query(fqdn, "A", server, timeout=timeout)
        if not records:
            # Fallback to system resolver
            ips = resolve_simple(fqdn)
            if ips:
                records = [{"name": fqdn, "type": "A", "ttl": 0, "value": ip} for ip in ips]

        with lock:
            done[0] += 1
            if done[0] % 50 == 0:
                pct = done[0] / total * 100
                print(c(f"\r  [{done[0]}/{total}] {pct:.0f}% — found: {len(found)}", C.DIM), end="", flush=True)

        if records:
            ips = [r["value"] for r in records if r["type"] == "A"]
            if ips:
                entry = {"subdomain": fqdn, "ips": ips}
                with lock:
                    found.append(entry)
                    print(c(f"\n  ✓ {fqdn:45s} {', '.join(ips)}", C.GREEN))

    print(c(f"\n[*] Brute forcing {total} subdomains on {domain} ...", C.CYAN))

    with ThreadPoolExecutor(max_workers=threads) as ex:
        ex.map(check, wordlist)

    print()  # newline after progress
    return sorted(found, key=lambda x: x["subdomain"])

# ─────────────────────────────────────────────
# REVERSE DNS
# ─────────────────────────────────────────────
def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def reverse_dns_range(base: str, start: int = 1, end: int = 254) -> list[dict]:
    """Reverse DNS on an IP range."""
    results = []
    lock = threading.Lock()

    def check(i):
        ip = f"{base}.{i}"
        host = reverse_dns(ip)
        if host:
            with lock:
                results.append({"ip": ip, "hostname": host})
                print(c(f"  ✓ {ip:18s} → {host}", C.GREEN))

    print(c(f"\n[*] Reverse DNS scan: {base}.{start}-{end}", C.CYAN))
    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(check, range(start, end + 1))

    return sorted(results, key=lambda x: int(x["ip"].split(".")[-1]))

# ─────────────────────────────────────────────
# MULTI-SERVER COMPARISON
# ─────────────────────────────────────────────
def compare_dns_servers(domain: str, qtype: str = "A") -> dict:
    """Query same domain from multiple DNS servers and compare."""
    results = {}
    for name, server in DNS_SERVERS.items():
        records = dns_query(domain, qtype, server)
        results[name] = [r["value"] for r in records if r["type"] == qtype]
    return results

# ─────────────────────────────────────────────
# SPF / DMARC / DKIM CHECK
# ─────────────────────────────────────────────
def check_email_security(domain: str, server: str = "8.8.8.8") -> dict:
    """Check SPF, DMARC, DKIM records."""
    result = {"spf": None, "dmarc": None, "dkim": [], "mx": []}

    # SPF
    txt = dns_query(domain, "TXT", server)
    for r in txt:
        if "v=spf1" in r["value"].lower():
            result["spf"] = r["value"]

    # DMARC
    dmarc = dns_query(f"_dmarc.{domain}", "TXT", server)
    for r in dmarc:
        if "v=dmarc1" in r["value"].lower():
            result["dmarc"] = r["value"]

    # MX
    mx = dns_query(domain, "MX", server)
    result["mx"] = [r["value"] for r in mx if r["type"] == "MX"]

    # Common DKIM selectors
    for sel in ["default", "google", "mail", "k1", "selector1", "selector2", "dkim"]:
        dkim = dns_query(f"{sel}._domainkey.{domain}", "TXT", server)
        for r in dkim:
            if "v=dkim1" in r["value"].lower() or "p=" in r["value"].lower():
                result["dkim"].append({"selector": sel, "value": r["value"][:80]})

    return result

# ─────────────────────────────────────────────
# REPORT PRINTER
# ─────────────────────────────────────────────
def print_enum_report(r: dict):
    print(f"\n{c(hr('═'), C.CYAN)}")
    print(c(f"  DNS ENUMERATION — {r['domain']}", C.BOLD+C.CYAN))
    print(c(hr('═'), C.CYAN))
    print(f"  Server    : {r['server']}")
    print(f"  Time      : {r['timestamp']}")

    if r["ip_addresses"]:
        print(f"\n{c('  A Records (IPs)', C.BOLD)}")
        for ip in r["ip_addresses"]:
            print(f"  {c('→', C.GREEN)} {ip}")

    if r["nameservers"]:
        print(f"\n{c('  Nameservers (NS)', C.BOLD)}")
        for ns in r["nameservers"]:
            print(f"  {c('→', C.CYAN)} {ns}")

    if r["mail_servers"]:
        print(f"\n{c('  Mail Servers (MX)', C.BOLD)}")
        for mx in r["mail_servers"]:
            print(f"  {c('→', C.YELLOW)} {mx}")

    if r["txt_records"]:
        print(f"\n{c('  TXT Records', C.BOLD)}")
        for txt in r["txt_records"]:
            print(f"  {c('│', C.DIM)} {txt[:90]}")

    if r.get("records", {}).get("SOA"):
        print(f"\n{c('  SOA Record', C.BOLD)}")
        for s in r["records"]["SOA"]:
            print(f"  {c('│', C.DIM)} {s['value']}")

    if r["zone_transfer"]:
        zt = r["zone_transfer"]
        if "SUCCESS" in zt.get("status",""):
            print(f"\n{c('  ⚠ ZONE TRANSFER', C.RED+C.BOLD)}")
            print(f"  {c(zt['status'], C.RED)}")
            print(f"  NS: {zt.get('ns')} ({zt.get('ns_ip')})")
        else:
            print(f"\n  Zone Transfer: {c(zt.get('status',''), C.DIM)}")

    print()

def print_email_report(r: dict, domain: str):
    print(f"\n{c(hr('─'), C.CYAN)}")
    print(c(f"  EMAIL SECURITY — {domain}", C.BOLD+C.CYAN))
    print(c(hr('─'), C.CYAN))

    # SPF
    if r["spf"]:
        print(f"  {c('✓ SPF', C.GREEN)}    {r['spf'][:80]}")
    else:
        print(f"  {c('✗ SPF', C.RED)}    Not found — email spoofing possible!")

    # DMARC
    if r["dmarc"]:
        print(f"  {c('✓ DMARC', C.GREEN)}  {r['dmarc'][:80]}")
    else:
        print(f"  {c('✗ DMARC', C.RED)}  Not found — no email policy!")

    # DKIM
    if r["dkim"]:
        for d in r["dkim"]:
            print(f"  {c('✓ DKIM', C.GREEN)}   selector={d['selector']} {d['value'][:50]}")
    else:
        print(f"  {c('✗ DKIM', C.YELLOW)}  No common selectors found")

    # MX
    if r["mx"]:
        print(f"\n  {c('MX Servers:', C.BOLD)}")
        for mx in r["mx"]:
            print(f"  {c('→', C.CYAN)} {mx}")
    print()

def save_results(data: dict, path: str, fmt: str = "json"):
    if fmt == "json":
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(c(f"[+] Saved JSON: {path}", C.GREEN))
    elif fmt == "csv":
        rows = []
        domain = data.get("domain","")
        for rtype, records in data.get("records",{}).items():
            for r in records:
                rows.append({"domain": domain, "type": rtype,
                             "name": r["name"], "value": r["value"], "ttl": r["ttl"]})
        if rows:
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=rows[0].keys())
                w.writeheader(); w.writerows(rows)
            print(c(f"[+] Saved CSV: {path}", C.GREEN))

# ─────────────────────────────────────────────
# INTERACTIVE CLI
# ─────────────────────────────────────────────
LOGO = f"""
{C.CYAN}{C.BOLD}
  ██████╗ ███╗   ██╗███████╗    ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
  ██╔══██╗████╗  ██║██╔════╝    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
  ██║  ██║██╔██╗ ██║███████╗    ███████╗██║     ██║   ██║██║   ██║   ██║   
  ██║  ██║██║╚██╗██║╚════██║    ╚════██║██║     ██║   ██║██║   ██║   ██║   
  ██████╔╝██║ ╚████║███████║    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝   ╚═╝   
{C.RESET}{C.DIM}  DNS Enumeration & Subdomain Finder v1.0
  [ For authorized and educational use only ]{C.RESET}
"""

MENU = f"""
{C.BOLD}  ── ENUMERATION ─────────────────────────────────{C.RESET}
  {C.GREEN}enum <domain>{C.RESET}              full DNS record enumeration
  {C.GREEN}enum <domain> -s <server>{C.RESET}  use custom DNS server (default: 8.8.8.8)

{C.BOLD}  ── SUBDOMAIN DISCOVERY ──────────────────────────{C.RESET}
  {C.GREEN}brute <domain>{C.RESET}             brute force with built-in wordlist
  {C.GREEN}brute <domain> -w <file>{C.RESET}   use custom wordlist file
  {C.GREEN}brute <domain> -t <n>{C.RESET}      set thread count (default 50)

{C.BOLD}  ── QUERIES ──────────────────────────────────────{C.RESET}
  {C.GREEN}query <domain> <type>{C.RESET}      query specific record (A/MX/TXT/NS/...)
  {C.GREEN}compare <domain>{C.RESET}           compare A records across DNS servers
  {C.GREEN}reverse <ip>{C.RESET}               reverse DNS lookup
  {C.GREEN}reverse <base> <start> <end>{C.RESET} reverse DNS range (e.g. 192.168.1 1 50)

{C.BOLD}  ── EMAIL SECURITY ───────────────────────────────{C.RESET}
  {C.GREEN}email <domain>{C.RESET}             check SPF / DMARC / DKIM records

{C.BOLD}  ── OUTPUT ───────────────────────────────────────{C.RESET}
  {C.GREEN}save json <file>{C.RESET}           save last result as JSON
  {C.GREEN}save csv  <file>{C.RESET}           save last result as CSV

  {C.GREEN}help{C.RESET} / {C.GREEN}exit{C.RESET}
"""

def interactive():
    print(LOGO)
    print(MENU)
    print(c("  ⚠  Only enumerate domains you own or have permission to test.\n", C.YELLOW+C.BOLD))

    last_result = {}

    while True:
        try:
            raw = input(c("dnsscout> ", C.CYAN+C.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print(c("\n[*] Bye.", C.CYAN)); break

        if not raw: continue
        parts = raw.split()
        cmd = parts[0].lower()

        if cmd in ("exit","quit","q"):
            print(c("[*] Goodbye.", C.CYAN)); break

        elif cmd == "help":
            print(MENU)

        # ── ENUM ──
        elif cmd == "enum" and len(parts) >= 2:
            domain = parts[1].lower().strip()
            server = "8.8.8.8"
            if "-s" in parts:
                server = parts[parts.index("-s")+1]
            print(c(f"\n[*] Enumerating {domain} via {server} ...", C.CYAN))
            t0 = time.time()
            result = enumerate_domain(domain, server)
            last_result = result
            print_enum_report(result)
            # Also check email security
            email = check_email_security(domain, server)
            print_email_report(email, domain)
            print(c(f"[*] Done in {time.time()-t0:.1f}s", C.DIM))

        # ── BRUTE ──
        elif cmd == "brute" and len(parts) >= 2:
            domain = parts[1].lower().strip()
            wordlist = None
            threads = 50
            server = "8.8.8.8"

            if "-w" in parts:
                wfile = parts[parts.index("-w")+1]
                try:
                    with open(wfile) as f:
                        wordlist = [l.strip() for l in f if l.strip()]
                    print(c(f"[*] Loaded {len(wordlist)} words from {wfile}", C.CYAN))
                except:
                    print(c(f"[!] Cannot open wordlist: {wfile}", C.RED)); continue
            if "-t" in parts:
                threads = int(parts[parts.index("-t")+1])
            if "-s" in parts:
                server = parts[parts.index("-s")+1]

            t0 = time.time()
            found = brute_subdomain(domain, wordlist, threads, server=server)
            elapsed = time.time() - t0
            last_result = {"domain": domain, "subdomains": found}
            print(c(f"\n[*] Found {len(found)} subdomains in {elapsed:.1f}s", C.GREEN+C.BOLD))

        # ── QUERY ──
        elif cmd == "query" and len(parts) >= 3:
            domain = parts[1]
            qtype = parts[2].upper()
            server = parts[parts.index("-s")+1] if "-s" in parts else "8.8.8.8"
            records = dns_query(domain, qtype, server)
            if records:
                print(f"\n{c(f'  {qtype} records for {domain}', C.BOLD+C.CYAN)}")
                for r in records:
                    print(f"  {c(r['type'], C.GREEN):8s} {r['value']:50s} TTL={r['ttl']}")
            else:
                print(c(f"  No {qtype} records found for {domain}", C.YELLOW))
            print()

        # ── COMPARE ──
        elif cmd == "compare" and len(parts) >= 2:
            domain = parts[1]
            qtype = parts[2].upper() if len(parts) > 2 else "A"
            print(c(f"\n[*] Comparing {qtype} records for {domain} across servers...\n", C.CYAN))
            results = compare_dns_servers(domain, qtype)
            for srv_name, values in results.items():
                vals = ", ".join(values) if values else c("no response", C.DIM)
                print(f"  {c(srv_name+':',C.BOLD):16s} {vals}")
            print()

        # ── REVERSE ──
        elif cmd == "reverse" and len(parts) >= 2:
            if len(parts) == 4:
                base = parts[1]
                start = int(parts[2])
                end = int(parts[3])
                results = reverse_dns_range(base, start, end)
                last_result = {"type": "reverse", "results": results}
                print(c(f"\n[*] Found {len(results)} hostnames", C.GREEN))
            else:
                ip = parts[1]
                host = reverse_dns(ip)
                if host:
                    print(c(f"\n  {ip} → {host}\n", C.GREEN))
                else:
                    print(c(f"\n  No PTR record for {ip}\n", C.YELLOW))

        # ── EMAIL ──
        elif cmd == "email" and len(parts) >= 2:
            domain = parts[1]
            server = "8.8.8.8"
            email = check_email_security(domain, server)
            print_email_report(email, domain)
            last_result = {"domain": domain, "email_security": email}

        # ── SAVE ──
        elif cmd == "save" and len(parts) >= 3:
            fmt = parts[1].lower()
            path = parts[2]
            if not last_result:
                print(c("[!] No results to save.", C.YELLOW))
            else:
                save_results(last_result, path, fmt)

        else:
            print(c(f"[!] Unknown command. Type 'help'.", C.RED))

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] not in ("-i","--interactive"):
        domain = sys.argv[1]
        mode = sys.argv[2] if len(sys.argv) > 2 else "enum"
        print(LOGO)
        if mode == "brute":
            found = brute_subdomain(domain)
            print(c(f"\n[*] Found {len(found)} subdomains", C.GREEN+C.BOLD))
        else:
            result = enumerate_domain(domain)
            print_enum_report(result)
            email = check_email_security(domain)
            print_email_report(email, domain)
    else:
        interactive()
