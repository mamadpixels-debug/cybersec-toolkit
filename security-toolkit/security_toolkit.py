#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║        SECURITY TOOLKIT v1.0                         ║
║  • Log Analyzer    • Password Analyzer               ║
║  • Secure Password Generator                         ║
╚═══════════════════════════════════════════════════════╝
Pure stdlib — no pip installs needed.
"""

import re, os, sys, math, json, string, secrets, hashlib
import gzip, bz2, argparse
from datetime import datetime
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────
class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    BLUE="\033[94m"; MAGENTA="\033[95m"; CYAN="\033[96m"
    WHITE="\033[97m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

def c(text,*codes): return "".join(codes)+str(text)+C.RESET
def hr(ch="─",n=60): return ch*n

# ─────────────────────────────────────────────────────────────
#  MODULE 1 — LOG ANALYZER
# ─────────────────────────────────────────────────────────────

# ── Regex patterns ──
PATTERNS = {
    "apache_combined": re.compile(
        r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    ),
    "nginx": re.compile(
        r'(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)'
    ),
    "ssh_failed": re.compile(
        r'(?P<time>\w+\s+\d+\s+[\d:]+).*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)'
    ),
    "ssh_accepted": re.compile(
        r'(?P<time>\w+\s+\d+\s+[\d:]+).*Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.]+)'
    ),
    "ssh_invalid": re.compile(
        r'(?P<time>\w+\s+\d+\s+[\d:]+).*Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)'
    ),
    "sudo": re.compile(
        r'(?P<time>\w+\s+\d+\s+[\d:]+).*sudo.*USER=(?P<user>\S+).*COMMAND=(?P<cmd>.+)'
    ),
    "syslog_error": re.compile(
        r'(?P<time>\w+\s+\d+\s+[\d:]+)\s+\S+\s+(?P<proc>[^:]+):\s+(?P<msg>.+)'
    ),
}

# Suspicious path patterns (web attacks)
SUSPICIOUS_PATHS = [
    (re.compile(r'\.\./'), "Path Traversal"),
    (re.compile(r'(etc/passwd|etc/shadow|proc/self)', re.I), "File Inclusion"),
    (re.compile(r'(select|union|insert|drop|update|delete)\s', re.I), "SQL Injection"),
    (re.compile(r'<script|javascript:|onerror=|onload=', re.I), "XSS Attempt"),
    (re.compile(r'(cmd=|exec=|system\(|passthru|shell_exec)', re.I), "RCE Attempt"),
    (re.compile(r'(wp-admin|wp-login|phpMyAdmin|phpmyadmin|\.env|config\.php)', re.I), "CMS/Config Probe"),
    (re.compile(r'(\.git|\.svn|\.htaccess|web\.config)', re.I), "Sensitive File Probe"),
    (re.compile(r'(nikto|sqlmap|nmap|masscan|zgrab)', re.I), "Scanner UA"),
]

def open_log(path: str):
    """Open plain, .gz, or .bz2 log files."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    elif path.endswith(".bz2"):
        return bz2.open(path, "rt", errors="replace")
    else:
        return open(path, "r", errors="replace")

def detect_log_type(lines: list[str]) -> str:
    sample = "\n".join(lines[:20])
    if PATTERNS["ssh_failed"].search(sample) or "sshd" in sample:
        return "ssh"
    if PATTERNS["apache_combined"].search(sample):
        return "apache"
    if "sudo" in sample and "COMMAND" in sample:
        return "sudo"
    return "syslog"

def analyze_web_log(lines: list[str], log_type: str) -> dict:
    pat = PATTERNS[log_type]
    stats = {
        "total": 0, "errors_4xx": 0, "errors_5xx": 0,
        "top_ips": Counter(), "top_paths": Counter(),
        "status_codes": Counter(), "methods": Counter(),
        "suspicious": [], "bytes_total": 0,
        "top_ua": Counter(),
    }
    for line in lines:
        m = pat.match(line)
        if not m: continue
        d = m.groupdict()
        stats["total"] += 1
        status = int(d.get("status", 0))
        stats["status_codes"][status] += 1
        if 400 <= status < 500: stats["errors_4xx"] += 1
        if 500 <= status < 600: stats["errors_5xx"] += 1
        ip = d.get("ip","")
        path = d.get("path","")
        method = d.get("method","")
        ua = d.get("ua","")
        stats["top_ips"][ip] += 1
        stats["top_paths"][path] += 1
        stats["methods"][method] += 1
        if ua: stats["top_ua"][ua] += 1
        try:
            size = int(d.get("size","0"))
            stats["bytes_total"] += size
        except: pass
        # Check suspicious
        for regex, label in SUSPICIOUS_PATHS:
            if regex.search(path) or regex.search(ua or ""):
                stats["suspicious"].append({
                    "ip": ip, "path": path[:120],
                    "label": label, "status": status
                })
                break
    return stats

def analyze_ssh_log(lines: list[str]) -> dict:
    stats = {
        "failed_attempts": Counter(),   # ip -> count
        "failed_users": Counter(),
        "accepted": [],
        "invalid_users": Counter(),
        "brute_force_suspects": [],
    }
    for line in lines:
        mf = PATTERNS["ssh_failed"].search(line)
        if mf:
            d = mf.groupdict()
            stats["failed_attempts"][d["ip"]] += 1
            stats["failed_users"][d.get("user","?")] += 1
            continue
        ma = PATTERNS["ssh_accepted"].search(line)
        if ma:
            d = ma.groupdict()
            stats["accepted"].append({"ip": d["ip"], "user": d["user"], "method": d.get("method","")})
            continue
        mi = PATTERNS["ssh_invalid"].search(line)
        if mi:
            d = mi.groupdict()
            stats["invalid_users"][d["user"]] += 1

    # Brute force: >20 failed from same IP
    for ip, count in stats["failed_attempts"].items():
        if count >= 20:
            stats["brute_force_suspects"].append({"ip": ip, "attempts": count})
    stats["brute_force_suspects"].sort(key=lambda x: -x["attempts"])
    return stats

def print_web_report(stats: dict, path: str):
    print(f"\n{c(hr('═'), C.CYAN)}")
    print(c(f"  WEB LOG ANALYSIS — {path}", C.BOLD+C.CYAN))
    print(c(hr('═'), C.CYAN))
    print(f"  Total Requests : {c(stats['total'], C.WHITE+C.BOLD)}")
    print(f"  4xx Errors     : {c(stats['errors_4xx'], C.YELLOW)}")
    print(f"  5xx Errors     : {c(stats['errors_5xx'], C.RED)}")
    print(f"  Data Served    : {c(format_bytes(stats['bytes_total']), C.GREEN)}")

    print(f"\n{c('  TOP IPs', C.BOLD)}")
    for ip, cnt in stats["top_ips"].most_common(10):
        bar = "█" * min(cnt // max(1, stats['total'] // 40), 30)
        print(f"  {ip:20s} {c(str(cnt).rjust(6), C.CYAN)} {c(bar, C.BLUE)}")

    print(f"\n{c('  STATUS CODES', C.BOLD)}")
    for code, cnt in sorted(stats["status_codes"].items()):
        col = C.GREEN if code < 300 else (C.YELLOW if code < 500 else C.RED)
        print(f"  {c(code, col)}  {cnt}")

    print(f"\n{c('  TOP PATHS', C.BOLD)}")
    for path_, cnt in stats["top_paths"].most_common(10):
        print(f"  {str(cnt).rjust(6)} {c(path_[:70], C.DIM)}")

    if stats["suspicious"]:
        print(f"\n{c('  ⚠  SUSPICIOUS REQUESTS', C.RED+C.BOLD)} ({len(stats['suspicious'])} found)")
        seen = set()
        for s in stats["suspicious"][:20]:
            key = (s["ip"], s["label"])
            if key in seen: continue
            seen.add(key)
            print(f"  {c(s['label'], C.RED):30s} from {c(s['ip'], C.YELLOW)}  {c(s['path'][:60], C.DIM)}")
    else:
        print(f"\n{c('  ✓  No suspicious patterns detected.', C.GREEN)}")

def print_ssh_report(stats: dict, path: str):
    print(f"\n{c(hr('═'), C.CYAN)}")
    print(c(f"  SSH LOG ANALYSIS — {path}", C.BOLD+C.CYAN))
    print(c(hr('═'), C.CYAN))
    total_failed = sum(stats["failed_attempts"].values())
    print(f"  Failed Logins  : {c(total_failed, C.RED+C.BOLD)}")
    print(f"  Unique Attackers: {c(len(stats['failed_attempts']), C.YELLOW)}")
    print(f"  Successful Logins: {c(len(stats['accepted']), C.GREEN)}")

    if stats["brute_force_suspects"]:
        print(f"\n{c('  🔴 BRUTE FORCE SUSPECTS', C.RED+C.BOLD)}")
        for s in stats["brute_force_suspects"][:15]:
            bar = "█" * min(s["attempts"] // 10, 30)
            print(f"  {s['ip']:20s} {c(str(s['attempts']).rjust(5)+' attempts', C.RED)} {c(bar, C.RED)}")

    if stats["failed_users"]:
        print(f"\n{c('  TOP TARGETED USERNAMES', C.BOLD)}")
        for user, cnt in stats["failed_users"].most_common(10):
            print(f"  {str(cnt).rjust(5)} {c(user, C.YELLOW)}")

    if stats["accepted"]:
        print(f"\n{c('  ✓ SUCCESSFUL LOGINS', C.GREEN+C.BOLD)}")
        for a in stats["accepted"][-10:]:
            print(f"  {c(a['user'], C.GREEN):20s} from {c(a['ip'], C.CYAN)}  [{a['method']}]")

def format_bytes(n: int) -> str:
    for unit in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def run_log_analyzer(log_path: str):
    if not os.path.exists(log_path):
        print(c(f"[!] File not found: {log_path}", C.RED)); return
    print(c(f"[*] Reading {log_path} ...", C.CYAN))
    with open_log(log_path) as f:
        lines = f.readlines()
    print(c(f"[*] {len(lines):,} lines loaded.", C.DIM))
    log_type = detect_log_type(lines)
    print(c(f"[*] Detected log type: {log_type}", C.CYAN))

    if log_type == "ssh":
        stats = analyze_ssh_log(lines)
        print_ssh_report(stats, log_path)
    elif log_type in ("apache","nginx"):
        stats = analyze_web_log(lines, log_type)
        print_web_report(stats, log_path)
    else:
        # Generic syslog: count ERRORs/WARNings
        errors   = [l for l in lines if "error" in l.lower()]
        warnings = [l for l in lines if "warn" in l.lower()]
        print(f"\n  Total lines : {len(lines):,}")
        print(f"  Errors      : {c(len(errors), C.RED)}")
        print(f"  Warnings    : {c(len(warnings), C.YELLOW)}")
        print(f"\n{c('  Recent Errors:', C.BOLD)}")
        for l in errors[-10:]:
            print(f"  {c(l.strip()[:100], C.DIM)}")

# ─────────────────────────────────────────────────────────────
#  MODULE 2 — PASSWORD STRENGTH ANALYZER
# ─────────────────────────────────────────────────────────────

# Common weak passwords (top 50 mini list)
COMMON_PASSWORDS = {
    "password","123456","12345678","qwerty","abc123","monkey","1234567",
    "letmein","trustno1","dragon","baseball","iloveyou","master","sunshine",
    "ashley","bailey","passw0rd","shadow","123123","654321","superman",
    "qazwsx","michael","football","password1","password123","admin","admin123",
    "root","toor","pass","test","guest","login","welcome","hello","qwerty123",
    "iloveyou1","princess","dragon1","password2","12345","1234","111111",
    "000000","123321","666666","121212","112233",
}

KEYBOARD_WALKS = [
    "qwerty","qwertyuiop","asdfgh","asdfghjkl","zxcvbn","zxcvbnm",
    "1234567890","0987654321","qweasdzxc","!@#$%^&*()",
]

def password_entropy(pw: str) -> float:
    charset = 0
    if re.search(r'[a-z]', pw): charset += 26
    if re.search(r'[A-Z]', pw): charset += 26
    if re.search(r'\d', pw):    charset += 10
    if re.search(r'[^a-zA-Z0-9]', pw): charset += 32
    if charset == 0: return 0
    return len(pw) * math.log2(charset)

def crack_time_str(entropy: float) -> str:
    """Estimate time to brute-force at 1 billion guesses/sec."""
    guesses = 2 ** entropy
    seconds = guesses / 1e9
    if seconds < 1:      return c("< 1 second", C.RED+C.BOLD)
    if seconds < 60:     return c(f"{seconds:.0f} seconds", C.RED+C.BOLD)
    if seconds < 3600:   return c(f"{seconds/60:.0f} minutes", C.RED)
    if seconds < 86400:  return c(f"{seconds/3600:.0f} hours", C.YELLOW)
    if seconds < 2592000:return c(f"{seconds/86400:.0f} days", C.YELLOW)
    if seconds < 31536000:return c(f"{seconds/2592000:.0f} months", C.GREEN)
    years = seconds / 31536000
    if years < 1000:     return c(f"{years:.0f} years", C.GREEN)
    return c(f"{years:.2e} years", C.GREEN+C.BOLD)

def analyze_password(pw: str) -> dict:
    issues = []
    score = 0

    # Length
    length = len(pw)
    if length < 8:   issues.append(("FAIL", "Too short (< 8 chars)"))
    elif length < 12: issues.append(("WARN", "Short (< 12 chars recommended)"))
    else: score += 2

    # Character classes
    has_lower  = bool(re.search(r'[a-z]', pw))
    has_upper  = bool(re.search(r'[A-Z]', pw))
    has_digit  = bool(re.search(r'\d', pw))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', pw))
    classes = sum([has_lower, has_upper, has_digit, has_symbol])
    if not has_lower:  issues.append(("WARN", "No lowercase letters"))
    if not has_upper:  issues.append(("WARN", "No uppercase letters"))
    if not has_digit:  issues.append(("WARN", "No digits"))
    if not has_symbol: issues.append(("WARN", "No special characters"))
    score += classes

    # Common password check
    if pw.lower() in COMMON_PASSWORDS:
        issues.append(("FAIL", "This is one of the most common passwords!"))
        score = max(0, score - 5)

    # Keyboard walk
    for walk in KEYBOARD_WALKS:
        if walk in pw.lower():
            issues.append(("WARN", f"Keyboard pattern detected: '{walk}'"))
            score -= 1
            break

    # Repeated chars
    if re.search(r'(.)\1{2,}', pw):
        issues.append(("WARN", "Repeated characters (aaa, 111...)"))
        score -= 1

    # Sequential
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|xyz)', pw.lower()):
        issues.append(("WARN", "Sequential pattern detected"))
        score -= 1

    # Leet speak
    leet_map = str.maketrans("@31!0$","a3li0s")
    if pw.translate(leet_map).lower() in COMMON_PASSWORDS:
        issues.append(("WARN", "Common password with leet-speak substitution"))

    # Entropy
    entropy = password_entropy(pw)
    score += int(entropy / 20)

    # Score → grade
    score = max(0, min(score, 10))
    if score <= 2:   grade, grade_c = "VERY WEAK", C.RED+C.BOLD
    elif score <= 4: grade, grade_c = "WEAK",      C.RED
    elif score <= 6: grade, grade_c = "MODERATE",  C.YELLOW
    elif score <= 8: grade, grade_c = "STRONG",    C.GREEN
    else:            grade, grade_c = "VERY STRONG",C.GREEN+C.BOLD

    return {
        "password": pw,
        "length": length,
        "classes": classes,
        "entropy": entropy,
        "score": score,
        "grade": grade,
        "grade_color": grade_c,
        "issues": issues,
        "crack_time": crack_time_str(entropy),
    }

def print_password_report(r: dict):
    print(f"\n{c(hr('═'), C.CYAN)}")
    print(c("  PASSWORD ANALYSIS", C.BOLD+C.CYAN))
    print(c(hr('═'), C.CYAN))

    # Mask password (show first 2 + last 1)
    pw = r["password"]
    masked = pw[:2] + "*"*(len(pw)-3) + pw[-1] if len(pw)>3 else "***"
    print(f"  Password  : {c(masked, C.WHITE)}")
    print(f"  Length    : {r['length']} chars")
    print(f"  Entropy   : {r['entropy']:.1f} bits")
    print(f"  Char Types: {r['classes']}/4")
    print(f"  Grade     : {c(r['grade'], r['grade_color'])}")
    print(f"  Crack Time: {r['crack_time']}  (at 10⁹ guesses/sec)")

    # Visual strength bar
    filled = int(r["score"])
    bar = "█" * filled + "░" * (10 - filled)
    col = r["grade_color"]
    print(f"\n  Strength  : [{c(bar, col)}] {r['score']}/10")

    if r["issues"]:
        print(f"\n{c('  Issues:', C.BOLD)}")
        for level, msg in r["issues"]:
            icon = c("✗", C.RED) if level == "FAIL" else c("⚠", C.YELLOW)
            print(f"  {icon}  {msg}")
    else:
        print(f"\n  {c('✓ No issues found!', C.GREEN)}")

    print()

# ─────────────────────────────────────────────────────────────
#  MODULE 3 — SECURE PASSWORD GENERATOR
# ─────────────────────────────────────────────────────────────

WORD_LIST = [
    "apple","bridge","castle","dragon","eagle","forest","galaxy","harbor",
    "island","jungle","knight","lemon","marble","noble","ocean","planet",
    "quest","river","storm","tower","ultra","valley","winter","xenon",
    "yellow","zephyr","amber","bronze","copper","desert","ember","flame",
    "granite","horizon","ivory","jasper","krypton","lava","meteor","nexus",
    "orbit","prism","quartz","radar","silver","titan","umbra","vortex",
    "walnut","xerus","yacht","zenith","azure","blaze","cedar","dune",
    "eclipse","frost","gust","haven","iris","jade","karma","lunar",
    "moss","nova","onyx","pearl","quill","raven","sage","thorn",
]

def gen_random(length=16, use_upper=True, use_digits=True, use_symbols=True,
               exclude_ambiguous=False) -> str:
    chars = string.ascii_lowercase
    required = [secrets.choice(string.ascii_lowercase)]
    if use_upper:
        pool = string.ascii_uppercase
        if exclude_ambiguous: pool = pool.translate(str.maketrans("","","IO"))
        chars += pool
        required.append(secrets.choice(pool))
    if use_digits:
        pool = string.digits
        if exclude_ambiguous: pool = pool.translate(str.maketrans("","","01"))
        chars += pool
        required.append(secrets.choice(pool))
    if use_symbols:
        pool = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        chars += pool
        required.append(secrets.choice(pool))
    if exclude_ambiguous:
        chars = chars.translate(str.maketrans("","","Il1O0o"))

    remaining = length - len(required)
    pw_list = required + [secrets.choice(chars) for _ in range(remaining)]
    secrets.SystemRandom().shuffle(pw_list)
    return "".join(pw_list)

def gen_passphrase(words=4, separator="-", capitalize=True, add_number=True) -> str:
    chosen = [secrets.choice(WORD_LIST) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    if add_number:
        phrase += separator + str(secrets.randbelow(9000) + 1000)
    return phrase

def gen_pin(length=6) -> str:
    return "".join([str(secrets.randbelow(10)) for _ in range(length)])

def gen_hex_key(bits=256) -> str:
    return secrets.token_hex(bits // 8)

def gen_pronounceable(length=12) -> str:
    consonants = "bcdfghjklmnprstvwxyz"
    vowels = "aeiou"
    result = []
    for i in range(length):
        if i % 2 == 0:
            result.append(secrets.choice(consonants))
        else:
            result.append(secrets.choice(vowels))
    # Capitalize first, add number at end
    result[0] = result[0].upper()
    pw = "".join(result) + str(secrets.randbelow(90) + 10)
    return pw

def print_generated(passwords: list[tuple[str, str]]):
    print(f"\n{c(hr('═'), C.CYAN)}")
    print(c("  GENERATED PASSWORDS", C.BOLD+C.CYAN))
    print(c(hr('═'), C.CYAN))
    for label, pw in passwords:
        r = analyze_password(pw)
        grade = c(r["grade"], r["grade_color"])
        print(f"  {c(label+':',C.BOLD):28s} {c(pw, C.WHITE+C.BOLD)}")
        print(f"  {'':26s} Entropy: {r['entropy']:.0f} bits | {grade} | Crack: {r['crack_time']}")
        print()

# ─────────────────────────────────────────────────────────────
#  INTERACTIVE SHELL
# ─────────────────────────────────────────────────────────────

LOGO = f"""
{C.CYAN}{C.BOLD}
  ╔══════════════════════════════════════════════════════╗
  ║   ███████╗███████╗ ██████╗████████╗██╗  ██╗         ║
  ║   ██╔════╝██╔════╝██╔════╝╚══██╔══╝██║ ██╔╝         ║
  ║   ███████╗█████╗  ██║        ██║   █████╔╝          ║
  ║   ╚════██║██╔══╝  ██║        ██║   ██╔═██╗          ║
  ║   ███████║███████╗╚██████╗   ██║   ██║  ██╗         ║
  ║   ╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝         ║
  ║         SECURITY TOOLKIT v1.0                       ║
  ╚══════════════════════════════════════════════════════╝
{C.RESET}"""

MENU = f"""
{C.BOLD}  ── LOG ANALYZER ────────────────────────────────{C.RESET}
  {C.GREEN}log <file>{C.RESET}              analyze Apache/Nginx/SSH/syslog
  {C.GREEN}log /var/log/auth.log{C.RESET}   SSH brute-force detection
  {C.GREEN}log /var/log/apache2/access.log{C.RESET}

{C.BOLD}  ── PASSWORD ANALYZER ───────────────────────────{C.RESET}
  {C.GREEN}check <password>{C.RESET}        analyze password strength
  {C.GREEN}check-file <file>{C.RESET}       analyze all passwords in a file

{C.BOLD}  ── PASSWORD GENERATOR ──────────────────────────{C.RESET}
  {C.GREEN}gen{C.RESET}                     generate password set (interactive)
  {C.GREEN}gen random [length]{C.RESET}     random password (default 16)
  {C.GREEN}gen passphrase [words]{C.RESET}  word-based passphrase (default 4)
  {C.GREEN}gen pin [length]{C.RESET}        numeric PIN (default 6)
  {C.GREEN}gen hex [bits]{C.RESET}          hex key (default 256-bit)
  {C.GREEN}gen pronounceable{C.RESET}       easy to say, hard to crack
  {C.GREEN}gen batch <n>{C.RESET}           generate n random passwords

  {C.GREEN}help{C.RESET} / {C.GREEN}exit{C.RESET}
"""

def interactive():
    print(LOGO)
    print(MENU)

    while True:
        try:
            raw = input(c("sectool> ", C.CYAN+C.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print(c("\n[*] Bye.", C.CYAN)); break

        if not raw: continue
        parts = raw.split()
        cmd = parts[0].lower()

        if cmd in ("exit","quit","q"):
            print(c("[*] Goodbye.", C.CYAN)); break

        elif cmd == "help":
            print(MENU)

        # ── LOG ──
        elif cmd == "log":
            if len(parts) < 2:
                print(c("[!] Usage: log <file>", C.YELLOW)); continue
            run_log_analyzer(parts[1])

        # ── CHECK ──
        elif cmd == "check":
            if len(parts) < 2:
                print(c("[!] Usage: check <password>", C.YELLOW)); continue
            pw = " ".join(parts[1:])
            r = analyze_password(pw)
            print_password_report(r)

        elif cmd == "check-file":
            if len(parts) < 2:
                print(c("[!] Usage: check-file <file>", C.YELLOW)); continue
            try:
                with open(parts[1]) as f:
                    passwords = [l.strip() for l in f if l.strip()]
                print(c(f"\n[*] Analyzing {len(passwords)} passwords...\n", C.CYAN))
                grades = Counter()
                for pw in passwords:
                    r = analyze_password(pw)
                    grades[r["grade"]] += 1
                print(c("  SUMMARY", C.BOLD))
                for grade, cnt in grades.most_common():
                    print(f"  {c(grade,C.YELLOW):20s} {cnt}")
            except FileNotFoundError:
                print(c(f"[!] File not found: {parts[1]}", C.RED))

        # ── GEN ──
        elif cmd == "gen":
            if len(parts) == 1:
                # Interactive generator
                print(c("\n  Password Generator", C.BOLD+C.CYAN))
                try:
                    length = int(input("  Length [16]: ").strip() or "16")
                    use_sym = input("  Include symbols? [Y/n]: ").strip().lower() != "n"
                    no_ambig = input("  Exclude ambiguous chars (0,O,l,1)? [y/N]: ").strip().lower() == "y"
                    count = int(input("  How many? [5]: ").strip() or "5")
                    passwords = [
                        (f"Password {i+1}", gen_random(length, use_symbols=use_sym, exclude_ambiguous=no_ambig))
                        for i in range(count)
                    ]
                    print_generated(passwords)
                except ValueError:
                    print(c("[!] Invalid input.", C.RED))

            elif parts[1] == "random":
                length = int(parts[2]) if len(parts) > 2 else 16
                passwords = [(f"Random ({length})", gen_random(length))]
                print_generated(passwords)

            elif parts[1] == "passphrase":
                words = int(parts[2]) if len(parts) > 2 else 4
                passwords = [(f"Passphrase ({words}w)", gen_passphrase(words))]
                print_generated(passwords)

            elif parts[1] == "pin":
                length = int(parts[2]) if len(parts) > 2 else 6
                pin = gen_pin(length)
                print(f"\n  PIN: {c(pin, C.WHITE+C.BOLD)}\n")

            elif parts[1] == "hex":
                bits = int(parts[2]) if len(parts) > 2 else 256
                key = gen_hex_key(bits)
                print(f"\n  {bits}-bit Hex Key:\n  {c(key, C.WHITE+C.BOLD)}\n")

            elif parts[1] == "pronounceable":
                passwords = [("Pronounceable", gen_pronounceable())]
                print_generated(passwords)

            elif parts[1] == "batch":
                n = int(parts[2]) if len(parts) > 2 else 10
                passwords = [(f"#{i+1}", gen_random(16)) for i in range(n)]
                print_generated(passwords)

            else:
                print(c(f"[!] Unknown gen type: {parts[1]}", C.RED))

        else:
            print(c(f"[!] Unknown command. Type 'help'.", C.RED))

# ─────────────────────────────────────────────
# CLI ENTRY
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Toolkit", add_help=False)
    parser.add_argument("mode", nargs="?", choices=["log","check","gen"], help="Mode")
    parser.add_argument("target", nargs="?", help="File/password/type")
    parser.add_argument("--length", type=int, default=16)
    parser.add_argument("--words",  type=int, default=4)
    parser.add_argument("--count",  type=int, default=5)
    args, _ = parser.parse_known_args()

    if args.mode == "log" and args.target:
        run_log_analyzer(args.target)
    elif args.mode == "check" and args.target:
        print_password_report(analyze_password(args.target))
    elif args.mode == "gen":
        passwords = [
            ("Random",        gen_random(args.length)),
            ("Passphrase",    gen_passphrase(args.words)),
            ("Pronounceable", gen_pronounceable()),
            ("Hex Key",       gen_hex_key(256)),
        ]
        for _ in range(args.count - 1):
            passwords.insert(0, (f"Random #{_+2}", gen_random(args.length)))
        print_generated(passwords)
    else:
        interactive()
