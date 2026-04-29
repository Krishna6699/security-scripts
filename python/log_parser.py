"""
log_parser.py
-------------
Parse log files for suspicious patterns, failed logins, and IOCs.
Useful for SOC triage and threat hunting workflows.

MITRE ATT&CK: T1078 - Valid Accounts
Usage:
    python3 log_parser.py --file samples/sample_log.txt --pattern "Failed password"
    python3 log_parser.py --file /var/log/auth.log --pattern "Invalid user" --top 10
"""

import re
import argparse
from collections import Counter
from datetime import datetime


SUSPICIOUS_PATTERNS = [
    "Failed password",
    "Invalid user",
    "authentication failure",
    "Connection closed by authenticating user",
    "Received disconnect",
    "error: maximum authentication attempts exceeded",
    "Permission denied",
    "sudo: command not found",
    "BREAK-IN ATTEMPT",
]


def parse_log(filepath, pattern=None, top_n=None):
    """
    Parse a log file and extract lines matching a pattern.
    Returns matched lines and top offending IPs/usernames.
    """
    matches = []
    ip_counter = Counter()
    user_counter = Counter()

    ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    user_regex = re.compile(r'(?:user|for)\s+(\w+)', re.IGNORECASE)

    try:
        with open(filepath, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                matched = False

                if pattern and re.search(pattern, line, re.IGNORECASE):
                    matched = True
                elif not pattern:
                    for sp in SUSPICIOUS_PATTERNS:
                        if sp.lower() in line.lower():
                            matched = True
                            break

                if matched:
                    matches.append((line_num, line))
                    ips = ip_regex.findall(line)
                    for ip in ips:
                        ip_counter[ip] += 1
                    users = user_regex.findall(line)
                    for user in users:
                        user_counter[user] += 1

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return [], Counter(), Counter()
    except PermissionError:
        print(f"[ERROR] Permission denied reading: {filepath}")
        return [], Counter(), Counter()

    if top_n:
        matches = matches[:top_n]

    return matches, ip_counter, user_counter


def print_report(filepath, pattern, matches, ip_counter, user_counter):
    """Print a structured summary report."""
    print("\n" + "="*60)
    print(f"  LOG PARSER REPORT")
    print(f"  File    : {filepath}")
    print(f"  Pattern : {pattern if pattern else 'Built-in suspicious patterns'}")
    print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    print(f"\n[+] Total matches found: {len(matches)}\n")

    if matches:
        print("--- Matched Lines ---")
        for line_num, line in matches:
            print(f"  Line {line_num:>5}: {line[:120]}")

    if ip_counter:
        print(f"\n--- Top Offending IPs ---")
        for ip, count in ip_counter.most_common(10):
            print(f"  {ip:<20} {count} occurrence(s)")

    if user_counter:
        print(f"\n--- Top Targeted Users ---")
        for user, count in user_counter.most_common(10):
            print(f"  {user:<20} {count} occurrence(s)")

    print("\n" + "="*60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Parse log files for suspicious patterns and IOCs."
    )
    parser.add_argument("--file", required=True, help="Path to the log file")
    parser.add_argument("--pattern", help="Regex pattern to search for (optional)")
    parser.add_argument("--top", type=int, default=None, help="Limit output to top N matches")
    args = parser.parse_args()

    matches, ip_counter, user_counter = parse_log(args.file, args.pattern, args.top)
    print_report(args.file, args.pattern, matches, ip_counter, user_counter)


if __name__ == "__main__":
    main()
