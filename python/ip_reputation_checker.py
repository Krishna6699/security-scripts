"""
ip_reputation_checker.py
------------------------
Query IP addresses against the AbuseIPDB threat intelligence API.
Identifies malicious IPs, abuse confidence scores, and ISP details.

MITRE ATT&CK: T1071 - Application Layer Protocol / Threat Intelligence
Usage:
    python3 ip_reputation_checker.py --ip 185.220.101.5 --apikey YOUR_API_KEY
    python3 ip_reputation_checker.py --file suspicious_ips.txt --apikey YOUR_API_KEY
    
Get a free API key at: https://www.abuseipdb.com/register
"""

import argparse
import ipaddress
import time
from datetime import datetime

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' library not found. Run: pip install requests")
    exit(1)


API_BASE = "https://api.abuseipdb.com/api/v2/check"
RISK_THRESHOLDS = {
    "low": 25,
    "medium": 50,
    "high": 75,
}


def validate_ip(ip_str):
    """Validate that the string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def check_ip(ip, api_key, max_age_days=90):
    """
    Query AbuseIPDB for IP reputation data.
    Returns parsed result dict or None on error.
    """
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
        "verbose": True
    }

    try:
        response = requests.get(API_BASE, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            return response.json().get("data", {})
        elif response.status_code == 401:
            print("[ERROR] Invalid API key.")
            return None
        elif response.status_code == 429:
            print("[WARN] Rate limit reached. Waiting 5 seconds...")
            time.sleep(5)
            return None
        else:
            print(f"[ERROR] API returned status {response.status_code}")
            return None

    except requests.exceptions.ConnectionError:
        print("[ERROR] No internet connection or API unreachable.")
        return None
    except requests.exceptions.Timeout:
        print("[ERROR] Request timed out.")
        return None


def get_risk_level(score):
    """Map abuse confidence score to human-readable risk level."""
    if score >= RISK_THRESHOLDS["high"]:
        return "HIGH"
    elif score >= RISK_THRESHOLDS["medium"]:
        return "MEDIUM"
    elif score >= RISK_THRESHOLDS["low"]:
        return "LOW"
    else:
        return "CLEAN"


def print_ip_report(ip, data):
    """Print formatted IP reputation report."""
    if not data:
        print(f"\n  [ERROR] No data returned for {ip}")
        return

    score = data.get("abuseConfidenceScore", 0)
    risk = get_risk_level(score)

    risk_indicators = {
        "HIGH": "[!!!] HIGH RISK",
        "MEDIUM": "[!!]  MEDIUM RISK",
        "LOW": "[!]   LOW RISK",
        "CLEAN": "[+]   CLEAN"
    }

    print(f"\n  {'─'*54}")
    print(f"  IP Address     : {ip}")
    print(f"  Risk Level     : {risk_indicators.get(risk, risk)}")
    print(f"  Abuse Score    : {score}/100")
    print(f"  Total Reports  : {data.get('totalReports', 0)}")
    print(f"  Last Reported  : {data.get('lastReportedAt', 'Never')}")
    print(f"  Country        : {data.get('countryCode', 'Unknown')}")
    print(f"  ISP            : {data.get('isp', 'Unknown')}")
    print(f"  Domain         : {data.get('domain', 'Unknown')}")
    print(f"  Usage Type     : {data.get('usageType', 'Unknown')}")
    print(f"  Is Whitelisted : {data.get('isWhitelisted', False)}")
    print(f"  Is TOR Node    : {data.get('isTor', False)}")


def check_file(filepath, api_key):
    """Check multiple IPs from a file."""
    try:
        with open(filepath, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]

        valid_ips = [ip for ip in ips if validate_ip(ip)]
        invalid = len(ips) - len(valid_ips)

        print(f"\n  Checking {len(valid_ips)} IPs from: {filepath}")
        if invalid > 0:
            print(f"  Skipping {invalid} invalid entries.")

        high_risk = []
        medium_risk = []

        for ip in valid_ips:
            data = check_ip(ip, api_key)
            print_ip_report(ip, data)
            if data:
                score = data.get("abuseConfidenceScore", 0)
                level = get_risk_level(score)
                if level == "HIGH":
                    high_risk.append(ip)
                elif level == "MEDIUM":
                    medium_risk.append(ip)
            time.sleep(1)

        print(f"\n  {'='*54}")
        print(f"  SUMMARY — {len(valid_ips)} IPs checked")
        print(f"  High Risk  : {len(high_risk)}")
        print(f"  Medium Risk: {len(medium_risk)}")
        if high_risk:
            print(f"\n  High-risk IPs to block:")
            for ip in high_risk:
                print(f"    {ip}")
        print(f"  {'='*54}")

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Check IP reputation using AbuseIPDB threat intelligence API."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="Single IP address to check")
    group.add_argument("--file", help="File containing one IP per line")
    parser.add_argument("--apikey", required=True, help="AbuseIPDB API key")
    parser.add_argument("--maxage", type=int, default=90, help="Max report age in days (default: 90)")
    args = parser.parse_args()

    print("\n" + "="*60)
    print(f"  IP REPUTATION CHECKER")
    print(f"  Source  : AbuseIPDB")
    print(f"  Max Age : {args.maxage} days")
    print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    if args.ip:
        if not validate_ip(args.ip):
            print(f"[ERROR] Invalid IP address: {args.ip}")
            return
        data = check_ip(args.ip, args.apikey, args.maxage)
        print_ip_report(args.ip, data)
    elif args.file:
        check_file(args.file, args.apikey)

    print()


if __name__ == "__main__":
    main()
