"""
password_auditor.py
-------------------
Evaluate password strength against security policy requirements.
Supports single password check or bulk file audit.

MITRE ATT&CK: T1110 - Brute Force / Credential Access
Usage:
    python3 password_auditor.py --password "MyP@ssw0rd!"
    python3 password_auditor.py --file passwords.txt
"""

import re
import argparse
from datetime import datetime


COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty",
    "abc123", "monkey", "1234567", "letmein", "trustno1",
    "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123",
    "654321", "superman", "qazwsx", "michael", "football",
    "password123", "admin", "welcome", "login", "hello",
}

POLICY = {
    "min_length": 12,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_digit": True,
    "require_special": True,
    "max_repeated_chars": 3,
}

SPECIAL_CHARS = r'[!@#$%^&*(),.?":{}|<>_\-\[\]\/\\]'


def evaluate_password(password):
    """
    Evaluate a password against the security policy.
    Returns a score, grade, and list of findings.
    """
    findings = []
    score = 0
    max_score = 100

    if password.lower() in COMMON_PASSWORDS:
        return 0, "F", ["CRITICAL: Password is in the common passwords list."]

    # Length check
    if len(password) >= POLICY["min_length"]:
        score += 25
    else:
        findings.append(f"FAIL: Minimum length is {POLICY['min_length']} chars (got {len(password)})")

    if len(password) >= 16:
        score += 10

    # Uppercase
    if re.search(r'[A-Z]', password):
        score += 15
    else:
        findings.append("FAIL: Must contain at least one uppercase letter")

    # Lowercase
    if re.search(r'[a-z]', password):
        score += 15
    else:
        findings.append("FAIL: Must contain at least one lowercase letter")

    # Digit
    if re.search(r'\d', password):
        score += 15
    else:
        findings.append("FAIL: Must contain at least one digit")

    # Special character
    if re.search(SPECIAL_CHARS, password):
        score += 15
    else:
        findings.append("FAIL: Must contain at least one special character (!@#$%^&* etc.)")

    # No repeated characters (e.g. aaa, 111)
    if re.search(r'(.)\1{' + str(POLICY["max_repeated_chars"]) + r',}', password):
        score -= 10
        findings.append(f"WARN: Contains {POLICY['max_repeated_chars']}+ consecutive repeated characters")

    # No sequential patterns
    sequences = ["abcdef", "qwerty", "123456", "zxcvbn", "asdfgh"]
    for seq in sequences:
        if seq in password.lower():
            score -= 10
            findings.append(f"WARN: Contains predictable sequence '{seq}'")
            break

    score = max(0, min(score, max_score))

    if score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    if not findings:
        findings.append("PASS: Password meets all policy requirements")

    return score, grade, findings


def mask_password(password):
    """Mask password for display, showing only first and last character."""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def print_result(password, score, grade, findings, show_masked=True):
    """Print a formatted password audit result."""
    display = mask_password(password) if show_masked else password
    grade_display = {
        "A": "[A] STRONG",
        "B": "[B] GOOD",
        "C": "[C] MODERATE",
        "D": "[D] WEAK",
        "F": "[F] VERY WEAK"
    }.get(grade, grade)

    print(f"\n  Password : {display}")
    print(f"  Score    : {score}/100")
    print(f"  Grade    : {grade_display}")
    print(f"  Findings :")
    for finding in findings:
        prefix = "    [!]" if "FAIL" in finding or "CRITICAL" in finding else "    [-]" if "WARN" in finding else "    [+]"
        print(f"{prefix} {finding}")


def audit_file(filepath):
    """Audit a list of passwords from a file."""
    grades = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    try:
        with open(filepath, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]

        print(f"\n  Auditing {len(passwords)} password(s) from: {filepath}\n")
        print("  " + "-"*60)

        for pwd in passwords:
            score, grade, findings = evaluate_password(pwd)
            grades[grade] += 1
            print_result(pwd, score, grade, findings, show_masked=True)

        print("\n  " + "="*60)
        print("  SUMMARY")
        print("  " + "-"*30)
        for g, count in grades.items():
            bar = "#" * count
            print(f"  {g}: {bar} ({count})")

        total = len(passwords)
        strong = grades["A"] + grades["B"]
        print(f"\n  Strong passwords (A/B): {strong}/{total} ({strong/total*100:.1f}%)")
        print("  " + "="*60)

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate password strength against security policy."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--password", help="Single password to evaluate")
    group.add_argument("--file", help="File containing one password per line")
    args = parser.parse_args()

    print("\n" + "="*60)
    print(f"  PASSWORD AUDITOR")
    print(f"  Policy: min {POLICY['min_length']} chars, upper+lower+digit+special")
    print(f"  Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    if args.password:
        score, grade, findings = evaluate_password(args.password)
        print_result(args.password, score, grade, findings, show_masked=False)
    elif args.file:
        audit_file(args.file)

    print()


if __name__ == "__main__":
    main()
