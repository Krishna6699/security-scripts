"""
hash_checker.py
---------------
Compute and verify file hashes for integrity monitoring and malware triage.
Supports MD5, SHA-1, and SHA-256. Can scan directories recursively.

MITRE ATT&CK: T1027 - Obfuscated Files or Information
Usage:
    python3 hash_checker.py --file malware_sample.exe --algorithm sha256
    python3 hash_checker.py --file document.pdf --verify abc123def456...
    python3 hash_checker.py --dir /home/user/downloads --algorithm sha256
"""

import hashlib
import argparse
import os
from datetime import datetime


KNOWN_MALICIOUS = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File (MD5)",
    "3395856ce81f2b7382dee72602f798b642f14d0": "EICAR Test File (SHA1)",
    "275a021bbfb6489e54d471899f7db9d1663fc695ef2bb48522ae9f3e2e62dbc6": "EICAR Test File (SHA256)",
}


def compute_hash(filepath, algorithm="sha256"):
    """Compute hash of a file using specified algorithm."""
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
    }

    if algorithm not in algorithms:
        print(f"[ERROR] Unsupported algorithm: {algorithm}. Use md5, sha1, or sha256.")
        return None

    hasher = algorithms[algorithm]()

    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return None
    except PermissionError:
        print(f"[ERROR] Permission denied: {filepath}")
        return None


def check_known_malicious(hash_value):
    """Check hash against known malicious hash list."""
    return KNOWN_MALICIOUS.get(hash_value.lower(), None)


def scan_directory(directory, algorithm="sha256"):
    """Recursively scan a directory and hash all files."""
    results = []
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_hash = compute_hash(filepath, algorithm)
            if file_hash:
                size = os.path.getsize(filepath)
                threat = check_known_malicious(file_hash)
                results.append({
                    "path": filepath,
                    "hash": file_hash,
                    "size": size,
                    "threat": threat
                })
    return results


def main():
    parser = argparse.ArgumentParser(
        description="File integrity checker and hash verifier."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Single file to hash")
    group.add_argument("--dir", help="Directory to scan recursively")
    parser.add_argument(
        "--algorithm",
        choices=["md5", "sha1", "sha256"],
        default="sha256",
        help="Hashing algorithm (default: sha256)"
    )
    parser.add_argument("--verify", help="Expected hash value to verify against")
    args = parser.parse_args()

    print("\n" + "="*60)
    print(f"  HASH CHECKER")
    print(f"  Algorithm : {args.algorithm.upper()}")
    print(f"  Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

    if args.file:
        file_hash = compute_hash(args.file, args.algorithm)
        if file_hash:
            print(f"  File      : {args.file}")
            print(f"  {args.algorithm.upper():<10}: {file_hash}")

            threat = check_known_malicious(file_hash)
            if threat:
                print(f"\n  [!] THREAT MATCH: {threat}")
            else:
                print(f"  [+] No known threat matches found.")

            if args.verify:
                if file_hash.lower() == args.verify.lower():
                    print(f"\n  [+] INTEGRITY CHECK PASSED — hashes match.")
                else:
                    print(f"\n  [!] INTEGRITY CHECK FAILED — hashes do not match!")
                    print(f"      Expected : {args.verify}")
                    print(f"      Computed : {file_hash}")

    elif args.dir:
        print(f"  Scanning directory: {args.dir}\n")
        results = scan_directory(args.dir, args.algorithm)
        threats_found = 0

        print(f"  {'HASH':<66} {'SIZE':>10}  FILE")
        print("  " + "-"*100)
        for r in results:
            threat_flag = " [THREAT]" if r["threat"] else ""
            print(f"  {r['hash']:<66} {r['size']:>10}  {r['path']}{threat_flag}")
            if r["threat"]:
                threats_found += 1

        print(f"\n  [+] Scanned {len(results)} file(s). Threats found: {threats_found}")

    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    main()
