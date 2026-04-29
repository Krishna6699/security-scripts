# security-scripts

A collection of Python, PowerShell, and Bash scripts built for security operations, endpoint auditing, and threat detection tasks. Designed to support SOC Analyst workflows including log analysis, network reconnaissance, file integrity monitoring, and system hardening checks.

---

## Author

**Rama Krishna Jujjuri**  
M.S. Cybersecurity & Networks — University of New Haven (2025)  
CompTIA Security+ | SC-200 (In Progress)  
[LinkedIn](https://linkedin.com/in/rama-krishna-jujjuri) | [GitHub](https://github.com/ramakrishna-j466)

---

## Repository Structure

```
security-scripts/
├── python/
│   ├── log_parser.py            # Parse logs for suspicious patterns (failed logins, errors)
│   ├── port_scanner.py          # Multi-threaded TCP port scanner
│   ├── hash_checker.py          # File integrity checker using MD5 / SHA-256
│   ├── password_auditor.py      # Password strength evaluator and policy checker
│   └── ip_reputation_checker.py # Check IPs against AbuseIPDB threat intel API
├── powershell/
│   ├── Get-FailedLogins.ps1     # Query Windows Event Log for failed authentication events
│   ├── Get-LocalAdmins.ps1      # Enumerate local administrator accounts
│   └── Invoke-SystemAudit.ps1   # Baseline security audit of a Windows endpoint
├── bash/
│   └── system_hardening_check.sh # Linux CIS benchmark-aligned hardening check
├── samples/
│   └── sample_log.txt           # Sample log file for testing log_parser.py
└── README.md
```

---

## Scripts Overview

### Python

| Script | Purpose | Key Libraries |
|---|---|---|
| `log_parser.py` | Parse log files for IOCs, failed logins, error patterns | `re`, `argparse`, `collections` |
| `port_scanner.py` | Scan TCP ports with threading for speed | `socket`, `threading`, `argparse` |
| `hash_checker.py` | Compute and verify MD5/SHA-256 file hashes | `hashlib`, `argparse` |
| `password_auditor.py` | Evaluate password strength against security policy | `re`, `argparse` |
| `ip_reputation_checker.py` | Query AbuseIPDB API for IP threat intelligence | `requests`, `argparse` |

### PowerShell

| Script | Purpose |
|---|---|
| `Get-FailedLogins.ps1` | Extracts Event ID 4625 failed login events with timestamps and usernames |
| `Get-LocalAdmins.ps1` | Lists all members of the local Administrators group |
| `Invoke-SystemAudit.ps1` | Checks firewall status, running services, open ports, and password policy |

### Bash

| Script | Purpose |
|---|---|
| `system_hardening_check.sh` | Checks SSH config, password policies, firewall status, world-writable files |

---

## Usage Examples

### log_parser.py
```bash
python3 log_parser.py --file samples/sample_log.txt --pattern "Failed password"
python3 log_parser.py --file /var/log/auth.log --pattern "Invalid user" --top 10
```

### port_scanner.py
```bash
python3 port_scanner.py --target 192.168.1.1 --ports 1-1024
python3 port_scanner.py --target 10.0.0.5 --ports 22,80,443,3389
```

### hash_checker.py
```bash
python3 hash_checker.py --file malware_sample.exe --algorithm sha256
python3 hash_checker.py --file document.pdf --verify abc123def456...
```

### password_auditor.py
```bash
python3 password_auditor.py --password "MyP@ssw0rd!"
python3 password_auditor.py --file passwords.txt
```

### ip_reputation_checker.py
```bash
python3 ip_reputation_checker.py --ip 185.220.101.5 --apikey YOUR_API_KEY
```

### PowerShell
```powershell
# Run with administrator privileges
.\Get-FailedLogins.ps1 -Hours 24
.\Get-LocalAdmins.ps1
.\Invoke-SystemAudit.ps1 -OutputPath C:\Temp\audit_report.txt
```

### Bash
```bash
chmod +x system_hardening_check.sh
sudo ./system_hardening_check.sh
```

---

## MITRE ATT&CK Coverage

| Script | Technique | Tactic |
|---|---|---|
| `log_parser.py` | T1078 — Valid Accounts | Defense Evasion, Persistence |
| `port_scanner.py` | T1046 — Network Service Discovery | Discovery |
| `hash_checker.py` | T1027 — Obfuscated Files or Information | Defense Evasion |
| `Get-FailedLogins.ps1` | T1110 — Brute Force | Credential Access |
| `Get-LocalAdmins.ps1` | T1087.001 — Local Account Discovery | Discovery |
| `system_hardening_check.sh` | T1548 — Abuse Elevation Control Mechanism | Privilege Escalation |

---

## Requirements

**Python:** Python 3.8+
```bash
pip install requests
```

**PowerShell:** Windows PowerShell 5.1+ or PowerShell 7+  
Run as Administrator for Event Log and audit scripts.

**Bash:** Linux/macOS with `bash`, `awk`, `grep`, `ss` or `netstat`  
Run as root or with `sudo` for full hardening checks.

---

## Disclaimer

These scripts are intended for **authorized security testing, auditing, and educational purposes only**.  
Do not use on systems or networks without explicit written permission.  
The author is not responsible for any misuse of these tools.

---

## Related Projects

- [soc-sentinel-home-lab](https://github.com/ramakrishna-j466/soc-sentinel-home-lab) — Microsoft Sentinel SIEM with KQL detection rules and SOAR playbooks
- [kql-detection-library](https://github.com/ramakrishna-j466/kql-detection-library) — 15+ KQL queries mapped to MITRE ATT&CK
- [active-directory-security-lab](https://github.com/ramakrishna-j466/active-directory-security-lab) — AD hardening and IAM security scripts
