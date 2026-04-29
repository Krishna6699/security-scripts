#!/usr/bin/env bash
# system_hardening_check.sh
# -------------------------
# Linux endpoint security hardening check aligned with CIS Benchmark basics.
# Checks SSH configuration, password policies, firewall status,
# world-writable files, SUID/SGID binaries, and open ports.
#
# MITRE ATT&CK: T1548 - Abuse Elevation Control Mechanism
#               T1021.004 - Remote Services: SSH
# Requires: root or sudo for full output
#
# Usage:
#   chmod +x system_hardening_check.sh
#   sudo ./system_hardening_check.sh

PASS=0
WARN=0
FAIL=0
REPORT="/tmp/hardening_report_$(date +%Y%m%d_%H%M%S).txt"

print_header() {
    echo ""
    echo "============================================================"
    echo "  LINUX HARDENING CHECK"
    echo "  Hostname  : $(hostname)"
    echo "  OS        : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
    echo "  Date      : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  User      : $(whoami)"
    echo "============================================================"
    echo ""
}

check() {
    local STATUS=$1
    local MESSAGE=$2
    local DETAIL=$3

    if [ "$STATUS" = "PASS" ]; then
        echo "  [PASS] $MESSAGE"
        PASS=$((PASS + 1))
    elif [ "$STATUS" = "WARN" ]; then
        echo "  [WARN] $MESSAGE"
        [ -n "$DETAIL" ] && echo "         $DETAIL"
        WARN=$((WARN + 1))
    elif [ "$STATUS" = "FAIL" ]; then
        echo "  [FAIL] $MESSAGE"
        [ -n "$DETAIL" ] && echo "         $DETAIL"
        FAIL=$((FAIL + 1))
    fi
}

section() {
    echo ""
    echo "  ── $1 ──────────────────────────────────────"
}

# ──────────────────────────────────────────────
# 1. SSH CONFIGURATION
# ──────────────────────────────────────────────
section "SSH Configuration"

SSH_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSH_CONFIG" ]; then
    # Root login
    if grep -qiE "^PermitRootLogin\s+no" "$SSH_CONFIG"; then
        check "PASS" "SSH PermitRootLogin is disabled"
    else
        check "FAIL" "SSH PermitRootLogin should be set to 'no'" "Edit $SSH_CONFIG: PermitRootLogin no"
    fi

    # Password authentication
    if grep -qiE "^PasswordAuthentication\s+no" "$SSH_CONFIG"; then
        check "PASS" "SSH PasswordAuthentication is disabled (key-only)"
    else
        check "WARN" "SSH PasswordAuthentication is enabled" "Consider disabling in favor of key-based auth"
    fi

    # Empty passwords
    if grep -qiE "^PermitEmptyPasswords\s+no" "$SSH_CONFIG"; then
        check "PASS" "SSH PermitEmptyPasswords is disabled"
    else
        check "FAIL" "SSH PermitEmptyPasswords must be 'no'" "Edit $SSH_CONFIG: PermitEmptyPasswords no"
    fi

    # X11 forwarding
    if grep -qiE "^X11Forwarding\s+no" "$SSH_CONFIG"; then
        check "PASS" "SSH X11Forwarding is disabled"
    else
        check "WARN" "SSH X11Forwarding is enabled" "Disable if not needed: X11Forwarding no"
    fi

    # Protocol version
    if ! grep -qiE "^Protocol\s+1" "$SSH_CONFIG"; then
        check "PASS" "SSH Protocol 1 not explicitly enabled"
    else
        check "FAIL" "SSH Protocol 1 is insecure and must be disabled"
    fi
else
    check "WARN" "SSH config file not found at $SSH_CONFIG"
fi

# ──────────────────────────────────────────────
# 2. PASSWORD POLICY
# ──────────────────────────────────────────────
section "Password Policy"

LOGIN_DEFS="/etc/login.defs"

if [ -f "$LOGIN_DEFS" ]; then
    PASS_MAX=$(grep "^PASS_MAX_DAYS" "$LOGIN_DEFS" | awk '{print $2}')
    PASS_MIN=$(grep "^PASS_MIN_DAYS" "$LOGIN_DEFS" | awk '{print $2}')
    PASS_WARN=$(grep "^PASS_WARN_AGE" "$LOGIN_DEFS" | awk '{print $2}')

    if [ -n "$PASS_MAX" ] && [ "$PASS_MAX" -le 90 ]; then
        check "PASS" "Password max age is $PASS_MAX day(s) (<=90)"
    else
        check "FAIL" "Password max age is $PASS_MAX — should be 90 or less" "Edit $LOGIN_DEFS: PASS_MAX_DAYS 90"
    fi

    if [ -n "$PASS_MIN" ] && [ "$PASS_MIN" -ge 1 ]; then
        check "PASS" "Password min age is $PASS_MIN day(s) (>=1)"
    else
        check "WARN" "PASS_MIN_DAYS is $PASS_MIN — consider setting to 1 or more"
    fi

    if [ -n "$PASS_WARN" ] && [ "$PASS_WARN" -ge 7 ]; then
        check "PASS" "Password warning age is $PASS_WARN day(s) (>=7)"
    else
        check "WARN" "PASS_WARN_AGE is $PASS_WARN — consider setting to 7+"
    fi
else
    check "WARN" "Could not read $LOGIN_DEFS"
fi

# ──────────────────────────────────────────────
# 3. FIREWALL STATUS
# ──────────────────────────────────────────────
section "Firewall Status"

if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    if echo "$UFW_STATUS" | grep -q "active"; then
        check "PASS" "UFW firewall is active"
    else
        check "FAIL" "UFW firewall is inactive" "Run: sudo ufw enable"
    fi
elif command -v firewall-cmd &>/dev/null; then
    if firewall-cmd --state 2>/dev/null | grep -q "running"; then
        check "PASS" "firewalld is running"
    else
        check "FAIL" "firewalld is not running" "Run: sudo systemctl start firewalld"
    fi
elif command -v iptables &>/dev/null; then
    RULES=$(iptables -L 2>/dev/null | grep -c "^ACCEPT\|^DROP\|^REJECT")
    if [ "$RULES" -gt 0 ]; then
        check "PASS" "iptables rules present ($RULES rules)"
    else
        check "WARN" "iptables has no active rules"
    fi
else
    check "WARN" "No firewall tool detected (ufw/firewalld/iptables)"
fi

# ──────────────────────────────────────────────
# 4. OPEN PORTS
# ──────────────────────────────────────────────
section "Open Ports"

echo "  Listening ports:"
if command -v ss &>/dev/null; then
    ss -tlnp 2>/dev/null | grep LISTEN | awk '{print "    " $1, $4, $6}'
elif command -v netstat &>/dev/null; then
    netstat -tlnp 2>/dev/null | grep LISTEN | awk '{print "    " $4, $7}'
else
    echo "    [WARN] Neither ss nor netstat found"
fi

# ──────────────────────────────────────────────
# 5. WORLD-WRITABLE FILES
# ──────────────────────────────────────────────
section "World-Writable Files"

WW_FILES=$(find / -xdev -type f -perm -0002 2>/dev/null | grep -v -E "^/proc|^/sys|^/dev")
WW_COUNT=$(echo "$WW_FILES" | grep -c . 2>/dev/null || echo 0)

if [ "$WW_COUNT" -eq 0 ]; then
    check "PASS" "No world-writable files found outside /proc /sys /dev"
elif [ "$WW_COUNT" -le 5 ]; then
    check "WARN" "$WW_COUNT world-writable file(s) found" "Review and tighten permissions"
    echo "$WW_FILES" | head -10 | while read -r f; do echo "         $f"; done
else
    check "FAIL" "$WW_COUNT world-writable files found" "Investigate and remove write permissions"
    echo "$WW_FILES" | head -10 | while read -r f; do echo "         $f"; done
    echo "         (showing first 10)"
fi

# ──────────────────────────────────────────────
# 6. SUID / SGID BINARIES
# ──────────────────────────────────────────────
section "SUID / SGID Binaries"

SUID=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
SUID_COUNT=$(echo "$SUID" | grep -c . 2>/dev/null || echo 0)

if [ "$SUID_COUNT" -le 15 ]; then
    check "PASS" "$SUID_COUNT SUID/SGID binaries found (within expected range)"
else
    check "WARN" "$SUID_COUNT SUID/SGID binaries found — review for unusual entries"
fi

echo "  SUID/SGID binaries:"
echo "$SUID" | while read -r f; do echo "    $f"; done

# ──────────────────────────────────────────────
# 7. SUMMARY
# ──────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  SUMMARY"
echo "  PASS: $PASS"
echo "  WARN: $WARN"
echo "  FAIL: $FAIL"
echo "  Total Checks: $((PASS + WARN + FAIL))"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "  [!] $FAIL critical issue(s) require immediate attention."
elif [ "$WARN" -gt 0 ]; then
    echo "  [-] $WARN warning(s) should be reviewed."
else
    echo "  [+] System passed all hardening checks."
fi

echo "============================================================"
echo ""
