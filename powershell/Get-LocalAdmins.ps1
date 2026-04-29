# Get-LocalAdmins.ps1
# --------------------
# Enumerate all members of the local Administrators group.
# Detects unauthorized admin accounts for IAM auditing and privilege management.
#
# MITRE ATT&CK: T1087.001 - Account Discovery: Local Account
#               T1098 - Account Manipulation
# Requires: Administrator privileges (recommended)
#
# Usage:
#   .\Get-LocalAdmins.ps1
#   .\Get-LocalAdmins.ps1 -ExportCsv C:\Temp\local_admins.csv

param(
    [string]$ExportCsv = "",
    [switch]$Verbose
)

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  LOCAL ADMINISTRATORS AUDIT" -ForegroundColor Cyan
Write-Host "  Hostname  : $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

$results = @()

try {
    $adminGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
    $members = @($adminGroup.Invoke("Members"))

    Write-Host "  [+] Found $($members.Count) member(s) in local Administrators group.`n"

    foreach ($member in $members) {
        $memberObj = [ADSI]$member.GetType().InvokeMember("AdsPath", 'GetProperty', $null, $member, $null)
        $name = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
        $class = $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)

        $domain = ""
        $source = "Local"
        if ($memberObj -match "WinNT://(.+)/$name") {
            $domain = $matches[1]
            if ($domain -ne $env:COMPUTERNAME) {
                $source = "Domain ($domain)"
            }
        }

        $enabled = "Unknown"
        $lastLogin = "Unknown"
        $passwordAge = "Unknown"

        if ($source -eq "Local") {
            try {
                $localUser = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
                if ($localUser) {
                    $enabled = if ($localUser.Enabled) { "Yes" } else { "No" }
                    $lastLogin = if ($localUser.LastLogon) { $localUser.LastLogon.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
                    $pwChanged = $localUser.PasswordLastSet
                    if ($pwChanged) {
                        $days = ((Get-Date) - $pwChanged).Days
                        $passwordAge = "$days days"
                    }
                }
            } catch {}
        }

        $entry = [PSCustomObject]@{
            Name        = $name
            Type        = $class
            Source      = $source
            Enabled     = $enabled
            LastLogin   = $lastLogin
            PasswordAge = $passwordAge
        }

        $results += $entry

        $color = if ($source -ne "Local") { "Yellow" } else { "White" }
        Write-Host ("  " + ("{0,-25} {1,-10} {2,-25} Enabled:{3}" -f $name, $class, $source, $enabled)) -ForegroundColor $color
    }

} catch {
    Write-Host "  [!] Error enumerating local admins: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  [!] Try running as Administrator." -ForegroundColor Red
    exit 1
}

# --- Findings ---
Write-Host "`n  --- Security Findings ---`n"

$domainAdmins = $results | Where-Object { $_.Source -ne "Local" }
$disabledAdmins = $results | Where-Object { $_.Enabled -eq "No" }
$staleAdmins = $results | Where-Object {
    $_.LastLogin -ne "Never" -and $_.LastLogin -ne "Unknown" -and
    ((Get-Date) - [datetime]$_.LastLogin).Days -gt 90
}

if ($domainAdmins) {
    Write-Host "  [!] Domain accounts with local admin rights:" -ForegroundColor Yellow
    foreach ($da in $domainAdmins) {
        Write-Host "      $($da.Name) ($($da.Source))" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($disabledAdmins) {
    Write-Host "  [-] Disabled accounts in Administrators group (should be removed):" -ForegroundColor Yellow
    foreach ($da in $disabledAdmins) {
        Write-Host "      $($da.Name)" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($staleAdmins) {
    Write-Host "  [-] Admin accounts with no login in 90+ days (review for removal):" -ForegroundColor Yellow
    foreach ($sa in $staleAdmins) {
        Write-Host "      $($sa.Name) — Last login: $($sa.LastLogin)" -ForegroundColor Yellow
    }
    Write-Host ""
}

if (-not $domainAdmins -and -not $disabledAdmins -and -not $staleAdmins) {
    Write-Host "  [+] No immediate concerns found." -ForegroundColor Green
}

# --- Recommendations ---
Write-Host "  --- Recommendations ---`n"
Write-Host "  1. Apply least-privilege: remove any accounts that do not require admin access."
Write-Host "  2. Review domain accounts — each should have documented justification."
Write-Host "  3. Remove or disable stale admin accounts immediately."
Write-Host "  4. Ensure the built-in Administrator account is renamed and disabled."
Write-Host "  5. Enable audit policy for privilege escalation (Event ID 4672, 4673)."

if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation
    Write-Host "`n  [+] Results exported to: $ExportCsv" -ForegroundColor Green
}

Write-Host "`n============================================================`n" -ForegroundColor Cyan
