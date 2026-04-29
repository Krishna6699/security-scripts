# Get-FailedLogins.ps1
# ---------------------
# Extract failed login events (Event ID 4625) from Windows Security Event Log.
# Identifies brute force attempts, credential stuffing, and account lockouts.
#
# MITRE ATT&CK: T1110 - Brute Force
# Requires: Administrator privileges, Windows Event Log access
#
# Usage:
#   .\Get-FailedLogins.ps1
#   .\Get-FailedLogins.ps1 -Hours 24
#   .\Get-FailedLogins.ps1 -Hours 48 -TopN 20 -ExportCsv C:\Temp\failed_logins.csv

param(
    [int]$Hours = 24,
    [int]$TopN = 10,
    [string]$ExportCsv = ""
)

# --- Header ---
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  FAILED LOGIN REPORT" -ForegroundColor Cyan
Write-Host "  Event ID  : 4625 (An account failed to log on)" -ForegroundColor Cyan
Write-Host "  Timeframe : Last $Hours hour(s)" -ForegroundColor Cyan
Write-Host "  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# --- Time filter ---
$startTime = (Get-Date).AddHours(-$Hours)

# --- Query Security Event Log ---
Write-Host "  [*] Querying Security Event Log..." -ForegroundColor Yellow

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = $startTime
    } -ErrorAction Stop
}
catch [System.Exception] {
    if ($_.Exception.Message -like "*No events were found*") {
        Write-Host "  [+] No failed login events found in the last $Hours hour(s)." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "  [!] Error querying event log: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  [!] Ensure you are running as Administrator." -ForegroundColor Red
        exit 1
    }
}

Write-Host "  [+] Found $($events.Count) failed login event(s).`n" -ForegroundColor Green

# --- Parse events ---
$results = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data

    $username     = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $domain       = ($data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
    $workstation  = ($data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
    $sourceIP     = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
    $logonType    = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    $failureReason = ($data | Where-Object { $_.Name -eq 'SubStatus' }).'#text'

    $logonTypeMap = @{
        '2'  = 'Interactive'
        '3'  = 'Network'
        '4'  = 'Batch'
        '5'  = 'Service'
        '7'  = 'Unlock'
        '8'  = 'NetworkCleartext'
        '10' = 'RemoteInteractive (RDP)'
        '11' = 'CachedInteractive'
    }

    $failureMap = @{
        '0xC000006A' = 'Wrong password'
        '0xC0000064' = 'Username does not exist'
        '0xC000006F' = 'Outside logon hours'
        '0xC0000070' = 'Workstation restriction'
        '0xC0000072' = 'Account disabled'
        '0xC000006D' = 'Bad username or auth package'
        '0xC0000234' = 'Account locked out'
    }

    [PSCustomObject]@{
        TimeCreated   = $event.TimeCreated
        Username      = if ($username) { $username } else { 'N/A' }
        Domain        = if ($domain) { $domain } else { 'N/A' }
        SourceIP      = if ($sourceIP -and $sourceIP -ne '-') { $sourceIP } else { 'N/A' }
        Workstation   = if ($workstation -and $workstation -ne '-') { $workstation } else { 'N/A' }
        LogonType     = if ($logonTypeMap[$logonType]) { $logonTypeMap[$logonType] } else { $logonType }
        FailureReason = if ($failureMap[$failureReason]) { $failureMap[$failureReason] } else { $failureReason }
    }
}

# --- Display results ---
Write-Host "  --- Failed Login Events (most recent first) ---`n"
$results | Sort-Object TimeCreated -Descending | Format-Table -AutoSize

# --- Top offending usernames ---
Write-Host "`n  --- Top $TopN Targeted Usernames ---`n"
$results |
    Where-Object { $_.Username -ne 'N/A' -and $_.Username -notmatch '^\$$' } |
    Group-Object Username |
    Sort-Object Count -Descending |
    Select-Object -First $TopN |
    Format-Table @{L='Username';E={$_.Name}}, @{L='Attempts';E={$_.Count}} -AutoSize

# --- Top offending source IPs ---
Write-Host "  --- Top $TopN Source IPs ---`n"
$results |
    Where-Object { $_.SourceIP -ne 'N/A' -and $_.SourceIP -ne '127.0.0.1' } |
    Group-Object SourceIP |
    Sort-Object Count -Descending |
    Select-Object -First $TopN |
    Format-Table @{L='Source IP';E={$_.Name}}, @{L='Attempts';E={$_.Count}} -AutoSize

# --- Potential brute force detection (>=5 attempts from same IP) ---
$bruteForce = $results |
    Where-Object { $_.SourceIP -ne 'N/A' } |
    Group-Object SourceIP |
    Where-Object { $_.Count -ge 5 }

if ($bruteForce) {
    Write-Host "  [!] POTENTIAL BRUTE FORCE DETECTED:" -ForegroundColor Red
    foreach ($bf in $bruteForce) {
        Write-Host "      $($bf.Name) — $($bf.Count) attempts" -ForegroundColor Red
    }
    Write-Host ""
}

# --- CSV export ---
if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation
    Write-Host "  [+] Results exported to: $ExportCsv" -ForegroundColor Green
}

Write-Host "============================================================`n" -ForegroundColor Cyan
