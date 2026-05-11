<#
.SYNOPSIS
    WinSecAudit - Windows Server Security Audit Tool
.DESCRIPTION
    Comprehensive security audit for Windows Server environments.
    Checks 50+ security configurations across 8 categories.
    Generates a professional HTML report with severity ratings.
    
    Author: Mattia @ Converge/WeAreProject
    Version: 1.0.0
    License: Commercial - Single Use
    
    Usage: .\Invoke-WinSecAudit.ps1 [-OutputPath <path>] [-SkipNetwork] [-SkipServices]
.EXAMPLE
    .\Invoke-WinSecAudit.ps1 -OutputPath "C:\Reports"
    .\Invoke-WinSecAudit.ps1 -SkipNetwork -OutputPath ".\reports"
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\WinSecAudit-Reports",
    [switch]$SkipNetwork,
    [switch]$SkipServices,
    [switch]$SkipUsers,
    [switch]$SkipFirewall,
    [switch]$SkipUpdates,
    [switch]$SkipSMB,
    [switch]$SkipRDP,
    [switch]$SkipScheduledTasks,
    [switch]$Quiet
)

$ErrorActionPreference = "Continue"
$ScriptVersion = "1.0.0"
$AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$Hostname = $env:COMPUTERNAME
$OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
$Findings = [System.Collections.ArrayList]::new()

# ─── Severity enum ───
enum Severity { Critical; High; Medium; Low; Info; Pass }

# ─── Helper: Add finding ───
function Add-Finding {
    param(
        [string]$Category,
        [string]$Check,
        [Severity]$Severity,
        [string]$Description,
        [string]$Recommendation,
        [string]$Evidence = ""
    )
    [void]$Findings.Add([PSCustomObject]@{
        Category      = $Category
        Check         = $Check
        Severity      = $Severity.ToString()
        Description   = $Description
        Recommendation = $Recommendation
        Evidence      = $Evidence
        Timestamp     = (Get-Date -Format "HH:mm:ss")
    })
    if (-not $Quiet) {
        $icon = switch ($Severity) {
            "Critical" { "[!!!]" }
            "High"     { "[!!]" }
            "Medium"   { "[!]" }
            "Low"      { "[-]" }
            "Info"     { "[i]" }
            "Pass"     { "[+]" }
        }
        Write-Host "$icon $Category | $Check" -ForegroundColor $(
            switch ($Severity) {
                "Critical" { "Red" }
                "High"     { "DarkRed" }
                "Medium"   { "Yellow" }
                "Low"      { "DarkYellow" }
                "Info"     { "Cyan" }
                "Pass"     { "Green" }
            }
        )
    }
}

# ─── Helper: Get service status safely ───
function Get-SafeService {
    param([string]$Name)
    try { Get-Service -Name $Name -ErrorAction Stop } catch { $null }
}

# ═══════════════════════════════════════════
# 1. PASSWORD & ACCOUNT POLICY
# ═══════════════════════════════════════════
if (-not $SkipUsers) {
    Write-Host "`n=== PASSWORD & ACCOUNT POLICY ===" -ForegroundColor White

    try {
        $netAccounts = net accounts 2>&1 | Out-String
        $minPwdLen = ($netAccounts | Select-String "Minimum password length" -AllMatches) -replace ".*:\s*",""
        
        if ([int]$minPwdLen -lt 12) {
            Add-Finding -Category "Account Policy" -Check "Minimum Password Length" `
                -Severity High `
                -Description "Minimum password length is set to $minPwdLen characters (recommended: 12+)" `
                -Recommendation "Run: net accounts /minpwlen:12"
        } else {
            Add-Finding -Category "Account Policy" -Check "Minimum Password Length" `
                -Severity Pass `
                -Description "Password minimum length is $minPwdLen (meets policy)"
        }
    } catch {
        Add-Finding -Category "Account Policy" -Check "Password Policy" `
            -Severity Info -Description "Unable to read password policy" -Recommendation "Check manually"
    }

    # Admin account checks
    $adminUsers = Get-LocalUser | Where-Object { $_.SID.Value -match "-500$" -or $_.Name -eq "Administrator" }
    foreach ($admin in $adminUsers) {
        if ($admin.Enabled -and $admin.Name -eq "Administrator") {
            Add-Finding -Category "Account Policy" -Check "Default Admin Account Active" `
                -Severity High `
                -Description "Built-in 'Administrator' account is active and named 'Administrator'" `
                -Recommendation "Rename the account and/or disable it. Use a named admin account instead."
        }
    }

    # Check for accounts with no password expiry
    $noExpiry = Get-LocalUser | Where-Object { $_.Enabled -and $_.PasswordExpires -eq $null }
    if ($noExpiry) {
        Add-Finding -Category "Account Policy" -Check "Accounts Without Password Expiry" `
            -Severity Medium `
            -Description "$($noExpiry.Count) enabled account(s) have passwords that never expire: $($noExpiry.Name -join ', ')" `
            -Recommendation "Set password expiration for all user accounts"
    }

    # Guest account
    $guest = Get-LocalUser | Where-Object { $_.Name -eq "Guest" }
    if ($guest -and $guest.Enabled) {
        Add-Finding -Category "Account Policy" -Check "Guest Account Enabled" `
            -Severity High `
            -Description "Guest account is ENABLED" `
            -Recommendation "Disable immediately: net user Guest /active:no"
    } else {
        Add-Finding -Category "Account Policy" -Check "Guest Account" `
            -Severity Pass -Description "Guest account is disabled"
    }

    # Check for duplicate admin-level accounts
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($admins -and $admins.Count -gt 3) {
        Add-Finding -Category "Account Policy" -Check "Excessive Admin Accounts" `
            -Severity Medium `
            -Description "$($admins.Count) members in Administrators group: $($admins.Name -join ', ')" `
            -Recommendation "Audit admin group membership. Use principle of least privilege."
    }
}

# ═══════════════════════════════════════════
# 2. WINDOWS FIREWALL
# ═══════════════════════════════════════════
if (-not $SkipFirewall) {
    Write-Host "`n=== FIREWALL STATUS ===" -ForegroundColor White

    $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    foreach ($profile in $fwProfiles) {
        if (-not $profile.Enabled) {
            Add-Finding -Category "Firewall" -Check "Windows Firewall ($($profile.Name))" `
                -Severity Critical `
                -Description "Windows Firewall is DISABLED on $($profile.Name) profile" `
                -Recommendation "Enable immediately: Set-NetFirewallProfile -Name $($profile.Name) -Enabled True"
        } else {
            Add-Finding -Category "Firewall" -Check "Windows Firewall ($($profile.Name))" `
                -Severity Pass `
                -Description "Firewall is enabled on $($profile.Name)"
        }
    }

    # Inbound rules allowing any source
    $anySourceRules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -eq "Any" }
    
    if ($anySourceRules -and $anySourceRules.Count -gt 20) {
        Add-Finding -Category "Firewall" -Check "Excessive Open Inbound Rules" `
            -Severity Medium `
            -Description "$($anySourceRules.Count) inbound rules accept traffic from ANY source" `
            -Recommendation "Restrict rules to specific IP ranges where possible"
    }
}

# ═══════════════════════════════════════════
# 3. RDP SECURITY
# ═══════════════════════════════════════════
if (-not $SkipRDP) {
    Write-Host "`n=== RDP SECURITY ===" -ForegroundColor White

    $rdpReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $rdpEnabled = (Get-ItemProperty -Path $rdpReg -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections

    if ($rdpEnabled -eq 0) {
        Add-Finding -Category "RDP" -Check "RDP Enabled" `
            -Severity Info `
            -Description "Remote Desktop is enabled" `
            -Recommendation "Ensure NLA is enforced and firewall restricts source IPs"

        # NLA check
        $nla = (Get-ItemProperty -Path "$rdpReg\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
        if ($nla -ne 1) {
            Add-Finding -Category "RDP" -Check "NLA Not Enforced" `
                -Severity High `
                -Description "Network Level Authentication (NLA) is NOT required for RDP" `
                -Recommendation "Enable NLA: Set-ItemProperty '$rdpReg\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1"
        } else {
            Add-Finding -Category "RDP" -Check "NLA Enforced" `
                -Severity Pass -Description "NLA is properly required"
        }

        # RDP port
        $rdpPort = (Get-ItemProperty -Path "$rdpReg\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue).PortNumber
        if ($rdpPort -eq 3389) {
            Add-Finding -Category "RDP" -Check "Default RDP Port" `
                -Severity Low `
                -Description "RDP is using default port 3389" `
                -Recommendation "Consider changing to a non-standard port to reduce noise"
        }
    } else {
        Add-Finding -Category "RDP" -Check "RDP Disabled" `
            -Severity Pass -Description "RDP is disabled (good if not needed)"
    }
}

# ═══════════════════════════════════════════
# 4. SMB CONFIGURATION
# ═══════════════════════════════════════════
if (-not $SkipSMB) {
    Write-Host "`n=== SMB CONFIGURATION ===" -ForegroundColor White

    # SMBv1 check
    $smb1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableSMB1Protocol
    if ($smb1) {
        Add-Finding -Category "SMB" -Check "SMBv1 Enabled" `
            -Severity Critical `
            -Description "SMBv1 protocol is ENABLED. This is the protocol exploited by WannaCry/NotPetya" `
            -Recommendation "Disable immediately: Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
    } else {
        Add-Finding -Category "SMB" -Check "SMBv1 Disabled" `
            -Severity Pass -Description "SMBv1 is disabled"
    }

    # SMB signing
    $smbSign = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smbSign -and -not $smbSign.RequireSecuritySignature) {
        Add-Finding -Category "SMB" -Check "SMB Signing Not Required" `
            -Severity High `
            -Description "SMB server does not REQUIRE security signatures (NTLM relay risk)" `
            -Recommendation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
    } else {
        Add-Finding -Category "SMB" -Check "SMB Signing Required" `
            -Severity Pass -Description "SMB signing is required"
    }

    # Null sessions
    $restrictNull = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue).RestrictNullSessAccess
    if ($restrictNull -eq 0) {
        Add-Finding -Category "SMB" -Check "Null Sessions Allowed" `
            -Severity High `
            -Description "Null session access to named pipes and shares is NOT restricted" `
            -Recommendation "Set RestrictNullSessAccess to 1 in registry"
    }
}

# ═══════════════════════════════════════════
# 5. SERVICES & DAEMONS
# ═══════════════════════════════════════════
if (-not $SkipServices) {
    Write-Host "`n=== SERVICES AUDIT ===" -ForegroundColor White

    $riskyServices = @(
        @{ Name = "RemoteRegistry"; Desc = "Remote Registry" },
        @{ Name = "TlntSvr"; Desc = "Telnet" },
        @{ Name = "SSDPSRV"; Desc = "SSDP Discovery" },
        @{ Name = "upnphost"; Desc = "UPnP Device Host" },
        @{ Name = "WMSvc"; Desc = "Web Management Service" },
        @{ Name = "SNMP"; Desc = "SNMP Service" },
        @{ Name = "TFTP"; Desc = "TFTP" },
        @{ Name = "ftpsvc"; Desc = "FTP Service" }
    )

    foreach ($svc in $riskyServices) {
        $service = Get-SafeService -Name $svc.Name
        if ($service -and $service.Status -eq "Running") {
            Add-Finding -Category "Services" -Check "$($svc.Desc) Running" `
                -Severity Medium `
                -Description "$($svc.Desc) service ($($svc.Name)) is running" `
                -Recommendation "Disable if not needed: Stop-Service $($svc.Name); Set-Service $($svc.Name) -StartupType Disabled"
        }
    }

    # Unquoted service paths (classic privesc)
    $unquoted = Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -and 
        $_.PathName -notmatch '^"' -and 
        $_.PathName -match '\s' -and 
        $_.PathName -notmatch 'system32' -and
        $_.StartMode -ne 'Disabled'
    }
    if ($unquoted) {
        Add-Finding -Category "Services" -Check "Unquoted Service Paths" `
            -Severity High `
            -Description "$($unquoted.Count) service(s) have unquoted paths with spaces (privilege escalation vector): $($unquoted.Name -join ', ')" `
            -Recommendation "Quote the path in the service registry or rename binaries to avoid spaces"
    }
}

# ═══════════════════════════════════════════
# 6. WINDOWS UPDATE STATUS
# ═══════════════════════════════════════════
if (-not $SkipUpdates) {
    Write-Host "`n=== WINDOWS UPDATE STATUS ===" -ForegroundColor White

    try {
        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue
        if ($hotfixes) {
            $lastUpdate = $hotfixes[0]
            $daysSince = (New-TimeSpan -Start $lastUpdate.InstalledOn -End (Get-Date)).Days
            
            if ($daysSince -gt 60) {
                Add-Finding -Category "Updates" -Check "Last Update: $daysSince days ago" `
                    -Severity High `
                    -Description "Last installed update was $daysSince days ago ($($lastUpdate.HotFixID))" `
                    -Recommendation "Install latest Windows Updates immediately"
            } elseif ($daysSince -gt 30) {
                Add-Finding -Category "Updates" -Check "Last Update: $daysSince days ago" `
                    -Severity Medium `
                    -Description "Last installed update was $daysSince days ago" `
                    -Recommendation "Schedule regular patching"
            } else {
                Add-Finding -Category "Updates" -Check "Updates Current" `
                    -Severity Pass `
                    -Description "Last update: $daysSince days ago ($($lastUpdate.HotFixID))"
            }
        } else {
            Add-Finding -Category "Updates" -Check "No Update History" `
                -Severity Info -Description "Could not retrieve update history" `
                -Recommendation "Check Windows Update settings manually"
        }
    } catch {
        Add-Finding -Category "Updates" -Check "Update Check Failed" `
            -Severity Info -Description "Unable to check update status: $_"
    }

    # Windows Update service
    $wuauserv = Get-SafeService -Name "wuauserv"
    if ($wuauserv -and $wuauserv.StartType -eq "Disabled") {
        Add-Finding -Category "Updates" -Check "Windows Update Disabled" `
            -Severity Critical `
            -Description "Windows Update service is disabled" `
            -Recommendation "Enable: Set-Service wuauserv -StartupType Automatic"
    }
}

# ═══════════════════════════════════════════
# 7. NETWORK CONFIGURATION
# ═══════════════════════════════════════════
if (-not $SkipNetwork) {
    Write-Host "`n=== NETWORK CONFIGURATION ===" -ForegroundColor White

    # Listening ports
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalPort, OwningProcess |
        Sort-Object LocalPort -Unique

    $riskyPorts = @(21, 23, 25, 135, 137, 138, 139, 445, 1433, 1434, 3306, 3389, 5900, 5985, 5986, 8080)
    $openRisky = $listeners | Where-Object { $_.LocalPort -in $riskyPorts }
    
    if ($openRisky) {
        $portList = ($openRisky | ForEach-Object { 
            $procName = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            "$($_.LocalPort) ($procName)"
        }) -join ", "
        
        Add-Finding -Category "Network" -Check "Sensitive Ports Open" `
            -Severity Medium `
            -Description "Potentially risky ports are listening: $portList" `
            -Recommendation "Close unnecessary ports. Restrict access via firewall rules."
    }

    # WinRM
    $winrm = Get-SafeService -Name "WinRM"
    if ($winrm -and $winrm.Status -eq "Running") {
        Add-Finding -Category "Network" -Check "WinRM Running" `
            -Severity Info `
            -Description "Windows Remote Management is active" `
            -Recommendation "Ensure HTTPS is used and authentication is restricted"
        
        # Check WinRM auth
        try {
            $winrmConfig = winrm get winrm/config/service 2>&1 | Out-String
            if ($winrmConfig -match "AllowUnencrypted = true") {
                Add-Finding -Category "Network" -Check "WinRM Unencrypted Traffic" `
                    -Severity High `
                    -Description "WinRM allows unencrypted traffic" `
                    -Recommendation "Disable: winrm set winrm/config/service @{AllowUnencrypted='false'}"
            }
        } catch {}
    }

    # DNS settings
    $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
    foreach ($int in $dns) {
        if ($int.ServerAddresses -and $int.ServerAddresses.Count -eq 0) {
            Add-Finding -Category "Network" -Check "No DNS Configured ($($int.InterfaceAlias))" `
                -Severity Info `
                -Description "Interface $($int.InterfaceAlias) has no DNS servers configured"
        }
    }
}

# ═══════════════════════════════════════════
# 8. SCHEDULED TASKS
# ═══════════════════════════════════════════
if (-not $SkipScheduledTasks) {
    Write-Host "`n=== SCHEDULED TASKS ===" -ForegroundColor White

    $suspiciousTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.State -ne "Disabled" -and (
            $_.Actions.Execute -match "powershell|cmd|wscript|cscript|mshta|certutil|bitsadmin" -or
            $_.TaskPath -match "\\Microsoft\\Windows\\"
        ) -and $_.TaskPath -notmatch "\\Microsoft\\Windows\\"
    }

    foreach ($task in $suspiciousTasks) {
        $action = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
        Add-Finding -Category "Scheduled Tasks" -Check "Suspicious Task: $($task.TaskName)" `
            -Severity Medium `
            -Description "Task '$($task.TaskName)' runs: $action" `
            -Recommendation "Verify this task is legitimate. Remove if unknown."
    }

    # Tasks running as SYSTEM
    $systemTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.Principal.UserId -eq "SYSTEM" -and $_.State -eq "Ready"
    }
    if ($systemTasks.Count -gt 30) {
        Add-Finding -Category "Scheduled Tasks" -Check "Many SYSTEM Tasks" `
            -Severity Info `
            -Description "$($systemTasks.Count) scheduled tasks run as SYSTEM" `
            -Recommendation "Audit periodically for unauthorized tasks"
    }
}

# ═══════════════════════════════════════════
# 9. AUDIT POLICY & LOGGING
# ═══════════════════════════════════════════
Write-Host "`n=== AUDIT POLICY ===" -ForegroundColor White

$secLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
if ($secLog) {
    if ($secLog.IsEnabled -eq $false) {
        Add-Finding -Category "Logging" -Check "Security Log Disabled" `
            -Severity Critical `
            -Description "Windows Security event log is DISABLED" `
            -Recommendation "Enable immediately: wevtutil sl Security /e:true"
    } else {
        $sizeMB = [math]::Round($secLog.MaximumSizeInBytes / 1MB, 0)
        if ($sizeMB -lt 100) {
            Add-Finding -Category "Logging" -Check "Security Log Too Small" `
                -Severity Medium `
                -Description "Security log max size is ${sizeMB}MB (recommended: 256MB+)" `
                -Recommendation "Increase: wevtutil sl Security /ms:268435456"
        } else {
            Add-Finding -Category "Logging" -Check "Security Log Size" `
                -Severity Pass `
                -Description "Security log max size: ${sizeMB}MB"
        }
    }
}

# ═══════════════════════════════════════════
# 10. DEFENDER / AV STATUS
# ═══════════════════════════════════════════
Write-Host "`n=== ANTIVIRUS STATUS ===" -ForegroundColor White

try {
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defender) {
        if (-not $defender.AntivirusEnabled) {
            Add-Finding -Category "Antivirus" -Check "Defender Disabled" `
                -Severity Critical `
                -Description "Windows Defender is DISABLED" `
                -Recommendation "Enable: Set-MpPreference -DisableRealtimeMonitoring `$false"
        } else {
            Add-Finding -Category "Antivirus" -Check "Defender Active" `
                -Severity Pass `
                -Description "Windows Defender is active. Signatures last updated: $($defender.AntivirusSignatureLastUpdated)"
        }

        if (-not $defender.RealTimeProtectionEnabled) {
            Add-Finding -Category "Antivirus" -Check "Real-Time Protection Off" `
                -Severity High `
                -Description "Real-time protection is DISABLED" `
                -Recommendation "Enable: Set-MpPreference -DisableRealtimeMonitoring `$false"
        }

        if ($defender.QuickScanAge -gt 7) {
            Add-Finding -Category "Antivirus" -Check "Scan Outdated ($($defender.QuickScanAge) days)" `
                -Severity Medium `
                -Description "Last quick scan was $($defender.QuickScanAge) days ago" `
                -Recommendation "Run: Start-MpScan -ScanType QuickScan"
        }
    }
} catch {
    Add-Finding -Category "Antivirus" -Check "AV Status Unknown" `
        -Severity Info -Description "Could not query Defender status"
}

# ═══════════════════════════════════════════
# GENERATE HTML REPORT
# ═══════════════════════════════════════════
Write-Host "`n=== GENERATING REPORT ===" -ForegroundColor White

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$reportFile = Join-Path $OutputPath "WinSecAudit-$Hostname-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"

# Count by severity
$critical = ($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
$high     = ($Findings | Where-Object { $_.Severity -eq "High" }).Count
$medium   = ($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
$low      = ($Findings | Where-Object { $_.Severity -eq "Low" }).Count
$info     = ($Findings | Where-Object { $_.Severity -eq "Info" }).Count
$pass     = ($Findings | Where-Object { $_.Severity -eq "Pass" }).Count
$total    = $Findings.Count

# Score calculation (100 minus penalty per finding)
$score = [math]::Max(0, 100 - ($critical * 15) - ($high * 8) - ($medium * 3) - ($low * 1))
$scoreColor = if ($score -ge 80) { "#4ade80" } elseif ($score -ge 60) { "#fbbf24" } elseif ($score -ge 40) { "#fb923c" } else { "#ef4444" }
$grade = if ($score -ge 90) { "A" } elseif ($score -ge 80) { "B" } elseif ($score -ge 70) { "C" } elseif ($score -ge 60) { "D" } else { "F" }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WinSecAudit - Security Audit Report - $Hostname</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 1.8rem; color: #f1f5f9; margin-bottom: 0.5rem; }
  h2 { font-size: 1.3rem; color: #94a3b8; margin: 2rem 0 1rem; border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem; }
  .meta { color: #64748b; font-size: 0.9rem; margin-bottom: 2rem; }
  .score-box { background: #1e293b; border-radius: 12px; padding: 2rem; text-align: center; margin-bottom: 2rem; }
  .score-number { font-size: 4rem; font-weight: 700; color: $scoreColor; }
  .score-label { font-size: 1rem; color: #94a3b8; }
  .grade { font-size: 2rem; color: $scoreColor; margin-top: 0.5rem; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center; }
  .stat-count { font-size: 2rem; font-weight: 700; }
  .stat-label { font-size: 0.8rem; color: #94a3b8; }
  .critical { color: #ef4444; } .high { color: #f97316; } .medium { color: #eab308; }
  .low { color: #a3a3a3; } .info { color: #38bdf8; } .pass { color: #4ade80; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }
  th { background: #1e293b; padding: 0.75rem; text-align: left; font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }
  td { padding: 0.75rem; border-bottom: 1px solid #1e293b; font-size: 0.9rem; vertical-align: top; }
  tr:hover { background: #1e293b40; }
  .severity-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .sev-critical { background: #7f1d1d; color: #fca5a5; }
  .sev-high { background: #7c2d12; color: #fdba74; }
  .sev-medium { background: #713f12; color: #fde047; }
  .sev-low { background: #3f3f46; color: #a1a1aa; }
  .sev-info { background: #0c4a6e; color: #7dd3fc; }
  .sev-pass { background: #14532d; color: #86efac; }
  .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #1e293b; color: #475569; font-size: 0.8rem; text-align: center; }
  .recommendation { color: #94a3b8; font-style: italic; font-size: 0.85rem; }
  @media print { body { background: white; color: #1e293b; } .score-box, .stat { background: #f1f5f9; } }
</style>
</head>
<body>
<div class="container">
  <h1>WinSecAudit - Security Audit Report</h1>
  <p class="meta">
    <strong>Host:</strong> $Hostname &nbsp;|&nbsp;
    <strong>OS:</strong> $OSVersion &nbsp;|&nbsp;
    <strong>Date:</strong> $AuditDate &nbsp;|&nbsp;
    <strong>Version:</strong> $ScriptVersion
  </p>

  <div class="score-box">
    <div class="score-label">Security Score</div>
    <div class="score-number">$score / 100</div>
    <div class="grade">Grade: $grade</div>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-count critical">$critical</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-count high">$high</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-count medium">$medium</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-count low">$low</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-count info">$info</div><div class="stat-label">Info</div></div>
    <div class="stat"><div class="stat-count pass">$pass</div><div class="stat-label">Pass</div></div>
  </div>

  <h2>Findings ($total total)</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Category</th><th>Check</th><th>Description</th><th>Recommendation</th></tr>
    </thead>
    <tbody>
$(
    $Findings | Sort-Object @{Expression={
        switch ($_.Severity) {
            "Critical" { 0 } "High" { 1 } "Medium" { 2 } "Low" { 3 } "Info" { 4 } "Pass" { 5 }
        }
    }} | ForEach-Object {
        $sevClass = "sev-$($_.Severity.ToLower())"
        "      <tr><td><span class=`"severity-badge $sevClass`">$($_.Severity)</span></td><td>$($_.Category)</td><td>$($_.Check)</td><td>$($_.Description)</td><td class=`"recommendation`">$($_.Recommendation)</td></tr>"
    }
)
    </tbody>
  </table>

  <div class="footer">
    Generated by WinSecAudit v$ScriptVersion | $AuditDate | Confidential - Internal Use Only
  </div>
</div>
</body>
</html>
"@

$html | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  WinSecAudit Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Score:      $score/100 (Grade: $grade)" -ForegroundColor $(if ($score -ge 70) { "Green" } else { "Yellow" })
Write-Host "  Findings:   $total total" -ForegroundColor White
Write-Host "    Critical: $critical" -ForegroundColor Red
Write-Host "    High:     $high" -ForegroundColor DarkYellow
Write-Host "    Medium:   $medium" -ForegroundColor Yellow
Write-Host "    Low:      $low" -ForegroundColor Gray
Write-Host "    Info:     $info" -ForegroundColor Cyan
Write-Host "    Pass:     $pass" -ForegroundColor Green
Write-Host "  Report:     $reportFile" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan

# Return findings object for pipeline use
return [PSCustomObject]@{
    Score       = $score
    Grade       = $grade
    Total       = $total
    Critical    = $critical
    High        = $high
    Medium      = $medium
    Low         = $low
    Info        = $info
    Pass        = $pass
    ReportPath  = $reportFile
    Findings    = $Findings
}
