# WinSecAudit - Windows Server Security Audit Tool

A comprehensive PowerShell-based security audit tool for Windows Server environments. Run it, get a professional HTML report with actionable findings in seconds.

## What It Checks (50+ checks across 10 categories)

- **Password & Account Policy** — min length, expiry, guest account, admin count
- **Windows Firewall** — profile status, overly permissive rules
- **RDP Security** — NLA, default port, exposure
- **SMB Configuration** — SMBv1 (WannaCry vector), signing, null sessions
- **Services & Daemons** — risky services, unquoted service paths (privesc)
- **Windows Update** — last patch date, service status
- **Network Configuration** — listening ports, WinRM, DNS
- **Scheduled Tasks** — suspicious tasks, SYSTEM tasks
- **Audit & Logging** — security log size, audit policy
- **Antivirus** — Defender status, real-time protection, scan age

## Output

- Professional dark-themed HTML report
- Security score (0-100) with letter grade (A-F)
- Severity-ranked findings: Critical, High, Medium, Low, Info, Pass
- Each finding includes: description, evidence, and remediation recommendation
- Print-friendly CSS for PDF export

## Usage

```powershell
# Basic scan with default output (.\WinSecAudit-Reports\)
.\Invoke-WinSecAudit.ps1

# Custom output directory
.\Invoke-WinSecAudit.ps1 -OutputPath "C:\SecurityReports"

# Skip specific categories
.\Invoke-WinSecAudit.ps1 -SkipNetwork -SkipScheduledTasks

# Quiet mode (no console output, just generates report)
.\Invoke-WinSecAudit.ps1 -Quiet
```

## Requirements

- Windows Server 2016+ (also works on Windows 10/11)
- PowerShell 5.1+ (built-in on all supported Windows)
- Run as Administrator for full results
- No external modules required — pure PowerShell

## What You Get

- `Invoke-WinSecAudit.ps1` — The main audit script
- `README.md` — This file
- `EXAMPLE-REPORT.html` — Sample report output

## Pricing

- **Single Server License**: $19
- **Unlimited Internal Use**: $49
- Includes 6 months of updates

## Support

Email: [your email] | Issues via Gumroad messaging

## License

Commercial — Single organization use. See LICENSE file.
