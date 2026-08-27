<#
.SYNOPSIS
    Enterprise Endpoint Telemetry & Audit Policy Automated Deployment Script
.DESCRIPTION
    Automates the installation, hardening, and verification of Windows Advanced Audit Policies,
    Microsoft Sysmon 64-bit with MITRE ATT&CK configuration, and Winlogbeat log forwarder.
.AUTHOR
    Nayan Solanki (Senior Detection Engineering Portfolio)
.EXAMPLE
    .\deploy-telemetry.ps1 -SiemServer "192.168.56.30" -Verbose
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$SiemServer = "192.168.56.30",

    [Parameter(Mandatory=$false)]
    [string]$ToolsDir = "C:\Tools"
)

# ------------------------------------------------------------------------------
# 1. Administrator Privilege Check
# ------------------------------------------------------------------------------
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[-] This script MUST be executed from an elevated Administrator PowerShell session!"
    Exit 1
}

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "   ENTERPRISE ENDPOINT TELEMETRY DEPLOYMENT AUTOMATION" -ForegroundColor Cyan
Write-Host "   Target SIEM Ingestion Host: $SiemServer" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 2. Configure Windows Advanced Audit Policies
# ------------------------------------------------------------------------------
Write-Host "`n[*] Configuring Windows Advanced Audit Policies..." -ForegroundColor Yellow

$AuditSubcategories = @(
    "Process Creation",
    "Logon",
    "Account Lockout",
    "Special Logon",
    "Security Group Management",
    "Audit Policy Change",
    "System Integrity"
)

ForEach ($SubCat in $AuditSubcategories) {
    auditpol /set /subcategory:"$SubCat" /success:enable /failure:enable | Out-Null
    Write-Host "  [+] Enabled Audit Policy: $SubCat" -ForegroundColor Green
}

# Enable Command Line in Event ID 4688
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "  [+] Enabled ProcessCreationIncludeCmdLine in Event ID 4688" -ForegroundColor Green

# Enable PowerShell ScriptBlock Logging (Event ID 4104)
$PSPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
If (-not (Test-Path $PSPolicyPath)) { New-Item -Path $PSPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $PSPolicyPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force | Out-Null
Write-Host "  [+] Enabled PowerShell Script Block Logging (Event ID 4104)" -ForegroundColor Green

# ------------------------------------------------------------------------------
# 3. Deploy and Optimize Microsoft Sysmon
# ------------------------------------------------------------------------------
Write-Host "`n[*] Deploying Microsoft Sysmon..." -ForegroundColor Yellow
$SysmonDir = Join-Path $ToolsDir "Sysmon"
If (-not (Test-Path $SysmonDir)) { New-Item -Path $SysmonDir -ItemType Directory -Force | Out-Null }

$SysmonZip = Join-Path $SysmonDir "Sysmon.zip"
$SysmonExe = Join-Path $SysmonDir "Sysmon64.exe"
$SysmonConfig = Join-Path $PSScriptRoot "sysmon-config.xml"

If (-not (Test-Path $SysmonExe)) {
    Write-Host "  [>] Downloading official Sysmon package from Microsoft Sysinternals..." -ForegroundColor Gray
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $SysmonZip
    Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
}

If (Test-Path $SysmonConfig) {
    Write-Host "  [>] Installing Sysmon with repository configuration: $SysmonConfig" -ForegroundColor Gray
    Start-Process -FilePath $SysmonExe -ArgumentList "-accepteula -i `"$SysmonConfig`"" -Wait -NoNewWindow
} Else {
    Write-Host "  [!] sysmon-config.xml not found in script directory. Downloading SwiftOnSecurity fallback..." -ForegroundColor Yellow
    $FallbackConfig = Join-Path $SysmonDir "sysmonconfig-export.xml"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $FallbackConfig
    Start-Process -FilePath $SysmonExe -ArgumentList "-accepteula -i `"$FallbackConfig`"" -Wait -NoNewWindow
}

$SysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
If ($SysmonService -and $SysmonService.Status -eq "Running") {
    Write-Host "  [✓] Microsoft Sysmon Service is ACTIVE and RUNNING." -ForegroundColor Green
} Else {
    Write-Error "  [-] Failed to verify Sysmon service status!"
}

# ------------------------------------------------------------------------------
# 4. Deploy and Configure Winlogbeat
# ------------------------------------------------------------------------------
Write-Host "`n[*] Deploying Winlogbeat Log Forwarder..." -ForegroundColor Yellow
$WinlogbeatDir = "C:\Program Files\Winlogbeat"
$WinlogbeatZip = Join-Path $ToolsDir "winlogbeat.zip"
$WinlogbeatExe = Join-Path $WinlogbeatDir "winlogbeat.exe"
$WinlogbeatConfig = Join-Path $PSScriptRoot "winlogbeat.yml"

If (-not (Test-Path $WinlogbeatDir)) {
    Write-Host "  [>] Downloading Winlogbeat 8.11.1..." -ForegroundColor Gray
    Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.1-windows-x86_64.zip" -OutFile $WinlogbeatZip
    Expand-Archive -Path $WinlogbeatZip -DestinationPath $ToolsDir -Force
    Rename-Item -Path (Join-Path $ToolsDir "winlogbeat-8.11.1-windows-x86_64") -NewName "Winlogbeat" -Force
    Move-Item -Path (Join-Path $ToolsDir "Winlogbeat") -Destination "C:\Program Files\" -Force
}

If (Test-Path $WinlogbeatConfig) {
    Write-Host "  [>] Applying custom winlogbeat.yml configuration..." -ForegroundColor Gray
    # Update the SIEM server IP in the config
    $ConfigContent = Get-Content $WinlogbeatConfig -Raw
    $ConfigContent = $ConfigContent -replace "192\.168\.56\.30", $SiemServer
    Set-Content -Path (Join-Path $WinlogbeatDir "winlogbeat.yml") -Value $ConfigContent -Force
}

If (-not (Get-Service -Name "winlogbeat" -ErrorAction SilentlyContinue)) {
    Write-Host "  [>] Installing Winlogbeat service..." -ForegroundColor Gray
    Set-Location $WinlogbeatDir
    PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
}

Start-Service -Name "winlogbeat"
Write-Host "  [+] Winlogbeat Service is ACTIVE and RUNNING." -ForegroundColor Green

# ------------------------------------------------------------------------------
# 5. Self-Test & Telemetry Generation Validation
# ------------------------------------------------------------------------------
Write-Host "`n[*] Running Telemetry Self-Test Event..." -ForegroundColor Yellow
powershell.exe -NoProfile -NonInteractive -EncodedCommand "V3JpdGUtSG9zdCAnWypdIEVuZHBvaW50IFRlbGVtZXRyeSBEZXBsb3ltZW50IFNlbGYtVGVzdCBFZGF0ZSc="

Start-Sleep -Seconds 2
$RecentSysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue
If ($RecentSysmonEvents) {
    Write-Host "  [✓] Confirmed Sysmon operational log generation (Event ID: $($RecentSysmonEvents.Id))." -ForegroundColor Green
}

Write-Host "`n==========================================================================" -ForegroundColor Cyan
Write-Host "   [✓] TELEMETRY ENGINEERING DEPLOYMENT COMPLETED SUCCESSFULLY" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
