# Windows Defensive Endpoint Setup Guide: Sysmon & Telemetry Engineering

This guide provides the exact terminal commands required to configure the Windows Target VM (`192.168.56.10`) with deep endpoint logging.

---

## Step 1: Enable Enhanced Windows Advanced Audit Policies

Open **PowerShell as Administrator** and execute:

```powershell
# 1. Enable Detailed Process Creation Logging (Event ID 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# 2. Enable Command-Line in Process Creation Events (Crucial for SOC analysts!)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force

# 3. Enable Logon & Account Failure Auditing (Event ID 4625)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# 4. Enable PowerShell Script Block Logging (Event ID 4104)
$PSLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
If (!(Test-Path $PSLoggingPath)) { New-Item -Path $PSLoggingPath -Force }
Set-ItemProperty -Path $PSLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
```

---

## Step 2: Install Microsoft Sysmon with Custom Rules

```powershell
# Create dedicated directory
New-Item -Path "C:\Tools\Sysmon" -ItemType Directory -Force
Set-Location "C:\Tools\Sysmon"

# Download Sysmon from Microsoft Sysinternals
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "." -Force

# Copy our repository sysmon-config.xml or download SwiftOnSecurity baseline
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"

# Install Sysmon 64-bit service with configuration
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify Sysmon service status
Get-Service -Name "Sysmon64"
```

---

## Step 3: Install and Configure Winlogbeat Telemetry Shipper

```powershell
# Create tools directory
New-Item -Path "C:\Tools\Winlogbeat" -ItemType Directory -Force
Set-Location "C:\Tools\Winlogbeat"

# Download Winlogbeat 8.x
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.1-windows-x86_64.zip" -OutFile "winlogbeat.zip"
Expand-Archive -Path "winlogbeat.zip" -DestinationPath "C:\Tools" -Force
Rename-Item -Path "C:\Tools\winlogbeat-8.11.1-windows-x86_64" -NewName "Winlogbeat"

# Copy repository winlogbeat.yml configuration to C:\Tools\Winlogbeat\winlogbeat.yml
# Then test configuration:
.\winlogbeat.exe test config -c winlogbeat.yml

# Install Winlogbeat as a persistent Windows Service
powershell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1

# Start the shipper service
Start-Service winlogbeat
Get-Service winlogbeat
```

---

## Step 4: Verification of Telemetry Generation

Trigger a test process to confirm Sysmon captures it:

```powershell
# Launch an encoded PowerShell command to test Event ID 1 / 4104
powershell.exe -enc "V3JpdGUtSG9zdCAnWypdIFN5c21vbiBUZXN0IEV2ZW50IEdlbmVyYXRlZCc="

# Query the most recent 3 Sysmon events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 | Format-List TimeCreated, Id, Message
```
