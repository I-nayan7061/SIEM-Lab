# Stage 2: Defensive Endpoint Configuration (Windows Target)

## Objective
Harden and instrument the Windows target machine (`192.168.56.10`) with deep visibility audit policies, Sysmon, and Winlogbeat to capture adversarial actions.

---

## 1. Static IP Configuration
Open **PowerShell (Administrator)**:
```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.10 -PrefixLength 24 -DefaultGateway 192.168.56.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("8.8.8.8","1.1.1.1")
```

---

## 2. Advanced Security Audit Policy Configuration
Ensure Windows records high-fidelity forensic events:
```powershell
# Detailed Tracking
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable

# Account Logon and Authentication
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# Privilege Use & System Changes
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# Include Command Line in Event 4688
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force
```

---

## 3. Sysmon Installation & Optimization
```powershell
mkdir C:\Tools\Sysmon -Force
cd C:\Tools\Sysmon

Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "." -Force

# Use the repository XML configuration
.\Sysmon64.exe -accepteula -i ..\..\telemetry-config\sysmon-config.xml

# Check running status
Get-Service Sysmon64
```

---

## 4. Winlogbeat Forwarder Setup
```powershell
mkdir C:\Tools\Winlogbeat -Force
cd C:\Tools\Winlogbeat

Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.1-windows-x86_64.zip" -OutFile "winlogbeat.zip"
Expand-Archive -Path "winlogbeat.zip" -DestinationPath "C:\Tools\" -Force
Move-Item "C:\Tools\winlogbeat-8.11.1-windows-x86_64\*" "C:\Tools\Winlogbeat\" -Force

# Copy your customized winlogbeat.yml here
# Test configuration syntax and connectivity
.\winlogbeat.exe test config -c winlogbeat.yml
.\winlogbeat.exe test output -c winlogbeat.yml

# Register service and start
powershell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
Start-Service winlogbeat
```
