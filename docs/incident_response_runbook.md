# SOC Analyst Incident Response Runbook

**Author:** Nayan Solanki (Senior Detection Engineering Portfolio)  
**Standard:** NIST SP 800-61 Rev. 2 / SANS Incident Handling Framework  

---

## 🚨 Alert Runbook 01: Multiple Failed Logons / RDP Brute Force (`T1110.003`)

### 1. Initial Triage & Investigation
1. **Verify Alert Source:**
   - Confirm Source IP `Source_Network_Address` from Event 4625.
   - Check `SubStatus` code:
     - `0xC000006A`: Bad password (indicates credential guessing attempt).
     - `0xC0000064`: User name does not exist (indicates username enumeration).
     - `0xC0000072`: Account is disabled.
2. **Check for Subsequent Success (Event ID 4624):**
   ```spl
   index=winlogbeat sourcetype="WinEventLog:Security" EventCode=4624 Source_Network_Address="<Attacker_IP>"
   ```
   *If successful logon occurs immediately following failures, elevate incident to CRITICAL.*

### 2. Containment Actions
- Block `Source_Network_Address` at perimeter firewall / Windows Defender Firewall.
- If target account compromised, invoke immediate Active Directory password reset and revoke active Kerberos TGT tickets.

### 3. Eradication & Recovery
- Audit all logon sessions established during the attack timeframe.
- Restore account status and enforce Multi-Factor Authentication (MFA).

---

## 🚨 Alert Runbook 02: Obfuscated PowerShell Execution (`T1059.001`)

### 1. Initial Triage & Investigation
1. Retrieve full `CommandLine` and de-obfuscate Base64 UTF-16LE payload:
   ```bash
   echo "<Base64_String>" | base64 -d | iconv -f UTF-16LE -t UTF-8
   ```
2. Correlate with Sysmon Event ID 1 (Parent Process) to identify execution parent (`cmd.exe`, `w3wp.exe`, `explorer.exe`).
3. Check Sysmon Event ID 3 for outbound C2 network connections established by the spawned `powershell.exe`.

### 2. Containment Actions
- Terminate malicious process tree using EDR / PowerShell:
  ```powershell
  Stop-Process -Id <Target_PID> -Force
  ```
- Isolate affected endpoint from network segment.

---

## 🚨 Alert Runbook 03: LSASS Memory Dump & Process Access (`T1003.001`)

### 1. Initial Triage & Investigation
1. Inspect `SourceImage` and `SourceProcessGuid` from Sysmon Event 10.
2. Check `GrantedAccess` bitmask:
   - `0x1010`: `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`
   - `0x1F0FFF`: `PROCESS_ALL_ACCESS`
3. Check Sysmon Event ID 11 for `.dmp` file creations in `C:\Windows\Temp` or `%LOCALAPPDATA%\Temp`.

### 2. Containment Actions
- Immediately isolate the host from Active Directory domain network.
- Force enterprise-wide password reset for all Domain Admins logged into that host within the past 48 hours (Credential Harvester Containment).
- Collect forensic memory image for volatility analysis.
