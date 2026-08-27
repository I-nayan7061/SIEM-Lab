# Stage 4: Attack, Detect, and Document Playbooks

This guide details the complete operational lifecycle: launching adversarial attacks from the Offensive Node, capturing host telemetry, and alerting inside the SIEM dashboard.

---

## Playbook 1: RDP & SMB Password Spraying (MITRE ATT&CK T1110.003)

### 1. Attack Execution (From Kali / Offensive Node)
Run the automated brute-force simulator:
```bash
python3 attack-payloads/brute_force_simulator.py --target 192.168.56.10 --user Administrator --delay 2.0
```

### 2. Telemetry Captured (Windows Defensive Target)
- **Channel:** `Security`
- **Event ID:** `4625` (An account failed to log on)
- **Key Fields:**
  - `LogonType`: `3` (Network) or `10` (Remote Interactive / RDP)
  - `TargetUserName`: `Administrator`
  - `IpAddress`: `192.168.56.20`
  - `Status`: `0xC000006D` (Bad password / user mismatch)

### 3. Detection Engineering (SIEM Alert Logic)
- **Sigma Rule:** [`detection-rules/rdp_brute_force.yaml`](../detection-rules/rdp_brute_force.yaml)
- **Splunk SPL Query:**
  ```spl
  index=winlogbeat sourcetype="WinEventLog:Security" EventCode=4625 (Logon_Type=3 OR Logon_Type=10)
  | stats count as failures, values(TargetUserName) as targets by Source_Network_Address
  | where failures > 4
  ```
- **Kibana KQL Query:**
  ```kql
  winlog.channel: "Security" and winlog.event_id: 4625 and winlog.event_data.LogonType: ("3" or "10")
  ```

---

## Playbook 2: Encoded & Obfuscated PowerShell Execution (MITRE ATT&CK T1059.001)

### 1. Attack Execution
Run the PowerShell obfuscation simulator:
```bash
python3 attack-payloads/powershell_obfuscation.py
```

### 2. Telemetry Captured
- **Channel:** `Microsoft-Windows-PowerShell/Operational` (Event ID `4104`) & `Microsoft-Windows-Sysmon/Operational` (Event ID `1`)
- **Key Fields:**
  - `CommandLine`: Contains `-EncodedCommand`, `-enc`, `downloadstring`
  - `ScriptBlockText`: De-obfuscated script block content recorded in memory

### 3. Detection Engineering
- **Sigma Rule:** [`detection-rules/suspicious_powershell.yaml`](../detection-rules/suspicious_powershell.yaml)
- **Splunk SPL Query:**
  ```spl
  index=winlogbeat (EventCode=1 OR EventCode=4688) (CommandLine="*-enc*" OR CommandLine="*downloadstring*")
  | table _time, host, User, Image, CommandLine
  ```

---

## Playbook 3: LSASS Memory Access & Credential Dumping (MITRE ATT&CK T1003.001)

### 1. Attack Execution
Run the credential dump simulator:
```bash
python3 attack-payloads/credential_dump_simulator.py
```

### 2. Telemetry Captured
- **Channel:** `Microsoft-Windows-Sysmon/Operational`
- **Event ID:** `10` (ProcessAccess)
- **Key Fields:**
  - `TargetImage`: `C:\Windows\System32\lsass.exe`
  - `GrantedAccess`: `0x1010` or `0x1F0FFF` (High privilege handle access)

### 3. Detection Engineering
- **Sigma Rule:** [`detection-rules/lsass_access_attempt.yaml`](../detection-rules/lsass_access_attempt.yaml)
- **Splunk SPL Query:**
  ```spl
  index=winlogbeat EventCode=10 TargetImage="*\\lsass.exe" NOT (SourceImage="*\\svchost.exe")
  | table _time, host, SourceImage, TargetImage, GrantedAccess
  ```
