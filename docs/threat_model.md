# Enterprise Threat Model & Attack Surface Analysis

**Author:** Nayan Solanki (Senior Detection Engineering Portfolio)  
**Methodology:** STRIDE + MITRE ATT&CK + MITRE D3FEND  
**Target Environment:** Hybrid Enterprise Active Directory & Endpoint Infrastructure

---

## 1. Executive Summary & Scope
This threat model evaluates the threat landscape for corporate Windows endpoints, Active Directory domain controllers, and centralized log aggregation infrastructure. The objective is to identify potential threat vectors, determine telemetry blind spots, and validate defensive countermeasures across the cyber kill chain.

---

## 2. Threat Actor Profiles & Motivations

| Threat Actor Profile | Motivation | Tactics & Techniques Observed | In-Scope Vectors |
| :--- | :--- | :--- | :--- |
| **Financial Cybercrime (e.g., FIN7, LockBit)** | Ransomware, extortion, data theft | Initial access via password spraying (`T1110.003`), living-off-the-land binaries (`T1218`), credential harvesting (`T1003.001`). | RDP Brute Force, LSASS Memory Dumping, PowerShell Cradles |
| **Advanced Persistent Threat (e.g., APT29, Cozy Bear)** | Espionage, intelligence gathering, long-term persistence | Stealthy living-off-the-land scripts (`T1059.001`), obfuscated memory injection (`T1027`), event log suppression (`T1070.001`). | Base64 Encoded PowerShell, Registry Autostarts |
| **Insider Threat / Rogue Admin** | Privilege abuse, data exfiltration | Abuse of administrative protocols (`WinRM`, `SMB`), bypassing change controls. | Unauthorized handle inspection, account creation |

---

## 3. STRIDE Threat Analysis Matrix

```
                      ┌────────────────────────────────────────────────────────┐
                      │                   STRIDE Assessment                    │
                      └──────────────────────────┬─────────────────────────────┘
                                                 │
          ┌──────────────────┬───────────────────┼───────────────────┬──────────────────┐
          ▼                  ▼                   ▼                   ▼                  ▼
   [Spoofing]         [Tampering]        [Repudiation]       [Info Disclosure]    [Elevation]
  Password Spray    Registry Run Key     Log Clearing          LSASS Dumping    Encoded Scripts
   (T1110.003)        (T1547.001)         (T1070.001)           (T1003.001)       (T1059.001)
```

| STRIDE Category | Threat Scenario | Attack Vector & MITRE ID | Defensive Countermeasure (D3FEND) |
| :--- | :--- | :--- | :--- |
| **Spoofing Identity** | Adversary attempts credential stuffing against RDP/SMB. | `T1110.003` (Password Spraying) | **D3-LAM** (Logon Account Monitoring), Event 4625 Correlation. |
| **Tampering with Data** | Malicious binary configures autostart persistence key. | `T1547.001` (Registry Run Keys) | **D3-RRA** (Registry Rule Auditing), Sysmon Event 12/13. |
| **Repudiation** | Attacker invokes `wevtutil` to clear forensic tracks. | `T1070.001` (Event Log Clearing) | Real-time log forwarding via Winlogbeat before local clearing, Event 1102 alert. |
| **Information Disclosure**| Unprivileged/elevated process dumps LSASS process memory. | `T1003.001` (LSASS Memory) | **D3-PMA** (Process Memory Access Monitoring), Sysmon Event 10. |
| **Elevation of Privilege**| Obfuscated PowerShell execution bypasses AMSI/script policies.| `T1059.001` (PowerShell) | Script Block Logging (Event 4104), Constrained Language Mode. |

---

## 4. Telemetry Gap Analysis & Engineering Controls

1. **Blind Spot:** Standard Windows Event Logs omit the full command-line string in Event 4688.
   - **Mitigation:** Applied GPO / Registry policy `ProcessCreationIncludeCmdLine_Enabled = 1`.
2. **Blind Spot:** High-privilege in-memory DLL injection without spawning child processes.
   - **Mitigation:** Deployed Microsoft Sysmon with Event ID 8 (`CreateRemoteThread`) and Event ID 10 (`ProcessAccess`).
3. **Blind Spot:** Attacker wiping local logs before incident responders connect.
   - **Mitigation:** Configured asynchronous, real-time memory buffer streaming in Winlogbeat directly to Elasticsearch.
