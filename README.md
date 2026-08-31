# 🛡️ Enterprise Cyber Range & Detection-as-Code (DaC) SIEM Lab

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14%20Enterprise-red.svg)](https://attack.mitre.org/)
[![Detection Engineering](https://img.shields.io/badge/Detection%20Engineering-Sigma%20Standard-blue.svg)](https://github.com/SigmaHQ/sigma)
[![Detection-as-Code](https://img.shields.io/badge/CI%2FCD-DaC%20Automated%20Tests%20Passing-brightgreen.svg)](.github/workflows/lint_and_validate.yaml)
[![Endpoint Telemetry](https://img.shields.io/badge/Telemetry-Sysmon%20v4.90%20%7C%20Winlogbeat-orange.svg)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![SIEM Platform](https://img.shields.io/badge/SIEM-Elasticsearch%208.x%20%7C%20Splunk%20Enterprise-purple.svg)](https://www.elastic.co/)
[![Threat Model](https://img.shields.io/badge/Methodology-STRIDE%20%7C%20D3FEND-informational.svg)](docs/threat_model.md)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade, virtualized **Adversary Emulation & SOC Detection Engineering Cyber Range**. This repository implements a full **Detection-as-Code (DaC)** lifecycle: simulating advanced threat actor techniques (APTs), capturing low-level endpoint telemetry (Microsoft Sysmon 4.90 & Windows Advanced Audit Policies), and authoring vendor-agnostic **Sigma** rules with automated unit test validation across **Elasticsearch (ECS)** and **Splunk (SPL)**.

---

## 📌 Executive Architecture & High-Level Design

```
   ┌───────────────────────────┐      ┌───────────────────────────┐      ┌───────────────────────────┐
   │ 1. Adversary Emulation    │      │ 2. Telemetry Engineering  │      │ 3. Detection & Analytics  │
   │ Kali Linux / Python Engine│ ───► │ Windows Target + Sysmon   │ ───► │ Elastic Stack / Splunk    │
   │ MITRE: T1110, T1059, T1003│      │ Event IDs: 4625, 4104, 10 │      │ Sigma Rules & DaC Testing │
   └───────────────────────────┘      └───────────────────────────┘      └───────────────────────────┘
```

The cyber range is deployed in an isolated **Host-Only Virtual Subnet (`192.168.56.0/24`)**, fully isolating offensive simulations from external networks while preserving high-fidelity forensic data streams.

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 Workstation Host OS                    │
                  │             (VirtualBox / VMware Engine)               │
                  └──────────────────────────┬─────────────────────────────┘
                                             │
             ┌───────────────────────────────┴──────────────────────────────┐
             │         Isolated Host-Only Virtual Switch (192.168.56.0/24)   │
             └──────┬────────────────────────┬────────────────────────┬─────┘
                    │                        │                        │
                    ▼                        ▼                        ▼
     ┌────────────────────────┐┌────────────────────────┐┌────────────────────────┐
     │  Attacker Node (Kali)  ││ Target Node (WinServer)││ SIEM Node (Ubuntu/ELK) │
     │  IP: 192.168.56.20     ││ IP: 192.168.56.10      ││ IP: 192.168.56.30      │
     │  - Python Attack Sim   ││ - Windows Event Logs   ││ - Elasticsearch Engine │
     │  - Hydra / Nmap        ││ - Sysmon (SwiftOnSec)  ││ - Kibana Dashboards    │
     │  - Metasploit Stagers  ││ - Winlogbeat Shipper   ││ - Splunk Enterprise    │
     └────────────────────────┘└────────────────────────┘└────────────────────────┘
                    │                        │                        ▲
                    │   Malicious Traffic    │                        │
                    └───────────────────────►│  Shipped Telemetry     │
                                             │  (Port 5044/9200)      │
                                             └────────────────────────┘
```

---

## 🎯 MITRE ATT&CK Matrix & Detection Coverage

| Technique ID | Technique Name | Tactic | Emulation Script | Telemetry Channel & Event ID | Detection Rule |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`T1110.003`** | Password Spraying | Credential Access | [`brute_force_simulator.py`](attack-payloads/brute_force_simulator.py) | Security Channel `4625` (LogonType 3/10) | [`rdp_brute_force.yaml`](detection-rules/rdp_brute_force.yaml) |
| **`T1059.001`** | PowerShell (Encoded) | Execution | [`powershell_obfuscation.py`](attack-payloads/powershell_obfuscation.py) | Sysmon `1` & PowerShell `4104` | [`suspicious_powershell_process.yaml`](detection-rules/suspicious_powershell_process.yaml) & [`suspicious_powershell_scriptblock.yaml`](detection-rules/suspicious_powershell_scriptblock.yaml) |
| **`T1003.001`** | LSASS Memory Dumping | Credential Access | [`credential_dump_simulator.py`](attack-payloads/credential_dump_simulator.py) | Sysmon `10` (`Target: lsass.exe`) | [`lsass_access_attempt.yaml`](detection-rules/lsass_access_attempt.yaml) |
| **`T1547.001`** | Registry Run Keys | Persistence | [`persistence_simulator.py`](attack-payloads/persistence_simulator.py) | Sysmon `12` / `13` & Security `4698` | Sysmon Registry Monitor |
| **`T1070.001`** | Clear Windows Event Logs | Defense Evasion | [`log_clearing_simulator.py`](attack-payloads/log_clearing_simulator.py) | Security `1102` / `104` | Event Log Clear Alert |

> [!TIP]
> Import [`network-architecture/mitre_attack_navigator_layer.json`](network-architecture/mitre_attack_navigator_layer.json) directly into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize the interactive coverage layer.

---

## 🔬 Deep-Dive Detection Playbooks

### Playbook 1: RDP & SMB Password Spraying (`T1110.003`)
* **Adversary Emulation:** Executes throttled authentication attempts against the domain controller, cycling common password dictionaries with random jitter delays to evade naive rate-limiting.
* **Forensic Schema:**
  | Field Name | Forensic Value / Meaning |
  | :--- | :--- |
  | `EventCode` | `4625` (An account failed to log on) |
  | `LogonType` | `3` (Network / SMB) or `10` (Remote Interactive / RDP) |
  | `SubStatus` | `0xC000006A` (Bad Password) vs `0xC0000064` (User Does Not Exist) |
* **Splunk Risk-Based Alert (SPL):**
  ```spl
  index=winlogbeat sourcetype="WinEventLog:Security" EventCode=4625 (Logon_Type=3 OR Logon_Type=10)
  | bin _time span=5m
  | stats count as failures, values(TargetUserName) as target_users by _time, Source_Network_Address, Logon_Type
  | where failures > 4
  | eval risk_score = case(failures > 20, 100, failures > 10, 75, true(), 50)
  | table _time, Source_Network_Address, target_users, failures, risk_score
  ```

---

### Playbook 2: Obfuscated PowerShell Execution (`T1059.001` / `T1027`)
* **Adversary Emulation:** Invocations using `-EncodedCommand` with UTF-16LE Base64 blobs attempting download cradle simulation.
* **Forensic Schema:** Sysmon Event ID `1` (Process Creation) and PowerShell Event ID `4104` (Script Block Logging).
* **Elasticsearch KQL Query:**
  ```kql
  (process.name: "powershell.exe" or process.name: "pwsh.exe") and 
  (process.command_line: *"-enc"* or process.command_line: *"-encodedcommand"* or process.command_line: *"downloadstring"*)
  ```

---

### Playbook 3: LSASS Process Access & Credential Harvesting (`T1003.001`)
* **Adversary Emulation:** Simulates credential dumping handles targeting `lsass.exe` using `MiniDumpWriteDump` access masks.
* **Forensic Schema:** Sysmon Event ID `10` (`ProcessAccess` with `GrantedAccess: 0x1010` / `0x1F0FFF`).
* **Splunk SPL Query:**
  ```spl
  index=winlogbeat sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe"
  | search NOT (SourceImage="*\\svchost.exe" OR SourceImage="*\\csrss.exe" OR SourceImage="*\\MsMpEng.exe")
  | table _time, host, SourceImage, TargetImage, GrantedAccess, CallTrace
  ```

---

## ⚙️ Detection-as-Code (DaC) Automated CI/CD Pipeline

To ensure enterprise-level code quality and zero alert regression, all detection rules and emulation scripts are validated automatically:

```bash
# Run unit tests across all detection rules and mock telemetry fixtures
python tests/test_detection_rules.py
```

```
....
----------------------------------------------------------------------
Ran 4 tests in 0.007s

OK (Schema validity, True Positive logic, and False Positive filters verified)
```

---

## 🚀 Rapid Lab Deployment

### 1. Provision SIEM Server (Ubuntu 22.04 LTS - `192.168.56.30`)
```bash
cd siem-server/
docker compose up -d
# Access Kibana SOC Dashboard: http://192.168.56.30:5601
# Access Splunk Enterprise: http://192.168.56.30:8000 (admin:admin123)
```

### 2. Provision Windows Defensive Node (`192.168.56.10`)
Run the automated PowerShell deployment script in an Administrator console (this will install Sysmon and Winlogbeat):
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\telemetry-config\deploy-telemetry.ps1 -SiemServer "192.168.56.30"
```

### 3. Launch Adversary Emulation Suite (`192.168.56.20`)
```bash
# Run emulation and stream Ground-Truth execution logs to Elasticsearch for MTTD correlation
python3 attack-payloads/run_simulation_suite.py --target 192.168.56.10 --siem-url http://192.168.56.30:9200
```

---

## 📚 Technical Documentation Library

- 📖 [Enterprise Threat Model (STRIDE + D3FEND)](docs/threat_model.md)
- 📖 [Detection Engineering Standard Operating Procedure (SOP)](docs/detection_engineering_standard.md)
- 📖 [SOC Incident Response Runbook (NIST SP 800-61r2)](docs/incident_response_runbook.md)
- 📖 [Stage 1: Lab Infrastructure Setup](docs/stage1_lab_infrastructure.md)
- 📖 [Stage 2: Defensive Endpoint Configuration](docs/stage2_windows_target_setup.md)
- 📖 [Stage 3: Ubuntu SIEM Node Deployment](docs/stage3_ubuntu_siem_setup.md)
- 📖 [Stage 4: Attack Execution & Detection Playbooks](docs/stage4_attack_detection_playbooks.md)
- ☁️ [AWS Cloud Cyber Range Deployment Guide](docs/cloud_deployment_aws.md)
- ☁️ [Azure Sentinel Cloud Cyber Range Deployment Guide](docs/cloud_deployment_azure.md)

---

## 📈 Demonstrated Senior Cybersecurity Competencies

- **Object-Oriented Adversary Emulation:** Engineered a modular Python emulation framework with extensible base classes (`BaseAdversaryTechnique`) for scalable mapping to MITRE ATT&CK.
- **Detection-as-Code (DaC):** Unit testing and continuous validation of Sigma detection rules against synthetic JSON telemetry within GitHub Actions CI/CD pipelines.
- **Enterprise Telemetry Engineering:** Authored high-signal, low-noise Sysmon 4.90 XML schemas, Windows Audit GPO policies, and robust Winlogbeat log forwarding pipelines.
- **Threat Modeling & Risk Quantification:** STRIDE decomposition, MITRE D3FEND alignment, and continuous MTTD/MTTR operational benchmarks via dynamic SIEM telemetry streaming.
- **Full-Spectrum Incident Response:** Authored NIST SP 800-61r2 triage runbooks and Splunk risk-scoring correlation rules.

---

## 📜 License
This project is open-source under the [MIT License](LICENSE). Built for defensive cybersecurity research and detection engineering education.
