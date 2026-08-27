# Lab Network Architecture & Topology

## Overview
This cyber range is deployed within an isolated **Host-Only Virtual Network (`192.168.56.0/24`)**. The environment isolates all adversarial traffic from the host workstation and external local area network (LAN), ensuring safe execution of malware simulations, port scanning, and credential spraying.

---

## Network Schematic

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

## IP Allocation & Virtual Machine Specifications

| Node Name | Operating System | Hostname | Assigned IP | RAM / CPU | Primary Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Offensive Node** | Kali Linux / Ubuntu | `attacker-node` | `192.168.56.20` | 4 GB / 2 vCPU | Executes adversary emulation scripts, password spraying, and network scans. |
| **Defensive Node** | Windows Server 2022 / Win 10 | `victim-dc01` | `192.168.56.10` | 4 GB / 2 vCPU | Target machine running Sysmon & Winlogbeat forwarder. |
| **SIEM Central Node** | Ubuntu Server 22.04 LTS | `siem-core` | `192.168.56.30` | 6 GB / 2 vCPU | Ingests, indexes, normalizes (ECS), and alerts on incoming telemetry. |

---

## Firewall & Traffic Flow Matrix

| Source Node | Destination Node | Destination Port | Protocol | Purpose / Description |
| :--- | :--- | :--- | :--- | :--- |
| `192.168.56.20` (Kali) | `192.168.56.10` (Windows) | `3389` | TCP | RDP Attack Simulation (MITRE T1110.003) |
| `192.168.56.20` (Kali) | `192.168.56.10` (Windows) | `445` / `139` | TCP | SMB Brute Force / Lateral Movement simulation |
| `192.168.56.20` (Kali) | `192.168.56.10` (Windows) | `5985` / `5986` | TCP | WinRM Remote Execution |
| `192.168.56.10` (Windows) | `192.168.56.30` (SIEM) | `5044` / `9200` | TCP | Winlogbeat / Logstash streaming endpoint logs |
| `192.168.56.10` (Windows) | `192.168.56.30` (SIEM) | `9997` | TCP | Splunk Universal Forwarder (if using Splunk) |
| Host Browser | `192.168.56.30` (SIEM) | `5601` / `8000` | TCP | Kibana Web UI / Splunk Web Dashboard Access |

---

## Security & Isolation Controls
1. **Host-Only Networking:** Adapter is attached exclusively to `VirtualBox Host-Only Ethernet Adapter` (`vboxnet0` on Linux/macOS).
2. **Promiscuous Mode:** Disabled on all adapters to prevent unauthorized packet sniffing outside designated monitoring taps.
3. **Snapshot Baseline:** Clean snapshots are taken before executing any simulation to enable zero-overhead rollback and repeatability.
