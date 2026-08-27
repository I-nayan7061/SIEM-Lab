# Cloud Deployment Guide: Microsoft Azure & Microsoft Sentinel

Deploying this lab in **Microsoft Azure** showcases native cloud SIEM capabilities (**Microsoft Sentinel**) and Log Analytics Workspace engineering.

---

## Azure Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │              Azure VNet                │
                      │          (172.16.0.0/16)               │
                      └──────────────────┬─────────────────────┘
                                         │
             ┌───────────────────────────┴───────────────────────────┐
             ▼                                                       ▼
┌──────────────────────────┐                           ┌──────────────────────────┐
│     Attacker Subnet      │                           │      Target Subnet       │
│      (172.16.1.0/24)     │                           │     (172.16.2.0/24)      │
├──────────────────────────┤                           ├──────────────────────────┤
│ Kali Linux VM            │────[ Simulation Traffic ]►│ Windows Server 2022 VM   │
│ - Azure Network Sec Grp  │                           │ - Azure Monitor Agent    │
│ - Attack Scripts         │                           │ - Sysmon Telemetry       │
└──────────────────────────┘                           └─────────────┬────────────┘
                                                                     │
                                                   Log Ingestion Flow│ (HTTPS / TLS)
                                                                     ▼
                                                       ┌──────────────────────────┐
                                                       │ Microsoft Sentinel SIEM  │
                                                       │ (Log Analytics Workspace)│
                                                       │ - KQL Detection Rules    │
                                                       │ - Incident Dashboards    │
                                                       └──────────────────────────┘
```

---

## 1. Resource Group & Virtual Network Setup
1. Create Resource Group: `rg-cyber-range-lab`
2. Create Virtual Network: `vnet-cyber-range` (`172.16.0.0/16`)
   - Subnet 1: `snet-attacker` (`172.16.1.0/24`)
   - Subnet 2: `snet-target` (`172.16.2.0/24`)

---

## 2. Deploy Log Analytics Workspace & Microsoft Sentinel
1. In Azure Portal, search for **Log Analytics Workspaces** > Click **Create**.
2. Name: `law-soc-cyber-range`
3. Search for **Microsoft Sentinel** > Click **Add** > Link to `law-soc-cyber-range`.

---

## 3. Install Azure Monitor Agent (AMA) & Windows Data Connector
1. In Sentinel, navigate to **Data Connectors** > Select **Windows Security Events via AMA**.
2. Create Data Collection Rule (DCR) targeting `All Security Events` + `Sysmon/Operational`.
3. Install the AMA extension on your Windows Server VM.

---

## 4. Run KQL Threat Detection Rules in Sentinel
In Microsoft Sentinel > **Logs**, execute:
```kql
SecurityEvent
| where EventID == 4625
| where LogonType in (3, 10)
| summarize FailedCount = count(), TargetUsers = make_set(TargetUserName) by IpAddress, bin(TimeGenerated, 5m)
| where FailedCount > 4
```
