# Cloud Deployment Guide: AWS Cyber Range Architecture

Deploying this lab in **Amazon Web Services (AWS)** demonstrates cloud networking, VPC peering/segmentation, Security Group configuration, and cloud threat detection.

---

## AWS Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │              AWS VPC                   │
                      │          (10.0.0.0/16)                 │
                      └──────────────────┬─────────────────────┘
                                         │
             ┌───────────────────────────┴───────────────────────────┐
             ▼                                                       ▼
┌──────────────────────────┐                           ┌──────────────────────────┐
│   Public Attack Subnet   │                           │  Private Security Subnet │
│       (10.0.1.0/24)      │                           │      (10.0.2.0/24)       │
├──────────────────────────┤                           ├──────────────────────────┤
│ Kali Linux AMI / EC2     │                           │ 1. Windows Server 2022   │
│ - Elastic IP (SSH Access)│────[ Target Attacks ]────►│    (EC2 Instance)        │
│ - Attack Scripts         │                           │ 2. Elastic Stack / Splunk│
│                          │                           │    (Ubuntu EC2 Instance) │
└──────────────────────────┘                           └──────────────────────────┘
```

---

## 1. AWS VPC & Subnet Provisioning
- **VPC CIDR:** `10.0.0.0/16`
- **Subnet 1 (Public / Attacker):** `10.0.1.0/24` with Internet Gateway attached.
- **Subnet 2 (Private / Lab Target & SIEM):** `10.0.2.0/24`

---

## 2. EC2 Instances & Sizing

| Instance Role | AMI | Instance Type | Pricing / Free Tier |
| :--- | :--- | :--- | :--- |
| **Attacker (Kali)** | Kali Linux Official AWS Marketplace AMI | `t2.micro` / `t3.small` | Free Tier eligible |
| **Target (Windows)** | Microsoft Windows Server 2022 Base | `t3.medium` | ~$0.046/hr or AWS Credits |
| **SIEM (Elastic/Splunk)**| Ubuntu 22.04 LTS | `t3.medium` / `t3.large` | ~$0.041/hr |

---

## 3. Security Group Rules

### `sg-attacker` (Kali EC2):
- Inbound: SSH (Port `22`) from your home public IP only.
- Outbound: All traffic to `10.0.2.0/24` (Lab Subnet).

### `sg-target` (Windows EC2):
- Inbound: RDP (`3389`), SMB (`445`), WinRM (`5985`) from `sg-attacker` only.
- Outbound: Telemetry to `10.0.2.30` (Port `9200`/`5044`).

### `sg-siem` (Ubuntu SIEM EC2):
- Inbound: Port `9200`/`5044` from `sg-target`.
- Inbound: Port `5601` (Kibana) / Port `8000` (Splunk) from your home public IP.
