# Stage 1: Lab Infrastructure Setup

## Objective
Establish an isolated virtual network testbed where adversarial simulation traffic cannot escape onto the home or corporate local area network (LAN).

---

## 1. Hypervisor Selection
You can build this lab using either **Oracle VirtualBox** (100% Free & Open Source) or **VMware Workstation Pro** (Free for Personal Use).

### Recommended Host Machine Specifications
- **Operating System:** Windows 10/11, macOS, or Linux
- **Processor:** 4+ Cores (Intel Core i5/i7/i9 or AMD Ryzen 5/7/9)
- **RAM:** Minimum 16 GB (allocated across 3 VMs)
- **Disk Space:** 80 GB free SSD storage

---

## 2. Setting Up the Host-Only Network in VirtualBox

1. Open VirtualBox and navigate to **File > Tools > Network Manager**.
2. Click **Create** under the **Host-only Networks** tab.
3. Configure the adapter parameters:
   - **Adapter Name:** `VirtualBox Host-Only Ethernet Adapter` (or `vboxnet0`)
   - **IPv4 Address:** `192.168.56.1`
   - **IPv4 Network Mask:** `255.255.255.0`
4. Configure DHCP Server:
   - Check **Enable Server** (or assign static IPs manually as detailed in the IP matrix).
   - **Server Address:** `192.168.56.100`
   - **Server Mask:** `255.255.255.0`
   - **Lower Address Limit:** `192.168.56.101`
   - **Upper Address Limit:** `192.168.56.254`

---

## 3. Provisioning the Three Virtual Machines

### Node 1: Offensive Node (Kali Linux)
- **RAM:** 2048 MB - 4096 MB | **vCPU:** 2
- **Network Adapter 1:** NAT (temporary during installation for updates/packages)
- **Network Adapter 2:** Host-Only Adapter (`VirtualBox Host-Only Ethernet Adapter`)
- **Static IP:** `192.168.56.20`

### Node 2: Defensive Target Node (Windows Server / Windows 10)
- **Image:** Windows Server 2022 Evaluation ISO or Windows 10 Enterprise Eval (Microsoft Evaluation Center)
- **RAM:** 4096 MB | **vCPU:** 2
- **Network Adapter 1:** Host-Only Adapter
- **Static IP:** `192.168.56.10`
- **Subnet Mask:** `255.255.255.0` | **Gateway:** `192.168.56.1`

### Node 3: Central SIEM Node (Ubuntu Server 22.04 LTS)
- **Image:** Ubuntu Server 22.04 LTS ISO
- **RAM:** 4096 MB - 6144 MB | **vCPU:** 2
- **Network Adapter 1:** NAT (for package installation)
- **Network Adapter 2:** Host-Only Adapter
- **Static IP:** `192.168.56.30`

---

## 4. Connectivity Verification
From the Kali Linux terminal:
```bash
ping -c 3 192.168.56.10  # Target Windows VM
ping -c 3 192.168.56.30  # Ubuntu SIEM Server
```
*Note: If Windows does not respond to ICMP ping, enable File and Printer Sharing (Echo Request - ICMPv4-In) in Windows Defender Firewall.*
