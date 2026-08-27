# Ubuntu SIEM Server Deployment Guide (Elastic Stack 8.x / Splunk)

This guide documents the exact Linux commands to provision the central SIEM node on Ubuntu Server 22.04 LTS (`192.168.56.30`).

---

## Method A: Rapid Dockerized Elastic Stack Deployment (Recommended)

### 1. Update Ubuntu and Install Docker & Docker Compose
```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y curl apt-transport-https ca-certificates gnupg lsb-release

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose Plugin
sudo apt-get install -y docker-compose-plugin
```

### 2. Increase Virtual Memory for Elasticsearch
Elasticsearch requires `vm.max_map_count` to be at least `262144`:
```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### 3. Deploy the SIEM Stack
Clone the repository and run Docker Compose from `siem-server/`:
```bash
cd siem-server/
docker compose up -d
```

### 4. Verify Services
```bash
# Check running containers
docker ps

# Query Elasticsearch Health
curl -X GET "http://localhost:9200/_cluster/health?pretty"

# Output should show status "green" or "yellow"
```

Access the Kibana SOC Dashboard in your browser: **`http://192.168.56.30:5601`**

---

## Method B: Splunk Enterprise Free Deployment (Alternative)

```bash
# 1. Download Splunk Enterprise .deb package
wget -O splunk-9.1.2-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/9.1.2/linux/splunk-9.1.2-linux-2.6-amd64.deb"

# 2. Install Splunk
sudo dpkg -i splunk-9.1.2-linux-2.6-amd64.deb

# 3. Start Splunk and accept license
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes

# 4. Enable Splunk to start on system boot
sudo /opt/splunk/bin/splunk enable boot-start

# 5. Enable Splunk Ingestion Port for Winlogbeat / Forwarders
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:YourStrongPassword123
```

Access the Splunk Dashboard in your browser: **`http://192.168.56.30:8000`**

---

## Ingestion Validation Checklist
- [ ] Windows Winlogbeat service is connected to `http://192.168.56.30:9200`.
- [ ] In Kibana > **Stack Management > Data Views**, create data view `winlogbeat-*` with timestamp `@timestamp`.
- [ ] In Kibana > **Discover**, verify Windows Security and Sysmon log streams are arriving in real time.
