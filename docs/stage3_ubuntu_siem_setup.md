# Stage 3: Central SIEM Node Setup (Ubuntu 22.04 LTS)

## Objective
Stand up Elasticsearch & Kibana (or Splunk Enterprise) on the Ubuntu SIEM VM (`192.168.56.30`) to collect, parse, index, and visualize endpoint telemetry.

---

## 1. Network Configuration
Set static IP `192.168.56.30` on the Ubuntu host-only adapter (`/etc/netplan/01-netcfg.yaml`):
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s8: # Match your host-only adapter name
      addresses:
        - 192.168.56.30/24
```
Apply with:
```bash
sudo netplan apply
```

---

## 2. Dockerized Elastic Stack Deployment
```bash
# 1. Update packages
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y docker.io docker-compose-v2 git curl

# 2. Configure system kernel for Elasticsearch
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# 3. Launch SIEM services
cd siem-server/
docker compose up -d

# 4. Check cluster status
curl -X GET "http://localhost:9200/_cat/indices?v"
```

---

## 3. Kibana Index Data View Setup
1. Open your browser on the host machine and navigate to: `http://192.168.56.30:5601`.
2. Go to **Management > Stack Management > Data Views**.
3. Click **Create Data View**.
4. Name: `Windows Security & Sysmon Telemetry`
5. Index pattern: `winlogbeat-*`
6. Timestamp field: `@timestamp`
7. Click **Save data view to Kibana**.
8. Go to **Analytics > Discover** to see real-time streaming security events.
