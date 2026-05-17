# Lab 3: SIEM Deployment Guide

## Overview

This document provides a step-by-step guide for deploying Wazuh, an open-source SIEM platform, on a dedicated Ubuntu Server VM. Wazuh integrates log management, intrusion detection, vulnerability assessment, and compliance monitoring into a single platform.

## Selected SIEM Platform: Wazuh

### Why Wazuh?
- **Free and open-source** (no licensing costs)
- **Enterprise-grade** features (real-time monitoring, SIEM, XDR)
- **Built on Elastic Stack** (Elasticsearch, Logstash/Filebeat, Kibana)
- **Active community** with extensive documentation
- **Compliance support** (PCI DSS, HIPAA, GDPR, NIST)

### Alternative Platforms
| Platform | License | Log Limit | Best For |
|----------|---------|-----------|----------|
| Wazuh | Free (OSS) | Unlimited | Full SOC operations |
| Splunk Free | Free (limited) | 500MB/day | Learning SPL |
| ELK Stack | Free (OSS) | Unlimited | Log centralisation |

---

## Architecture Overview

```
[Windows Endpoint] -----> [Wazuh Agent] \
                        |         |    |
[Linux Endpoint]  -----> [Wazuh Agent]  \----> [Wazuh Manager/Indexer/Dashboard]
[Network Devices] -------> [Syslog]            (Ubuntu VM: 4 vCPU, 8GB RAM, 50GB disk)
```

---

## Task 1: Prerequisites and Hardware Requirements

### Minimum Hardware for Wazuh All-in-One
| Component | Minimum | Recommended |
|-----------|---------|-------------|
| vCPU | 2 | 4 |
| RAM | 4 GB | 8 GB |
| Disk | 30 GB | 50+ GB SSD |
| Network | 1 NIC | 2 NICs (management + production) |

### Software Requirements
- Ubuntu Server 22.04 LTS
- Python 3.8+
- Java 11+ (for Elasticsearch)
- OpenJDK

### Network Ports
| Port | Protocol | Service |
|------|----------|---------|
| 443 | TCP | Wazuh Dashboard (HTTPS) |
| 1514 | TCP | Wazuh Agent communication |
| 1515 | TCP | Agent enrollment |
| 9200 | TCP | Elasticsearch API |
| 9300 | TCP | Elasticsearch cluster |

---

## Task 2: Deploy Wazuh on Ubuntu VM

### Step 2.1: System Update
```bash
sudo apt update && sudo apt upgrade -y
sudo reboot
```

### Step 2.2: Download and Run Wazuh Installation Assistant
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
sudo bash wazuh-install.sh -a
```

### Step 2.3: Verify Installation
```bash
# Check Wazuh manager status
sudo systemctl status wazuh-manager

# Check Elasticsearch status
sudo systemctl status wazuh-indexer

# Check Dashboard status
sudo systemctl status wazuh-dashboard

# Check firewall rules
sudo ufw status
```

### Step 2.4: Open Required Ports
```bash
sudo ufw allow 443/tcp
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
sudo ufw reload
```

---

## Task 3: Configure Network Settings and Access Controls

### Step 3.1: Configure Firewall Rules
```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow Wazuh management
sudo ufw allow 443/tcp
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp

# Enable UFW
sudo ufw enable
sudo ufw status numbered
```

### Step 3.2: Configure SSH Hardening
```bash
sudo nano /etc/ssh/sshd_config
# Edit: PermitRootLogin no
# Edit: PasswordAuthentication no
# Edit: AllowUsers soc_analyst wazuh_user
sudo systemctl restart sshd
```

### Step 3.3: Create SOC Analyst User
```bash
sudo adduser soc_analyst
sudo usermod -aG sudo soc_analyst
sudo systemctl restart wazuh-manager
```

### Step 3.4: Configure Wazuh Manager (ossec.conf)
```xml
<!-- /var/ossec/etc/ossec.conf -->
<global>
  <email_notification>yes</email_notification>
  <smtp_server>smtp.example.com</smtp_server>
  <email_from>wazuh@example.com</email_from>
  <email_to>soc@example.com</email_to>
</global>

<ossec_config>
  <cluster>
    <node_name>node01</node_name>
    <node_type>master</node_type>
    <key>cluster_secret_key</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
  </cluster>
</ossec_config>
```

---

## Task 4: Verify SIEM is Operational

### Step 4.1: Access Wazuh Dashboard
1. Open browser: `https://<WAZUH_SERVER_IP>`
2. Login with default credentials:
   - Username: `admin`
   - Password: (retrieved from `/etc/wazuh-dashboard/opensearch_dashboards.keystore`)
3. Navigate to: Security > Dashboard

### Step 4.2: Verify Agent Connectivity
```bash
# List connected agents
/var/ossec/bin/agent_control -l

# Check agent connection
/var/ossec/bin/agent_control -i 000
```

### Step 4.3: Test Log Ingestion
```bash
# Generate test log on manager
echo "Test alert from Wazuh manager" | /var/ossec/bin/player 

# Check alerts log
tail -f /var/ossec/logs/alerts/alerts.json
```

### Step 4.4: Verify Dashboard Data
- Go to **Security > Events** and confirm logs are appearing
- Check **Security > Agents** shows manager as active
- Verify **Security > Cluster** shows cluster as healthy
- Navigate to **Security > FIM (File Integrity Monitoring)** to verify baseline

---

## Post-Deployment Checklist

- [ ] Wazuh Manager running
- [ ] Wazuh Indexer running
- [ ] Wazuh Dashboard accessible
- [ ] Firewall configured
- [ ] SSH hardened
- [ ] SOC analyst user created
- [ ] Dashboard credentials changed from default
- [ ] Backup strategy configured
- [ ] NTP/time sync configured
- [ ] Log rotation configured

## References
- [Wazuh Documentation](https://documentation.wazuh.com)
- [Wazuh Deployment Guide](https://documentation.wazuh.com/current/deployment-guide/index.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
