# Lab 3 - Task 2: Log Ingestion Configuration

## Overview
This document provides the configuration steps for ingesting logs from multiple data sources into the Wazuh SIEM platform. Proper log ingestion is critical for comprehensive security monitoring and threat detection.

## 2.1 Log Source Inventory

| Source Type | Host/System | Log Format | Ingestion Method | Priority |
|-------------|-------------|------------|------------------|----------|
| Windows Event Logs | Domain Controllers | XML/Eventlog | Wazuh Agent | High |
| Windows Event Logs | Workstations | XML/Eventlog | Wazuh Agent | Medium |
| Linux Syslog | Web Servers | Syslog | Syslog Forwarder | High |
| Linux Syslog | Application Servers | Syslog | Syslog Forwarder | Medium |
| Firewall Logs | Perimeter Firewall | Syslog | Remote Syslog | High |
| Authentication | Active Directory | XML | Wazuh Agent | High |
| Network Devices | Switches/Routers | Syslog | Remote Syslog | Medium |
| Application Logs | Custom Apps | JSON/Text | File Monitor | Low |

## 2.2 Wazuh Agent Configuration

### 2.2.1 Agent Installation (Windows)
1. Download the Wazuh Windows agent MSI from the Wazuh manager
2. Run installer with manager IP: `agent.msi /q MANAGER_IP=<SIEM-IP> AUTHD_PASS=<password>`
3. Verify agent status: `sc query wazuh`
4. Confirm agent appears in Wazuh dashboard

### 2.2.2 Agent Configuration (ossec.conf)
```
<agent_config>
  <localfile>
    <location>Security</location>
    <log_format>eventlog</log_format>
  </localfile>
  <localfile>
    <location>System</location>
    <log_format>eventlog</log_format>
  </localfile>
  <localfile>
    <location>Application</location>
    <log_format>eventlog</log_format>
  </localfile>
  <syscheck>
    <frequency>43200</frequency>
    <directories check_all="yes">C:\Windows\System32</directories>
  </syscheck>
  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>
</agent_config>
```

### 2.2.3 Agent Installation (Linux)
```
wget https://packages.wazuh.com/4.x/wazuh-agent_4.x_amd64.deb
sudo dpkg -i wazuh-agent_4.x_amd64.deb
sudo /var/ossec/bin/wazuh-control restart
```

## 2.3 Syslog Forwarder Configuration

### 2.3.1 Rsyslog Configuration (/etc/rsyslog.conf)
```
# Forward all logs to Wazuh
*.* @<SIEM-IP>:514

# Application-specific forwarding
:programname, isequal, "nginx" @<SIEM-IP>:514
:programname, isequal, "apache2" @<SIEM-IP>:514

# Firewall logs
:programname, isequal, "iptables" @<SIEM-IP>:514
```

### 2.3.2 Wazuh Manager Syslog Reception
```
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>192.168.1.0/24</allowed-ips>
  </remote>
</ossec_config>
```

## 2.4 Log Collection Verification

### 2.4.1 Verify Agent Connectivity
```
curl -k https://<SIEM-IP>:1515/agents/overview
```

### 2.4.2 Check Log Reception in Wazuh
- Navigate to Security Events in dashboard
- Filter by agent name to confirm logs are arriving
- Check Events per Second (EPS) metrics

### 2.4.3 Troubleshooting Checklist
- [ ] Agent shows as active in dashboard
- [ ] Firewall allows ports 1514, 1515, 514
- [ ] Agent keys are properly registered
- [ ] Log files exist and are readable
- [ ] Syslog forwarder is running
- [ ] Network connectivity between sources and SIEM

## 2.5 Log Volume Baseline

| Source | Expected EPS | Peak EPS | Storage/Day |
|--------|--------------|----------|-------------|
| Domain Controllers | 50 | 200 | 4.3 GB |
| Workstations (100) | 10 | 50 | 86 GB |
| Web Servers | 20 | 100 | 1.7 GB |
| Firewall | 30 | 150 | 2.6 GB |
| Applications | 5 | 25 | 0.4 GB |
| **Total** | **115** | **525** | **~95 GB** |

## References
- Wazuh Agent Deployment Guide: https://documentation.wazuh.com/current/deployment-options/index.html
- Wazuh Log Data Collection: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html
- RFC 5424 - Syslog Protocol
