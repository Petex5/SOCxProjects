# Lab 3 - Task 4: Detection Queries and Dashboards

## Overview
This document contains detection queries and dashboard configurations for the Wazuh SIEM platform. Detection queries identify security threats and anomalies in log data, while dashboards provide real-time visibility into the security posture of the organization.

## 4.1 Detection Queries

### 4.1.1 Wazuh Query Language - Authentication Failures
```
decoder.name:windows-auth AND data.event_id:4625 AND rule.level>5
```
**Purpose:** Identify all failed authentication attempts across Windows systems.
**Use Case:** Brute force detection, account compromise investigation.

### 4.1.2 Privilege Escalation Detection
```
(rule.id:100401 OR rule.id:100402) AND rule.level>=10
```
**Purpose:** Detect privilege escalation attempts via sudo or SUID binaries.
**Use Case:** Lateral movement detection, insider threat monitoring.

### 4.1.3 Web Application Attacks
```
rule.groups:web_attack AND rule.level>=10 AND data.status_code:(403 OR 500)
```
**Purpose:** Identify SQL injection, XSS, and path traversal attempts.
**Use Case:** Web application security monitoring.

### 4.1.4 New User Account Creation
```
data.event_id:4720 AND rule.groups:system
```
**Purpose:** Detect creation of new user accounts on Windows systems.
**Use Case:** Unauthorized account creation, persistence detection.

### 4.1.5 Remote Desktop Protocol (RDP) Logins
```
data.event_id:4624 AND data.LogonType:10
```
**Purpose:** Monitor all RDP login attempts.
**Use Case:** Remote access monitoring, lateral movement detection.

### 4.1.6 Malware Execution Indicators
```
(rule.id:100402) OR (full_log:(powershell -enc OR powershell -e ) AND rule.level>=7)
```
**Purpose:** Detect suspicious PowerShell execution and potentially malicious binary execution.
**Use Case:** Malware execution detection.

### 4.1.7 Firewall Deny with High Frequency
```
rule.groups:scan AND rule.level>=10
```
**Purpose:** Detect port scanning activity from blocked connections.
**Use Case:** Network reconnaissance detection.

### 4.1.8 Data Exfiltration Indicators
```
(data.bytes>10000000 AND decoder.name:pfsense-firewall AND data.action=allow AND data.direction=out)
```
**Purpose:** Identify large outbound data transfers that may indicate exfiltration.
**Use Case:** Data loss prevention, exfiltration detection.

## 4.2 Security Dashboards

### 4.2.1 Executive Security Overview Dashboard
**Panels:**
1. **Total Security Events (24h)** - Count of all security events
2. **Events by Severity** - Pie chart showing distribution by rule level
3. **Top Attacking IPs** - Table of source IPs with most alerts
4. **Events by Agent** - Bar chart of events per monitored host
5. **Authentication Failures Timeline** - Time series of failed logins

### 4.2.2 SOC Operations Dashboard
**Panels:**
1. **Real-time Event Feed** - Live scrolling list of security events (level >= 10)
2. **Alerts by Category** - Grouped alerts: Authentication, Web Attack, Malware, Network
3. **Firewall Deny Map** - GeoIP map showing blocked connection origins
4. **Top Targeted Systems** - Table of hosts receiving most attack attempts
5. **Incident Response Queue** - High-severity alerts requiring immediate attention

### 4.2.3 Authentication Monitoring Dashboard
**Panels:**
1. **Successful vs Failed Logins** - Stacked area chart (24h)
2. **Failed Logins by Username** - Horizontal bar chart
3. **Failed Logins by Source IP** - Table with GeoIP
4. **Logon Type Distribution** - Pie chart (Interactive, Network, RDP, etc.)
5. **Account Lockouts** - Count of locked accounts (Event ID 4740)

### 4.2.4 Network Security Dashboard
**Panels:**
1. **Firewall Allow vs Deny** - Ratio chart
2. **Blocked Ports** - Top blocked destination ports
3. **Outbound Connections** - Top destination IPs for outbound traffic
4. **Protocol Distribution** - TCP/UDP/ICMP breakdown
5. **Geographic Threat Map** - World map of blocked connections by country

### 4.2.5 Web Application Security Dashboard
**Panels:**
1. **HTTP Status Codes** - Distribution chart (2xx, 3xx, 4xx, 5xx)
2. **Request Rate by Path** - Top requested URLs
3. **Attack Attempts Timeline** - SQLi, XSS, Path Traversal over time
4. **User-Agent Distribution** - Top browsers and suspicious user agents
5. **Response Time Analysis** - Identify slow responses (potential DoS)

## 4.3 Wazuh Visualization Configuration

### 4.3.1 Creating a Metric Visualization
```json
{
  "aggs": [
    {
      "id": "1",
      "type": "count",
      "schema": "metric",
      "params": {}
    }
  ],
  "title": "Security Events Count",
  "type": "metric"
}
```

### 4.3.2 Creating a Time Series Visualization
```json
{
  "aggs": [
    {
      "id": "2",
      "type": "date_histogram",
      "schema": "segment",
      "params": {
        "field": "@timestamp",
        "interval": "1h"
      }
    }
  ],
  "title": "Security Events Over Time",
  "type": "line"
}
```

## 4.4 Dashboard Refresh and Maintenance

- **Auto-refresh:** Set dashboards to refresh every 30 seconds for SOC operations
- **Time ranges:** Default to last 24 hours for operational dashboards
- **Thresholds:** Configure visual thresholds (green < 10, yellow < 50, red >= 50)
- **Drill-down:** Enable click-through from dashboard panels to detailed event view
- **Export:** Schedule PDF/PNG exports for daily security reports

## 4.5 Integration with MITRE ATT&CK

Map detection queries to MITRE ATT&CK techniques:

| Detection Query | MITRE Tactic | MITRE Technique |
|-----------------|--------------|------------------|
| Auth Failures | Credential Access | T1110 - Brute Force |
| Privilege Escalation | Privilege Escalation | T1548 - Abuse Elevation Control |
| Web Attacks | Initial Access | T1190 - Exploit Public-Facing App |
| New Account Creation | Persistence | T1136 - Create Account |
| RDP Logins | Lateral Movement | T1021 - Remote Services |
| Large Outbound Data | Exfiltration | T1041 - Exfiltration Over C2 |

## References
- Wazuh Dashboards: https://documentation.wazuh.com/current/user-manual/dashboards/index.html
- Wazuh Query Language: https://documentation.wazuh.com/current/user-manual/api/reference.html
- MITRE ATT&CK Framework: https://attack.mitre.org/
