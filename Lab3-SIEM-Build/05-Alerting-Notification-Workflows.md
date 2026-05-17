# Lab 3 - Task 5: Alerting and Notification Workflows

## Overview
This document defines the alerting rules, notification channels, and incident response workflows for the Wazuh SIEM platform. Effective alerting ensures that security teams are promptly notified of potential threats, enabling rapid response and mitigation.

## 5.1 Alert Severity Classification

### 5.1.1 Severity Levels

| Level | Score Range | Description | Response Time |
|-------|-------------|-------------|---------------|
| Informational | 0-3 | Normal activity, no action required | Log only |
| Low | 4-6 | Minor anomalies, review at next shift | 24 hours |
| Medium | 7-9 | Potential security issue, investigate | 4 hours |
| High | 10-12 | Likely attack, immediate investigation | 1 hour |
| Critical | 13-15 | Active compromise, immediate response | 15 minutes |

### 5.1.2 Alert Grouping

- **Authentication Alerts:** Failed logins, brute force, account lockouts
- **Network Alerts:** Port scans, blocked connections, suspicious outbound
- **Web Application Alerts:** SQL injection, XSS, path traversal
- **Malware Alerts:** Suspicious process execution, known malware signatures
- **System Alerts:** Configuration changes, privilege escalation

## 5.2 Notification Channels

### 5.2.1 Email Notifications
Configure email alerts in Wazuh (ossec.conf):
```
<ossec_config>
  <email_alerts>
    <email_to>soc-team@company.com</email_to>
    <do_not_delay />      
    <do_not_group />
    <rules_id>100101,100102,100201,100202,100203,100301,100302,100303,100401,100402,100501</rules_id>
  </email_alerts>
</ossec_config>
```

### 5.2.2 Slack Integration
Configure Slack webhook in Wazuh:
```
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/YOUR/WEBHOOK/URL</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
  <group>web,authentication,firewall,malware</group>
</integration>
```

### 5.2.3 PagerDuty Integration
For critical alerts requiring immediate response:
```
<integration>
  <name>pagerduty</name>
  <api_key>PAGERDUTY_API_KEY</api_key>
  <level>13</level>
  <alert_format>json</alert_format>
  <group>brute_force,malicious_ip,malware</group>
</integration>
```

### 5.2.4 Custom Webhook Integration
For integration with ticketing systems (ServiceNow, Jira):
```
<integration>
  <name>custom-webhook</name>
  <hook_url>https://api.servicenow.com/webhook</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

## 5.3 Alert Routing Matrix

| Rule ID Range | Description | Channel | Severity | On-Call |
|--------------|-------------|---------|----------|----------|
| 100101-100102 | Firewall blocked/deny | Slack | Medium | SOC Analyst |
| 100201 | Auth failure (single) | Email | Low | SOC Analyst |
| 100202 | Brute force detection | Slack + Email | High | SOC Lead |
| 100203 | Login after failures | Slack + Email | High | SOC Lead |
| 100301-100303 | Web attacks (SQLi/XSS) | Slack | High | SOC Analyst |
| 100401-100402 | Privilege escalation | PagerDuty | Critical | SOC Manager |
| 100501 | Malicious IP (IOC match) | PagerDuty | Critical | SOC Manager |

## 5.4 Incident Response Workflows

### 5.4.1 Workflow 1: Brute Force Attack Response
1. **Detection:** Rule 100202 triggers (5+ failed auth in 2 min)
2. **Notification:** Alert sent to Slack #security-alerts channel
3. **Triage:** SOC Analyst reviews source IP and targeted account
4. **Investigation Steps:**
   - Check if source IP is internal or external
   - Verify if targeted account is privileged
   - Check for successful authentication after failures
   - Review GeoIP data for source
5. **Response Actions:**
   - If external: Block IP at firewall
   - If internal: Investigate host for compromise
   - Reset compromised account password
   - Document incident in ticketing system
6. **Escalation:** If >100 attempts or privileged account, escalate to SOC Lead

### 5.4.2 Workflow 2: Web Application Attack Response
1. **Detection:** Rule 100301/100302/100303 triggers
2. **Notification:** Alert sent to Slack #web-security channel
3. **Triage:** SOC Analyst reviews attack type and source
4. **Investigation Steps:**
   - Identify targeted endpoint
   - Check web server logs for additional context
   - Verify if attack was successful (HTTP 200 response)
   - Check if application logged the attacker
5. **Response Actions:**
   - Block source IP at WAF/firewall
   - Notify application security team
   - Review application code for vulnerability
   - Create bug ticket for development team
6. **Escalation:** If SQL injection successful, escalate to Application Security Lead

### 5.4.3 Workflow 3: Malicious IP Detection Response
1. **Detection:** Rule 100501 triggers (IOC match from CDB list)
2. **Notification:** PagerDuty alert + Slack #critical-alerts
3. **Triage:** SOC Manager reviews immediately
4. **Investigation Steps:**
   - Identify which threat actor/malware the IP is associated with
   - Determine what data/system was targeted
   - Check for lateral movement indicators
   - Review endpoint logs for compromise evidence
5. **Response Actions:**
   - Isolate affected systems
   - Block IP at perimeter firewall
   - Initiate incident response playbook
   - Preserve evidence for forensics
6. **Escalation:** Immediate escalation to CISO for critical threats

### 5.4.4 Workflow 4: Privilege Escalation Response
1. **Detection:** Rule 100402 triggers (SUID from temp directory)
2. **Notification:** PagerDuty alert + Slack #critical-alerts
3. **Triage:** SOC Manager + Security Engineer review
4. **Investigation Steps:**
   - Identify the binary that was executed
   - Check MD5 hash against malware databases
   - Review process tree for parent/child processes
   - Check for persistence mechanisms
5. **Response Actions:**
   - Kill malicious process
   - Isolate affected host
   - Collect memory and disk forensics
   - Reset credentials for affected user
6. **Escalation:** Immediate escalation to CISO, engage incident response team

## 5.5 Alert Suppression and Tuning

### 5.5.1 Scheduled Suppression
Suppress known maintenance windows:
```
<rule id="100101" level="5">
  <if_sid>100100</if_sid>
  <match>action=deny</match>
  <time>Mon-Tue-Wed-Thu-Fri 02:00-04:00</time>
  <description>Scheduled firewall maintenance - suppressed alert</description>
  <options>no_full_log</options>
</rule>
```

### 5.5.2 Whitelist Configuration
```
# /var/ossec/etc/lists/whitelist-ips
192.168.1.1:Security-Scanner
10.0.0.1:Monitoring-Server
```

### 5.5.3 Alert Frequency Limiting
Prevent alert fatigue by grouping similar alerts:
```
<global>
  <email_notification>yes</email_notification>
  <smtp_server>smtp.company.com</smtp_server>
  <email_from>soc-alerts@company.com</email_from>
  <email_maxperhour>60</email_maxperhour>
</global>
```

## 5.6 On-Call Schedule

| Shift | Time | Primary | Secondary | Escalation |
|-------|------|---------|-----------|------------|
| Day Shift | 08:00-16:00 | SOC Analyst 1 | SOC Analyst 2 | SOC Lead |
| Evening | 16:00-00:00 | SOC Analyst 3 | SOC Analyst 4 | SOC Manager |
| Night | 00:00-08:00 | SOC Analyst 5 | On-call Engineer | CISO |

## 5.7 Alert Testing and Validation

### 5.7.1 Test Alert Generation
```
/var/ossec/bin/ossec-logtest
> Testing email notification
> Inject test event matching rule 100201
```

### 5.7.2 Notification Channel Verification
- Verify email delivery to all recipients
- Confirm Slack channel receives alerts
- Test PagerDuty escalation chain
- Validate webhook integrations

### 5.7.3 Monthly Review Checklist
- [ ] Review false positive rate per rule
- [ ] Update IOC lists and CDB lists
- [ ] Test all notification channels
- [ ] Review on-call schedule
- [ ] Update incident response playbooks
- [ ] Document lessons learned from incidents

## References
- Wazuh Integration Guide: https://documentation.wazuh.com/current/user-manual/manager/integrations.html
- Wazuh Email Configuration: https://documentation.wazuh.com/current/user-manual/manager/email-alerts.html
- NIST SP 800-61 Rev 2: Computer Security Incident Handling Guide
