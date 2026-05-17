# Lab 3: SIEM Build and Configuration

## Overview

This lab involves deploying, configuring, and customizing a Security Information and Event Management (SIEM) solution. You will learn how to ingest logs, create parsing rules, build dashboards, and set up alerting.

## Objectives

- Deploy a SIEM platform (Splunk, ELK Stack, or Wazuh)
- Configure log ingestion from multiple sources
- Create custom parsing and field extraction rules
- Build detection queries and dashboards
- Set up alerting and notification workflows

## Tasks

### Task 1: SIEM Deployment
- Choose a SIEM platform (Splunk Free, ELK Stack, or Wazuh)
- Deploy the SIEM on a dedicated VM
- Configure network settings and access controls
- Verify the SIEM is operational

### Task 2: Log Ingestion
- Ingest Windows Security logs (via forwarder or syslog)
- Ingest firewall logs (pfSense/OPNsense)
- Ingest web server logs (Apache/Nginx)
- Ingest SSH/auth logs from Linux systems
- Verify all log sources are streaming to SIEM

### Task 3: Parsing and Field Extraction
- Create custom field extraction rules for firewall logs
- Parse custom application logs
- Map fields to Common Information Model (CIM)
- Create saved searches for parsed data

### Task 4: Dashboard Creation
- Build an executive summary dashboard
- Create a threat overview dashboard
- Build a log source health dashboard
- Design a network traffic analysis dashboard

### Task 5: Alerting and Correlation
- Create a brute force detection alert
- Build a failed login threshold alert
- Set up a new admin account creation alert
- Configure email/Slack notifications for alerts

## Deliverables

- SIEM deployment documentation
- Log source inventory with ingestion status
- Custom parsing rules documentation
- 4+ dashboards (screenshots + config)
- Alert rules with detection logic explanations

## Skills Gained

- SIEM deployment and architecture
- Log parsing and normalization
- Detection engineering
- Dashboard design
- Alert tuning and correlation

## Tools

- Splunk (Free/Enterprise) or ELK Stack or Wazuh
- Syslog-ng / Rsyslog
- Universal Forwarder (if Splunk)

## Resources

- Splunk Search Processing Language (SPL) docs
- ELK Stack Documentation
- Wazuh Documentation
- Sigma Rule Repository
