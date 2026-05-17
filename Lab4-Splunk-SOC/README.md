# Lab 4: Splunk SOC Operations

## Overview

This lab focuses on using Splunk as a SOC analyst to write SPL queries, build correlation searches, create dashboards, and manage alerts. You will develop hands-on proficiency in Splunk's core SOC analyst capabilities.

## Objectives

- Master SPL (Search Processing Language) fundamentals
- Write detection queries for common attack patterns
- Build and tune correlation searches
- Create SOC analyst dashboards
- Configure and manage Splunk alerts

## Tasks

### Task 1: SPL Fundamentals
- Learn basic SPL syntax (search, fields, table, stats)
- Practice using comparison operators and wildcards
- Master time-based searches and relative time modifiers
- Use subsearches and eval commands

### Task 2: Detection Query Development
- Write a query to detect brute force attacks (multiple failed logins)
- Create a query for suspicious process execution
- Build a query for data exfiltration indicators
- Develop a query for lateral movement detection

### Task 3: Correlation Searches
- Create a correlation search for repeated failed logins followed by success
- Build a search for new admin account creation + privilege escalation
- Develop a search for DNS tunneling indicators
- Tune searches to reduce false positives

### Task 4: SOC Analyst Dashboards
- Build an incident triage dashboard
- Create a threat overview dashboard
- Design a log source health monitoring dashboard
- Build a user behavior analytics dashboard

### Task 5: Alert Management
- Configure scheduled alerts for detection queries
- Set up alert actions (email, webhook, ticket creation)
- Create an alert suppression strategy
- Document alert tuning procedures

## Deliverables

- 10+ SPL queries with explanations
- 4+ correlation searches with tuning notes
- 4+ Splunk dashboards (screenshots + XML)
- Alert configuration documentation

## Skills Gained

- Advanced SPL query writing
- Detection engineering
- Correlation search development
- Dashboard design and visualization
- Alert tuning and management

## Tools

- Splunk Enterprise (Free) or Splunk Cloud
- Boss of the SOC (BOTS) datasets (optional)

## Resources

- Splunk SPL Reference Guide
- Splunk Security Essentials App
- Splunk BOTS Datasets
- MITRE ATT&CK for Splunk Searches
