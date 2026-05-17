# Lab 2: Phishing Investigation

## Overview

This lab focuses on investigating phishing emails, analyzing email headers, extracting indicators of compromise (IOCs), and leveraging threat intelligence to determine the scope and impact of a phishing campaign.

## Objectives

- Perform email header analysis and trace routing
- Extract IOCs (URLs, IPs, domains, file hashes)
- Use threat intelligence platforms for IOC lookup
- Identify phishing indicators and TTPs
- Document findings in an investigation report

## Tasks

### Task 1: Email Header Analysis
- Obtain a sample phishing email (use provided .eml file)
- Parse and analyze full email headers
- Trace the email route using Received headers
- Identify spoofing indicators and suspicious hops

### Task 2: IOC Extraction
- Extract all URLs from the email body
- Extract all IP addresses and domains
- Analyze attachments (if present) for file hashes
- Compile a list of all IOCs

### Task 3: Threat Intelligence Lookup
- Use VirusTotal to check URL and hash reputation
- Use AbuseIPDB to check IP reputation
- Search URLhaus and PhishTank for known phishing
- Document findings with screenshots

### Task 4: Campaign Attribution
- Identify the phishing TTPs used (MITRE ATT&CK)
- Determine if the campaign matches known APT groups
- Assess the target demographic and intent

### Task 5: Investigation Report
- Write a structured investigation report
- Include timeline of events, IOCs, and conclusions
- Recommend remediation actions

## Deliverables

- Annotated email header analysis
- IOC extraction spreadsheet
- Threat intelligence lookup results
- Final investigation report (PDF/Markdown)

## Skills Gained

- Email header parsing
- IOC identification and extraction
- Threat intelligence research
- MITRE ATT&CK mapping
- Security report writing

## Tools Used

- Email header analyzer (online or CLI)
- VirusTotal
- AbuseIPDB
- URLhaus
- PhishTank
- MITRE ATT&CK Navigator

## Resources

- RFC 5322 - Internet Message Format
- MITRE ATT&CK T1566 - Phishing
- SANS Phishing Investigation Guide
