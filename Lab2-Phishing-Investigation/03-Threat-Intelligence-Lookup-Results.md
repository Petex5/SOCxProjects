# Threat Intelligence Lookup Results

---

## Document Control

| Field | Value |
|----------|----------|
| Document ID | PHISH-TIL-003 |
| Version | 1.0 |
| Classification | Internal Use Only |
| Related Incident ID | [INC-XXXX] |

---

## Investigation Metadata

| Field | Value |
|----------|----------|
| Analyst Name | |
| Date/Time | |
| Source Email | |
| Incident ID | |
| Investigation Phase | Threat Intelligence Lookup |

---

## 1. URL Reputation Lookup

### 1.1 VirusTotal Results

| URL | Detections | Total Engines | Malicious Score | First Submitted | Last Analyzed | Tags |
|-----|------------|---------------|----------------|-----------------|---------------|------|
| | / | | | | | |
| | / | | | | | |

### 1.2 URLScan.io Results

| URL | Verdict | Score | Server Location | Registrant | Categories |
|-----|---------|-------|----------------|------------|------------|
| | | /100 | | | |
| | | /100 | | | |

### 1.3 Google Safe Browsing

| URL | Status | Threat Type | Platform Affected |
|-----|--------|-------------|-------------------|
| | Safe / Unsafe | | |
| | Safe / Unsafe | | |

### 1.4 Cisco Talos Intelligence

| URL | Reputation | Category | GEO | IPs Associated |
|-----|------------|----------|-----|----------------|
| | High/Medium/Low/Unknown | | | |
| | High/Medium/Low/Unknown | | | |

### 1.5 Other Platform Results

| Platform | URL | Verdict | Confidence | Notes |
|----------|-----|---------|------------|----------|
| IBM X-Force | | | | |
| McAfee TrustedSource | | | | |
| BrightCloud | | | | |
| Palo Alto WildFire | | | | |
| Other | | | | |

---

## 2. IP Address Reputation Lookup

### 2.1 VirusTotal IP Report

| IP | Detections | Ratio | Country | ASN | Organization | Tags |
|----|------------|-------|---------|-----|-------------|------|
| | / | | | | | |
| | / | | | | | |

### 2.2 AbuseIPDB

| IP | Abuse Score | Reports | Last Reported | Categories |
|----|-------------|---------|---------------|------------|
| | 0-100 | | | |
| | 0-100 | | | |

### 2.3 Cisco Talos IP Lookup

| IP | Reputation | Country | ASN | Category |
|----|------------|---------|-----|----------|
| | High/Medium/Low/Unknown | | | |
| | High/Medium/Low/Unknown | | | |

### 2.4 Reverse DNS / Whois

| IP | Reverse DNS | Registrar | Registration Date | Notes |
|----|-------------|-----------|-------------------|----------|
| | | | | |
| | | | | |

---

## 3. Domain Reputation Lookup

### 3.1 VirusTotal Domain Report

| Domain | Detections | Ratio | Categories | Creation Date | Tags |
|--------|------------|-------|------------|---------------|------|
| | / | | | | |
| | / | | | | |

### 3.2 Whois Information

| Domain | Registrar | Creation Date | Expiration | Registrant | Abuse Contact |
|--------|-----------|---------------|------------|------------|---------------|
| | | | | | |
| | | | | | |

### 3.3 SecurityTrails / Passive DNS

| Domain | Historical IPs | Subdomains Found | First Seen | Last Seen |DNS Records |
|--------|----------------|-----------------|------------|-----------|------------|
| | | | | | |
| | | | | | |

### 3.4 Domain Category Classification

| Domain | BlueCoat | FortiGuard | Cisco Umbrella | Zscalar | Category Notes |
|--------|----------|------------|----------------|---------|---------------|
| | | | | | |
| | | | | | |

---

## 4. File Hash Reputation Lookup

### 4.1 VirusTotal Hash Report

| Hash (SHA256) | Malicious | Suspicious | Total | Detection Names | First Seen |
|---------------|-----------|------------|-------|-----------------|------------|
| | / | | | | |
| | / | | | | |

### 4.2 Hybrid Analysis

| Hash | Malicious Score | File Type | Signatures | Environment Detected |
|------|----------------|-----------|------------|--------------------|
| | | | | |
| | | | | |

### 4.3 Any.Run / Joe Sandbox

| Hash | Score | Classification | Behaviors | YARA Matches |
|------|-------|----------------|-----------|-------------|
| | | | | |
| | | | | |

---

## 5. Threat Actor Attribution

### 5.1 MITRE ATT&CK Mapping

| Technique ID | Technique Name | Evidence | Confidence | Tactic |
|--------------|----------------|----------|------------|--------|
| | | | | |
| | | | | |

### 5.2 Known Campaign Indicators

| IOC | Campaign | Threat Actor | Source | Confidence |
|-----|----------|--------------|--------|------------|
| | | | | |
| | | | | |

### 5.3 Industry Reports Correlation

| Report Source | Publication Date | Relevant Findings | Matched IOCs |
|---------------|------------------|-------------------|-------|
| | | | |
| | | | |

---

## 6. Threat Intelligence Feed Results

### 6.1 STIX/TAXII Feeds

| Feed Name | IOC | Match Found | Context | Last Updated |
|-----------|-----|-------------|---------|-------|
| | | Yes/No | | |
| | | Yes/No | | |

### 6.2 MISP Instance

| IOC Type | Indicator | Event ID | Tags | Distribution |
|----------|-----------|----------|------|-------------|
| | | | | |
| | | | | |

### 6.3 AlienVault OTX

| Pulse Name | IOC | Author | Subscribers | Relevance |
|------------|-----|--------|-------------|-----------|
| | | | | |
| | | | | |

---

## 7. IOC Summary and Risk Rating

### 7.1 Reputation Summary Table

| IOC | Type | VT Score | AbuseIPDB | Talos | Safe Browsing | Other | Overall Risk |
|-----|------|----------|-----------|-------|---------------|-------|-------------|
| | URL | / | | | | | High/Med/Low |
| | IP | / | | | | | High/Med/Low |
| | Domain | / | | | | | High/Med/Low |
| | Hash | / | | | | | High/Med/Low |

### 7.2 Risk Rating Criteria

| Overall Risk | Criteria | Recommended Action |
|-----|---------|------------------|
| Critical | 3+ platforms flag as malicious | Immediate block, notify team |
| High | 2 platforms flag as malicious | Block within 4 hours |
| Medium | 1 platform flags or suspicious indicators | Monitor and investigate |
| Low | No malicious flags but cautious indicators | Document and review |
| Benign | No flags from any platform | Archive for reference |

---

## 8. References and Sources

| Source | URL | Date Accessed |
|--------|-----|--------------|
| VirusTotal | https://www.virustotal.com | |
| URLScan.io | https://urlscan.io | |
| Google Safe Browsing | https://transparencyreport.google.com | |
| Cisco Talos | https://talosintelligence.com | |
| AbuseIPDB | https://www.abuseipdb.com | |
| Hybrid Analysis | https://www.hybrid-analysis.com | |
| Any.Run | https://any.run | |
| MISP | | |
| AlienVault OTX | https://otx.alienvault.com | |
| Other | | |

---

## 9. Document Control

| Field | Value |
|----------|----------|
| Document ID | PHISH-TIL-003 |
| Version | 1.0 |
| Classification | Internal Use Only |
| Created | |
| Last Updated | |
| Next Review | |

---
