# IOC Extraction Template

---

## Document Control

| Field | Value |
|----------|----------|
| Document ID | PHISH-IET-002 |
| Version | 1.0 |
| Classification | Internal Use Only |
| Related Incident ID | [INC-XXXX] |

---

## Investigation Metadata

| Field | Value |
|----------|----------|
| Analyst Name | |
| Date/Time | |
| Email Subject | |
| Sender Address | |
| Recipient(s) | |
| Incident ID | |

---

## 1. Email Header IOCs

### 1.1 Sender Information

| Field | Value | IOC Type | Notes |
|----------|----------|----------|----------|
| From Address | | Email Address | |
| Display Name | | Display Name Spoofing | |
| Reply-To | | Email Address | |
| Return-Path | | Email Address | |
| Envelope From | | Email Address | |

### 1.2 Receiving Information

| Field | Value | IOC Type | Notes |
|----------|----------|----------|----------|
| To Address | | Email Address | |
| Received Headers | | Routing Path | |
| X-Originating-IP | | IP Address | |
| Authentication Results | | SPF/DKIM/DMARC | |

---

## 2. URL IOCs

| # | URL | Decoded/Expanded URL | Shortener Service | Threat Type | Reputation | Notes |
|---|-----|----------------------|-------------------|-------------|------------|----------|
| 1 | | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |

### 2.1 URL Analysis Tools Used:

- [ ] VirusTotal URL Scan
- [ ] URLScan.io
- [ ] Google Safe Browsing
- [ ] Cisco Talos Intelligence
- [ ] IBM X-Force Exchange
- [ ] Other: _________

---

## 3. IP Address IOCs

| # | IP Address | Geolocation | ASN/Organization | Reputation | Associated Domains | Notes |
|---|------------|-------------|------------------|------------|--------------------|----------|
| 1 | | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |

### 3.1 IP Analysis Tools Used:

- [ ] VirusTotal IP Report
- [ ] AbuseIPDB
- [ ] Cisco Talos IP Lookup
- [ ] IPVoid
- [ ] Whois Lookup
- [ ] Other: _________

---

## 4. Domain IOCs

| # | Domain | Registrar | Creation Date | Name Servers | Reputation | Associated IPs | Notes |
|---|--------|-----------|---------------|--------------|------------|---------------|----------|
| 1 | | | | | | | |
| 2 | | | | | | | |
| 3 | | | | | | | |

### 4.1 Domain Analysis Tools Used:

- [ ] Whois Lookup
- [ ] VirusTotal Domain Report
- [ ] Cisco Talos Domain Lookup
- [ ] SecurityTrails
- [ ] Passive DNS Lookup
- [ ] Other: _________

---

## 5. File Hash IOCs

### 5.1 Attachment Hashes

| # | Filename | File Type | Size | MD5 | SHA1 | SHA256 | Reputation | Notes |
|---|----------|-----------|------|-----|------|--------|------------|----------|
| 1 | | | | | | | | |
| 2 | | | | | | | | |

### 5.2 Hash Analysis Tools Used:

- [ ] VirusTotal Hash Lookup
- [ ] Hybrid Analysis
- [ ] Any.Run
- [ ] Joe Sandbox
- [ ] Malshare
- [ ] Other: _________

---

## 6. Expanded IOCs

### 6.1 Social Engineering Indicators

| Indicator Type | Finding | Confidence | Notes |
|----------------|---------|------------|----------|
| Urgency Language | | High/Medium/Low | |
| Authority Impersonation | | High/Medium/Low | |
| Fake Branding | | High/Medium/Low | |
| Suspicious Grammar | | High/Medium/Low | |
| Mismatched Display/Return Path | | High/Medium/Low | |

### 6.2 Infrastructure IOCs

| Type | Indicator | Source | First Seen | Context |
|------|-----------|--------|------------|----------|
| C2 Server | | | | |
| Malware Distribution | | | | |
| Credential Harvesting | | | | |
| Redirect Chain | | | | |
| Hosting Provider | | | | |

---

## 7. IOC Enrichment

### 7.1 Threat Intelligence Platform Correlations

| Platform | IOC | Match Type | Confidence | Tags/Labels |
|----------|-----|------------|------------|------------|
| VirusTotal | | | | |
| MISP | | | | |
| AlienVault OTX | | | | |
| Recorded Future | | | | |
| CrowdStrike | | | | |

### 7.2 Historical Context

| IOC | Previous Sightings | Campaign Association | Threat Actor Link | Notes |
|-----|-------------------|---------------------|-------------------|----------|
| | | | | |

---

## 8. IOC Summary Matrix

| IOC Type | Total Extracted | Malicious | Suspicious | Benign | Action Taken |
|----------|----------------|-----------|------------|--------|-------------|
| URLs | | | | | |
| IP Addresses | | | | | |
| Domains | | | | | |
| File Hashes | | | | | |
| Email Addresses | | | | | |

---

## 9. Recommended Actions

| Priority | Action | IOC | Status | Assigned To |
|----------|--------|-----|--------|------------|
| Critical | Block IP at firewall | | | |
| High | Add domain to blocklist | | | |
| High | Block sender address | | | |
| High | Quarantine affected accounts | | | |
| Medium | Submit to threat intel feeds | | | |
| Medium | Update detection rules | | | |
| Low | Archive evidence | | | |

---

## 10. Document Control

| Field | Value |
|----------|----------|
| Document ID | PHISH-IET-002 |
| Version | 1.0 |
| Classification | Internal Use Only |
| Created | |
| Last Updated | |
