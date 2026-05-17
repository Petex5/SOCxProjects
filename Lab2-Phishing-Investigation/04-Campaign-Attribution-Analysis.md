# Campaign Attribution Analysis

---

## Document Control

| Field | Value |
|----------|----------|
| Document ID | PHISH-CAA-004 |
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
| Investigation Phase | Campaign Attribution |

---

## 1. Campaign Overview

### 1.1 Campaign Identification

| Field | Details |
|----------|----------|
| Campaign Name | |
| First Observed | |
| Last Observed | |
| Target Sector | |
| Target Geography | |
| Campaign Objective | Credential Theft / Malware Delivery / Reconnaissance / Other |

### 1.2 Campaign Timeline

| Date/Time | Event | Description | Source |
|-----------|-------|-------------|--------|
| | | | |
| | | | |
| | | | |

---

## 2. MITRE ATT&CK Technique Mapping

### 2.1 Initial Access

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1566 | Phishing | | High/Medium/Low | |
| T1566.001 | Spearphishing Attachment | | High/Medium/Low | |
| T1566.002 | Spearphishing Link | | High/Medium/Low | |
| T1566.003 | Spearphishing via Service | | High/Medium/Low | |

### 2.2 Execution

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1204 | User Execution | | High/Medium/Low | |
| T1204.002 | Malicious File | | High/Medium/Low | |
| T1059 | Command and Scripting Interpreter | | High/Medium/Low | |

### 2.3 Persistence

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1547 | Boot or Logon Autostart Execution | | High/Medium/Low | |
| T1053 | Scheduled Task/Job | | High/Medium/Low | |

### 2.4 Privilege Escalation

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1548 | Abuse Elevation Control Mechanism | | High/Medium/Low | |
| T1134 | Access Token Manipulation | | High/Medium/Low | |

### 2.5 Defense Evasion

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1027 | Obfuscated Files or Information | | High/Medium/Low | |
| T1070 | Indicator Removal | | High/Medium/Low | |
| T1562 | Impair Defenses | | High/Medium/Low | |

### 2.6 Credential Access

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1110 | Brute Force | | High/Medium/Low | |
| T1113 | Screen Capture | | High/Medium/Low | |
| T1003 | OS Credential Dumping | | High/Medium/Low | |

### 2.7 Discovery

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1082 | System Information Discovery | | High/Medium/Low | |
| T1083 | File and Directory Discovery | | High/Medium/Low | |
| T1049 | System Network Connections Discovery | | High/Medium/Low | |

### 2.8 Lateral Movement

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1021 | Remote Services | | High/Medium/Low | |
| T1563 | Remote Service Session Hijacking | | High/Medium/Low | |

### 2.9 Collection

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1005 | Data from Local System | | High/Medium/Low | |
| T1039 | Data from Network Shared Drive | | High/Medium/Low | |
| T1113 | Screen Capture | | High/Medium/Low | |

### 2.10 Command and Control

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1071 | Application Layer Protocol | | High/Medium/Low | |
| T1573 | Encrypted Channel | | High/Medium/Low | |
| T1102 | Web Service | | High/Medium/Low | |

### 2.11 Exfiltration

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1041 | Exfiltration Over C2 Channel | | High/Medium/Low | |
| T1048 | Exfiltration Over Alternative Protocol | | High/Medium/Low | |

### 2.12 Impact

| Technique ID | Technique Name | Evidence | Confidence | Notes |
|--------------|----------------|----------|------------|----------|
| T1486 | Data Encrypted for Impact | | High/Medium/Low | |
| T1565 | Data Manipulation | | High/Medium/Low | |

---

## 3. Threat Actor Attribution

### 3.1 Suspected Threat Actor

| Field | Details |
|----------|----------|
| Expected Actor | |
| Known Aliases | |
| Primary Objective | |
| Typical TTPs | |
| Target Sectors | |
| Geographic Origin | |
| Sophistication Level | |

### 3.2 Attribution Confidence

| Factor | Evidence | Support for Attribution |
|--------|----------|------------------------|
| IOCs match known actor | | Strong / Moderate / Weak |
| TTPs align with known actor | | Strong / Moderate / Weak |
| Target matches known actor focus | | Strong / Moderate / Weak |
| Infrastructure overlaps | | Strong / Moderate / Weak |
| Linguistic/cultural indicators | | Strong / Moderate / Weak |
| Timing/geo-political context | | Strong / Moderate / Weak |

**Overall Attribution Confidence: [High / Medium / Low]**

### 3.3 MITRE ATT&CK Navigator

*Link to Navigator Layer: [URL]*

---

## 4. Infrastructure Analysis

### 4.1 Infrastructure Mapping

| Component | Details | Relationship |
|-----------|---------|-------------|
| Domain 1 | | Phishing landing page |
| Domain 2 | | C2 server |
| IP Address 1 | | Hosting |
| IP Address 2 | | Redirect server |
| Email Account | | Sending source |
| URL | | Shortener/Redirect |

### 4.2 Infrastructure Overlap with Known Campaigns

| IOCs | Known Campaign | Actor | Source | Overlap Type |
|------|----------------|-------|--------|-------------|
| | | | | Domain/IP/Hash/TTP |
| | | | | Domain/IP/Hash/TTP |

---

## 5. Phishing Brand Impersonation

### 5.1 Brand Analysis

| Brand Impersonated | Evidence | Impersonation Technique | Notes |
|-------------------|---------|------------------------|----------|
| | | Login page clone / Email spoof / Domain typo | |
| | | | |

### 5.2 Typosquatting/Looksquatting

| Legitimate Domain | Phishing Domain | Type | Notes |
|-------------------|-----------------|------|----------|
| | | Typosquat / Homograph / Subdomain | |
| | | | |

---

## 6. Social Engineering Analysis

### 6.1 Pretext Analysis

| Element | Details |
|---------|---------|
| Lure Type | Financial urgency / Security alert / Package delivery / HR / IT support / Other |
| Emotional Trigger | Fear / Greed / Curiosity / Authority / Scarcity / Helpfulness |
| Target Audience | Executives / Finance / HR / IT / General staff / Specific individual |

### 6.2 Delivery Mechanism

| Channel | Details |
|---------|---------|
| Email Platform | |
| Spoofing Technique | Display name / SPF bypass / Compromised account / Domain impersonation |
| Attachment Type | |
| Link Type | Direct / Shortened / Redirect chain |

---

## 7. Campaign Sophistication Assessment

### 7.1 Scoring Matrix

| Criterion | Score (1-5) | Notes |
|-----------|-------------|----------|
| Targeting specificity | | |
| Infrastructure quality | | |
| Social engineering quality | | |
| Malware sophistication | | |
| Operational security | | |
| Scale of campaign | | |

**Overall Sophistication Score: /30 (Low: 1-10, Medium: 11-20, High: 21-30)**

### 7.2 Campaign Characteristics

- [ ] Small-scale, targeted
- [ ] Mass phishing campaign
- [ ] Business Email Compromise (BEC)
- [ ] Credential harvesting
- [ ] Malware distribution
- [ ] ransomware precursor
- [ ] Supply chain attack
- [ ] Other: ____________

---

## 8. Related Campaigns and Threat Intelligence

### 8.1 Similar Campaigns

| Campaign | Actor | Date | Similarities | Source |
|----------|-------|------|-------------|--------|
| | | | | |
| | | | | |

### 8.2 Threat Intel References

| Source | Title/Reference | Date | Relevance |
|--------|----------------|------|-----------|
| | | | |
| | | | |

---

## 9. Summary and Conclusions

### 9.1 Key Findings

1.
2.
3.

### 9.2 Attribution Statement

Based on the analysis of indicators of compromise, tactics, techniques, and procedures, the phishing campaign is attributed to **[Threat Actor/Campaign]** with **[High/Medium/Low]** confidence.

### 9.3 Impact on Organization

| Impact Area | Assessment |
|-------------|------------|
| Credential exposure risk | |
| Malware infection risk | |
| Data compromise risk | |
| Lateral movement risk | |
| Business disruption risk | |

---

## 10. Recommendations

| Priority | Recommendation | Details |
|----------|----------------|---------|
| Critical | | |
| High | | |
| Medium | | |
| Low | | |

---

## 11. Document Control

| Field | Value |
|----------|----------|
| Document ID | PHISH-CAA-004 |
| Version | 1.0 |
| Classification | Internal Use Only |
| Created | |
| Last Updated | |
| Reviewed By | |
| Approved By | |

---
