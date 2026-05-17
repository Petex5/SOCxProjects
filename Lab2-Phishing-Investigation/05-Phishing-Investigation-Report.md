# 05. Phishing Investigation Report

---

## Document Information

| Field | Value |
|-------|-------|
| **Report ID** | PHIR-2026-001 |
| **Title** | Phishing Investigation Report - Suspicious Credential Harvesting Campaign |
| **Classification** | Internal Use Only |
| **Investigator(s)** | [SOC Analyst Name(s)] |
| **Date Opened** | [YYYY-MM-DD] |
| **Date Closed** | [YYYY-MM-DD] |
| **Version** | 1.0 |

---

## 1. Executive Summary

### 1.1 Incident Overview

A coordinated phishing campaign was detected targeting organizational email accounts. The campaign utilized credential harvesting techniques via falsified Microsoft 365 login pages to capture user credentials.

### 1.2 Key Findings

- Total emails received: **[number]**
- Affected users: **[number]**
- Credentials potentially compromised: **[number]**
- Malicious domains identified: **[list]**
- Attack timeframe: **[start date] to [end date]**

### 1.3 Severity Assessment

| Severity | Score | Justification |
|----------|-------|---------------|
| Impact | High | Credential compromise risk |
| Likelihood | High | Active campaign observed |
| Overall | **High** | Immediate action required |

---

## 2. Incident Details

### 2.1 Initial Detection

The incident was detected through:
- [ ] Email gateway alert (Proofpoint/Mimecast)
- [ ] SIEM correlation rule (Microsoft Sentinel)
- [ ] User report
- [ ] Threat intelligence feed
- [ ] Other: _________

### 2.2 Timeline of Events

| Date/Time (UTC) | Event | Description |
|----------------|-------|-------------|
| [Timestamp] | First email sent | Initial phishing email dispatched |
| [Timestamp] | First click detected | User interaction with malicious link |
| [Timestamp] | Incident reported | SOC team notified |
| [Timestamp] | Investigation initiated | Triage began |
| [Timestamp] | Containment actions | Remediation steps taken |
| [Timestamp] | Investigation closed | Final report completed |

### 2.3 Attack Method

#### 2.3.1 Phishing Vector
- Delivery method: **Email**
- Spoofed sender: **[sender address]**
- Subject line: **[email subject]**
- Landing page: **[malicious URL]**

#### 2.3.2 Social Engineering Techniques
- [ ] Urgency/Threat (account suspension)
- [ ] Authority impersonation (IT/Admin)
- [ ] FOMO (limited-time offer)
- [ ] Curiosity (package delivery)
- [ ] Trust exploitation (known brand)
- [ ] Other: _________

---

## 3. Email Header Analysis

### 3.1 Original Email Headers

```
[Paste full email headers here]
```

### 3.2 Header Analysis Summary

| Header Field | Value | Analysis |
|-------------|-------|----------|
| From | [value] | [spoofed/genuine] |
| Reply-To | [value] | [discrepancy noted] |
| Return-Path | [value] | [matches sender] |
| Received-SPF | [value] | [pass/fail] |
| DKIM-Signature | [value] | [valid/invalid] |
| DMARC | [value] | [pass/fail] |

### 3.3 IP Address Tracing

| IP Address | ASN | Country | Reputation |
|-----------|-----|---------|------------|
| [IP] | [ASN] | [Country] | [Malicious/Legitimate] |

---

## 4. Indicators of Compromise (IOCs)

### 4.1 Network Indicators

| Type | Value | Threat Intel Result | Confidence |
|------|-------|--------------------|------------|
| Domain | [domain] | [VirusTotal/Whois findings] | High/Medium/Low |
| IP Address | [IP] | [GeoIP/Blacklist status] | High/Medium/Low |
| URL | [URL] | [Malware analysis result] | High/Medium/Low |

### 4.2 Host-Based Indicators

| Type | Value | Description |
|------|-------|-------------|
| File Hash (MD5) | [hash] | [Suspected payload] |
| File Hash (SHA256) | [hash] | [Suspected payload] |
| File Hash (SHA1) | [hash] | [Suspected payload] |
| File Name | [filename] | [Attachment type] |

### 4.3 Email Indicators

| Indicator | Value | Analysis |
|-----------|-------|----------|
| Sender Address | [email] | [Domain analysis] |
| From Name | [name] | [Impersonated entity] |
| Language | [language] | [Language characteristics] |

---

## 5. Threat Intelligence Findings

### 5.1 Domain Intelligence

**WHOIS Lookup Results:**
- Registrar: **[registrar]**
- Registration Date: **[date]**
- Registrant Country: **[country]**
- Name Servers: **[NS records]**
- Age Analysis: **[recently registered/established]**

**DNS Records:**
- A Record: **[IP address]**
- MX Records: **[mail servers]**
- TXT Records: **[TXT data]**

### 5.2 IP Intelligence

- IP: **[address]**
- Geolocation: **[city, country]**
- ASN: **[AS number and name]**
- IP Category: **[hosting/ISP/datacenter]**
- Blacklist Status: **[listed on [lists]]**

### 5.3 VirusTotal Analysis

| Scan Type | Detections | First Seen |
|-----------|-----------|------------|
| URL Scan | [X]/[Y] vendors | [date] |
| Domain Scan | [X]/[Y] vendors | [date] |
| File Hash Scan | [X]/[Y] vendors | [date] |

### 5.4 Threat Actor Attribution

- Campaign Name: **[known campaign name]**
- Threat Actor: **[actor name/codenamed]**
- TTP Mapping: MITRE ATT&CK Techniques
  - T1566.002 - Spearphishing Link
  - T1566.001 - Spearphishing Attachment
  - T1597 - Search Open Websites/Domains
  - T1592 - Gather Victim Host Information

---

## 6. Impact Assessment

### 6.1 Affected Users

| User | Department | Email Action | Credential Exposed | Follow-up Required |
|------|-----------|--------------|-------------------|--------------------|
| [Name/ID] | [Dept] | Clicked link |
| [Name/ID] | [Dept] | Entered credentials | Yes |
| [Name/ID] | [Dept] | Downloaded attachment |

### 6.2 Systems Affected

| System | Impact | Status |
|--------|--------|--------|
| [Email system] | [Description] | [Remediated] |
| [AD/Entra ID] | [Description] | [Remediated] |
| [Other] | [Description] | [Remediated] |

### 6.3 Risk Quantification

| Risk Category | Pre-Mitigation | Post-Mitigation |
|---------------|--------------|----------------|
| Financial | [score level] | [score level] |
| Operational | [score level] | [score level] |
| Reputational | [score level] | [score level] |
| Compliance | [score level] | [score level] |

---

## 7. Containment and Eradication

### 7.1 Immediate Actions Taken

- [ ] Blocked malicious domain at email gateway
- [ ] Reset compromised user credentials
- [ ] Enabled MFA for affected accounts
- [ ] Quarantined phishing emails from all mailboxes
- [ ] Updated email filtering rules
- [ ] Notified affected users
- [ ] Escalated to incident response team

### 7.2 Eradication Steps

1. **Credential Reset** - All compromised accounts had passwords reset
2. **Session Termination** - Active sessions for affected users were terminated
3. **Malicious Content Removal** - Phishing emails purged from all mailboxes
4. **Domain Blocklist** - Malicious domains added to permanent blocklist

---

## 8. Recovery

- [ ] User access restored
- [ ] Systems verified operational
- [ ] No residual compromises detected
- [ ] Normal operations resumed

---

## 9. Recommendations

### 9.1 Immediate Recommendations (Action within 24 hours)

1. [ ] Force password reset for all users who clicked links
2. [ ] Review and revoke suspicious OAuth app permissions
3. [ ] Monitor affected accounts for anomalous activity
4. [ ] Brief department heads on the threat

### 9.2 Short-term Recommendations (Action within 1 week)

1. [ ] Deploy updated email filtering signatures
2. [ ] Conduct targeted phishing awareness training
3. [ ] Review and update SPF/DKIM/DMARC records
4. [ ] Implement additional authentication controls

### 9.3 Long-term Recommendations (Action within 1 month)

1. [ ] Conduct organization-wide phishing simulation
2. [ ] Evaluate advanced email security solutions
3. [ ] Implement threat hunting for similar IOCs
4. [ ] Update incident response playbooks
5. [ ] Review and enhance monitoring capabilities

---

## 10. Lessons Learned

### 10.1 What Went Well
- [List successful response actions]

### 10.2 Areas for Improvement
- [List gaps identified during response]

### 10.3 Process Improvements
- [List recommended process changes]

---

## 11. Appendices

### Appendix A: Evidence References

| Evidence ID | Type | Location | Hash |
|-------------|------|----------|------|
| EVD-001 | Email message | [Evidence store] | [hash] |
| EVD-002 | Screenshot | [Evidence store] | - |
| EVD-003 | Log file | [Evidence store] | [hash] |

### Appendix B: Tools Used

| Tool | Purpose | Version |
|------|---------|---------|
| Microsoft Sentinel | SIEM/Analysis | [version] |
| VirusTotal | IOC lookup | Web |
| MXToolbox | DNS lookups | Web |
| WHOIS Lookup | Domain intelligence | Web |
| [Other tools] | [Purpose] | [version] |

### Appendix C: References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide
- ISO/IEC 27035 - Information Security Incident Management
- CISA Phishing Alert Resources

---

## 12. Document Control

| Field | Value |
|-------|-------|
| **Document ID** | PHIR-2026-001 |
| **Version** | 1.0 |
| **Classification** | Internal Use Only |
| **Created** | [YYYY-MM-DD] |
| **Approved By** | [Name/Title] |
| **Review Cycle** | Every 6 months |

---

*This report is part of the SOCxProjects Lab 2: Phishing Investigation training exercise.*
