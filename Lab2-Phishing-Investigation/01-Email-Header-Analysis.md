# 01 - Email Header Analysis

## Document Information

| Field | Value |
|-------|-------|
| Document ID | PHISH-EHA-001 |
| Version | 1.0 |
| Classification | Internal Use Only |
| Owner | SOC Analyst |
| Date of Analysis | |
| Analyst | |

---

## Task Overview

Analyse the email headers from a suspected phishing email to trace its routing path, identify the originating server, and detect spoofing or manipulation indicators.

---

## Email Metadata Summary

| Field | Value |
|-------|-------|
| Subject | |
| Sender (From) | |
| Reply-To | |
| Return-Path | |
| Recipient (To) | |
| Date Sent | |
| Message-ID | |
| X-Originating-IP | |

---

## Full Header Analysis

### Received Headers (Bottom to Top)

| # | Received From | Received By | IP Address | Timestamp | SPF/DKIM/DMARC | Notes |
|---|---------------|-------------|------------|-----------|----------------|-------|
| | | | | | | |
| | | | | | | |
| | | | | | | |
| | | | | | | |

### Authentication Results

| Method | Result | Domain | Notes |
|--------|--------|--------|-------|
| SPF (Sender Policy Framework) | | | |
| DKIM (DomainKeys Identified Mail) | | | |
| DMARC | | | |

---

## Header Anomalies and Red Flags

### Suspicious Indicators Found

- [ ] From address does not match Reply-To
- [ ] From address does not match Return-Path
- [ ] Missing or failed SPF record
- [ ] DKIM signature missing or invalid
- [ ] DMARC policy not enforced
- [ ] Received headers show unusual routing path
- [ ] IP geolocation inconsistent with claimed sender
- [ ] X-Mailer/X-Originator shows suspicious client
- [ ] Message-ID format unusual or forged
- [ ] Missing Message-ID header
- [ ] Content-Type manipulation detected
- [ ] HTML content mismatches plain text version
- [ ] Evocator header anomalies

### Spoofing Analysis

| Check | Pass/Fail | Evidence |
|-------|-----------|----------|
| Display name matches actual address | | |
| Domain matches legitimate organisation | | |
| No homograph/typosquatting in domain | | |
| Sending server authorised for domain | | |

---

## Header Parsing Details

### Critical Headers

**MIME-Version:** |
**Content-Type:** |
**Content-Transfer-Encoding:** |
**X-Priority:** |
**X-Mailer:** |
**X-Originating-IP:** |
**Authentication-Results:** |
**Received-SPF:** |

---

## IP Address Analysis

### Originating IP

| Field | Value |
|-------|-------|
| IP Address | |
| Geolocation | |
| ISP/AS Number | |
| Reverse DNS | |
| Known Malicious | |
| Blacklist Status | |

### Blacklist Checks

| Blacklist | Status | Result |
|-----------|--------|--------|
| Spamhaus SBL | | |
| Spamhaus CSS | | |
| Barracuda | | |
| SpamCop | | |
| SURBL | | |

---

## Timeline of Email Journey

| Hop | Server/Location | Action | Timestamp | Trustworthiness |
|-----|----------------|--------|-----------|----------------|
| 1 | Origin | Email sent | | |
| 2 | First relay | | | |
| 3 | Second relay | | | |
| 4 | Destination server | Email received | | |

---

## Evidence Preserved

| Item | Description | Storage Location |
|------|-------------|-------------------|
| Raw .eml file | Original email with headers | |
| Header screenshot | Annotated header view | |
| IP lookup results | Geolocation and ASN data | |
| Authentication logs | SPF/DKIM/DMARC results | |

---

## Findings Summary

### Verdict

| Category | Finding |
|----------|---------|
| Classification | Phishing / Spam / Legitimate / Suspicious |
| Confidence Level | High / Medium / Low |
| Severity | Critical / High / Medium / Low |
| Immediate Action Required | Yes / No |

### Key Findings

1. 
2. 
3. 

---

## Next Steps

- [ ] Proceed to IOC Extraction (02-IOC-Extraction-Template.md)
- [ ] Block sender domain
- [ ] Add originating IP to blocklist
- [ ] Notify affected users
- [ ] Escalate to Incident Response team
- [ ] Submit report

---

## Analyst Notes

_Add any additional observations or context:_

---

## Document Control

| Field | Value |
|-------|-------|
| Document ID | PHISH-EHA-001 |
| Version | 1.0 |
| Classification | Internal Use Only |
| Owner | SOC Analyst |
| Review Frequency | Per Investigation |
| Last Modified | |
