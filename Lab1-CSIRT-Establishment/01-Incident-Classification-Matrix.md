# Incident Classification and Severity Matrix

**Document ID:** CSIRT-ICM-001  
**Version:** 1.0  
**Last Updated:** 2026-05-17  
**Owner:** CSIRT Lead  
**Classification:** Internal Use Only

---

## 1. Purpose

This matrix provides a standardised framework for classifying and prioritising security incidents based on their impact and urgency. It enables consistent decision-making across the CSIRT and ensures appropriate resource allocation.

---

## 2. Severity Levels

| Level | Name | Description | Response Time Target |
|-------|------|-------------|----------------------|
| 1 | Critical | Active breach with significant business impact, data exfiltration in progress, or widespread system compromise | 15 minutes |
| 2 | High | Confirmed security incident with potential for serious impact if not addressed immediately | 1 hour |
| 3 | Medium | Security event requiring investigation; limited impact or contained | 4 hours |
| 4 | Low | Minor security event; no immediate threat, routine investigation | 24 hours |

---

## 3. Incident Categories

| Category Code | Category Name | Description |
|--------------|---------------|-------------|
| CAT-MAL | Malware / Ransomware | Malicious software infection, ransomware, trojans, worms |
| CAT-PHI | Phishing / Social Engineering | Phishing emails, vishing, smishing, credential harvesting |
| CAT-UNA | Unauthorised Access | Brute force attacks, credential stuffing, privilege escalation |
| CAT-DAT | Data Breach / Exfiltration | Unauthorised data access, leakage, or theft |
| CAT-DOS | Denial of Service | DDoS attacks, resource exhaustion, service disruption |
| CAT-INT | Insider Threat | Malicious or negligent actions by employees/contractors |
| CAT-NET | Network Intrusion | Unauthorised network access, lateral movement |
| CAT-WEB | Web Application Attack | SQL injection, XSS, CSRF, file upload exploits |
| CAT-PHY | Physical Security | Unauthorised physical access, tailgating, device theft |
| CAT-OTH | Other | Incidents not covered by above categories |

---

## 4. Impact Scoring

| Impact Factor | Low (1) | Medium (2) | High (3) | Critical (4) |
|---------------|---------|------------|----------|---------------|
| **Data Sensitivity** | Public information only | Internal non-sensitive data | Confidential business data | PII, financial, or regulated data |
| **Systems Affected** | Single non-critical endpoint | Multiple non-critical systems | Critical system partially affected | Multiple critical systems affected |
| **Business Impact** | No operational impact | Minor disruption to non-essential function | Significant disruption to operations | Complete business function failure |
| **Reputational Risk** | No public exposure | Limited internal awareness | Potential for external disclosure | Confirmed public disclosure |
| **Regulatory Impact** | No regulatory implications | Minor compliance concern | Potential regulatory reporting required | Mandatory regulatory notification |

---

## 5. Severity Determination Formula

**Overall Impact Score** = Sum of all Impact Factor scores (max 20)
**Urgency Score** = Assess speed of escalation (1-4, where 4 is immediate threat)

| Overall Impact | Urgency | Resulting Severity |
|----------------|---------|--------------------|
| 16-20 | 3-4 | Level 1 (Critical) |
| 12-20 | 2-3 | Level 2 (High) |
| 8-15 | 1-3 | Level 3 (Medium) |
| 4-11 | 1-2 | Level 4 (Low) |

---

## 6. Classification Examples

| Scenario | Category | Impact Score | Urgency | Severity Level |
|----------|----------|--------------|---------|----------------|
| Ransomware encrypting file server with 500GB of customer PII | CAT-MAL | 19 | 4 | Level 1 - Critical |
| Phishing email opened by one user, no credentials entered | CAT-PHI | 6 | 2 | Level 4 - Low |
| DDoS attack affecting public-facing website for 30 minutes | CAT-DOS | 14 | 3 | Level 2 - High |
| Suspicious login from foreign IP (MFA successful) | CAT-UNA | 8 | 2 | Level 3 - Medium |
| SQL injection attempt on staging server (no data accessed) | CAT-WEB | 5 | 2 | Level 4 - Low |
| Lateral movement detected in production environment | CAT-NET | 17 | 4 | Level 1 - Critical |

---

## 7. Reassessment Triggers

Incidents must be reassessed and reclassified when:

- New information reveals greater scope or impact
- Attack scope expands to additional systems or data
- Third parties or regulators become involved
- Incident duration exceeds initial response time target
- Business context changes (e.g., incident during peak trading)

---

## 8. Escalation Path by Severity

| Severity Level | Initial Responder | Notify | Escalate To |
|----------------|-------------------|--------|-------------|
| Level 4 (Low) | SOC Analyst L1 | Team Lead | Ticketing system |
| Level 3 (Medium) | SOC Analyst L2 | Team Lead, CSIRT Lead | On-call rotation |
| Level 2 (High) | CSIRT Lead | IT Director, Legal | Senior Management |
| Level 1 (Critical) | CSIRT Lead | CISO, Legal, PR, Executive | Incident Commander |

---

## Appendix A: Document History

| Version | Date | Author | Changes |
|---------|------|--------|----------|
| 1.0 | 2026-05-17 | CSIRT Lead | Initial version |
