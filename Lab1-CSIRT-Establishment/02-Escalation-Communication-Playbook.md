# CSIRT Escalation and Communication Playbook

**Document ID:** CSIRT-ECP-002  
**Version:** 1.0  
**Last Updated:** 2026-05-17  
**Owner:** CSIRT Lead  
**Classification:** Internal Use Only

---

## 1. Purpose

This playbook defines the escalation procedures and communication protocols to be followed during a security incident. It ensures timely, accurate, and controlled information flow to all relevant stakeholders.

---

## 2. Communication Principles

- **Need to Know:** Information shared only on a need-to-know basis
- **Single Source of Truth:** All incident updates originated from the Incident Commander (IC)
- **Time-Bound:** Updates provided within defined SLAs per severity level
- **Accuracy:** No speculation; only confirmed facts communicated
- **Audit Trail:** All communications logged in the incident ticket

---

## 3. Roles and Communication Responsibilities

| Role | Communication Responsibility |
|------|------------------------------|
| SOC Analyst L1 | Initial detection alert to L2; document findings in ticket |
| SOC Analyst L2 | Technical updates to CSIRT Lead; coordinate with L1 |
| CSIRT Lead | Primary communications; updates to IT Director and stakeholders |
| Incident Commander | Executive updates; decides on external communications |
| Comms Lead | Draft external statements; liaise with PR/legal |
| Legal | Advise on regulatory notification obligations |
| PR | Manage media and public communications |

---

## 4. Internal Communication Matrix

| Severity | T+0 (Initial) | T+30min | T+1hr | T+4hr | T+24hr |
|----------|---------------|---------|-------|-------|--------|
| Level 1 (Critical) | CSIRT Lead, IC, IT Dir, Legal, CISO | Executive briefing | Stakeholder update | Status review | Post-incident report |
| Level 2 (High) | CSIRT Lead, Team Lead | IT Director notified | Status update | Resolution plan | Closure report |
| Level 3 (Medium) | Team Lead, CSIRT Lead | - | Status update | Resolution update | Closure |
| Level 4 (Low) | Ticketing system | Team Lead review | - | Resolution | Closure |

---

## 5. Escalation Triggers

### Automatic Escalation Conditions

| Condition | Escalate To | Timeframe |
|-----------|-------------|-----------|
| Severity upgraded by one or more levels | CSIRT Lead | Immediately |
| Incident involves PII or regulated data | Legal, CISO | Within 15 minutes |
| Attack scope expands beyond initial systems | CSIRT Lead | Immediately |
| Response time SLA exceeded | Team Lead / CSIRT Lead | At SLA breach |
| Media or public inquiry received | PR, Legal, IC | Immediately |
| Regulator initiates contact | Legal, CISO, IC | Immediately |
| Third-party vendor involved in incident | Vendor Management, Legal | Within 1 hour |

### Discretionary Escalation

Any team member may escalate if they believe:
- The incident is more severe than currently classified
- Resources are insufficient to manage the situation
- There is a potential conflict of interest
- They are unsure how to proceed

---

## 6. Communication Channels

| Channel | Use Case | Security |
|---------|----------|----------|
| SIEM / Ticketing System | All incident logging and updates | Encrypted, access-controlled |
| Dedicated Slack Channel | Real-time team coordination | Private channel, invite-only |
| Secure Email | Formal notifications to stakeholders | Encrypted via PGP/S/MIME |
| Phone / Video Call | Critical incident bridge calls | Authenticated participants only |
| Incident War Room (physical/virtual) | Active response coordination | Restricted access |

### Bridge Call Protocol

**Trigger:** Level 1 or Level 2 incidents  
**Host:** Incident Commander  
**Scribe:** Designated SOC Analyst  
**Frequency:**
- Level 1: Every 30 minutes while active
- Level 2: Every 2 hours while active

**Bridge Call Agenda:**
1. Current incident status (IC)
2. Actions taken since last update
3. Blockers or resource needs
4. Next steps and owners
5. ETA for next update

---

## 7. External Communication

### Regulatory Notification

| Regulation | Trigger | Timeline | Responsible Party |
|------------|---------|----------|--------------------|
| UK GDPR Article 33 | Personal data breach likely to result in risk | 72 hours to ICO | Legal / DPO |
| UK GDPR Article 34 | High risk to individuals | Without undue delay | Legal / DPO |
| NIS Regulations 2018 | Significant incident to OES | Without undue delay | Legal / CSIRT |
| PCI DSS | Cardholder data breach | Immediately to acquirer | Legal / Finance |

### Public / Media Communication

- All media inquiries directed to PR Lead
- No individual CSIRT member to speak to media
- Pre-approved holding statement maintained
- Social media monitored for incident-related discussion

---

## 8. Post-Incident Communications

| Deliverable | Audience | Owner | Timeline |
|-------------|----------|-------|----------|
| Incident Closure Report | Internal team | CSIRT Lead | Within 5 business days |
| Executive Summary | Senior Management | CSIRT Lead | Within 3 business days |
| Root Cause Analysis | Technical team | CSIRT Lead | Within 10 business days |
| Lessons Learned Report | CSIRT team | All members | Within 10 business days |
| Regulatory Notification | ICO / Relevant regulator | Legal / DPO | Per regulatory timeline |

---

## 9. Contact Directory Template

| Role | Name | Primary Contact | Secondary Contact | Escalation Contact |
|------|------|-----------------|-------------------|--------------------------|
| Incident Commander | [Name] | Phone / Email | Slack | - |
| CSIRT Lead | [Name] | Phone / Email | Slack | CISO |
| SOC Team Lead | [Name] | Phone / Email | Slack | CSIRT Lead |
| Legal | [Name] | Phone / Email | Slack | Legal Director |
| PR Lead | [Name] | Phone / Email | Slack | Comms Director |
| IT Director | [Name] | Phone / Email | Slack | CTO |
| CISO | [Name] | Phone / Email | Slack | CEO |
| External Forensics | [Vendor] | 24/7 Hotline | - | CSIRT Lead |
| Law Enforcement | [Contact] | As required | - | Legal |

---

## Appendix A: Sample Notification Templates

### Level 1 Incident - Initial Executive Notification

```
URGENT: Security Incident Notification

Severity: Level 1 - Critical
Time Detected: [TIMESTAMP]
Category: [CATEGORY]
Systems Affected: [SYSTEMS]
Initial Assessment: [BRIEF DESCRIPTION]
Next Update: [TIME]
Bridge Call: [LINK/NUMBER]
```

### Level 2 Incident - Stakeholder Update

```
Security Incident Update - [INCIDENT ID]

Current Status: [STATUS]
Actions Taken: [LIST]
Business Impact: [DESCRIPTION]
Next Steps: [LIST]
Req from Stakeholders: [IF ANY]
Next Update: [TIME]
```
