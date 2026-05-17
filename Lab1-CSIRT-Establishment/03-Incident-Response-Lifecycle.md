# Incident Response Lifecycle (CSIRT-IRL-003)

## Overview

This document defines the standard incident response lifecycle for the CSIRT team. The lifecycle follows NIST SP 800-61 and ISO/IEC 27035 frameworks and consists of six phases:

1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned (Post-Incident Review)

---

## Phase 1: Preparation

**Objective:** Ensure the organisation is ready to detect, respond to, and recover from security incidents.

### Activities
- Deploy and configure monitoring tools (SIEM, EDR, IDS/IPS)
- Establish and document CSIRT roles and responsibilities
- Develop and maintain incident response playbooks and SOPs
- Conduct regular tabletop exercises and simulations
- Maintain asset inventory and classification register
- Establish secure communication channels for incident response
- Define and test backup and recovery procedures

### Key Documents
- CSIRT Charter and SOPs
- Asset Inventory
- Network Diagrams
- Contact Lists and Escalation Paths

---

## Phase 2: Identification

**Objective:** Detect and validate security incidents through monitoring and analysis.

### Activities
- Monitor SIEM alerts and security tool notifications
- Triage incoming alerts and determine validity
- Correlate events across multiple data sources
- Classify the incident using the Incident Classification Matrix (CSIRT-ICM-001)
- Determine initial severity level and impact
- Log the incident in the ticketing/tracking system
- Notify relevant stakeholders based on escalation criteria

### Identification Sources
- SIEM alerting (Wazuh/Splunk)
- EDR telemetry
- IDS/IPS alerts
- User reports (helpdesk tickets, emails)
- Threat intelligence feeds
- Vulnerability scanner results
- Log analysis

### Decision Criteria
| Condition | Action |
|-----------|--------|
| Confirmed security incident | Proceed to Containment |
| False positive | Document and close |
| Requires further investigation | Assign to analyst for analysis |

---

## Phase 3: Containment

**Objective:** Limit the scope and impact of the incident to prevent further damage.

### Short-Term Containment (Immediate)
- Isolate affected systems from the network
- Block malicious IPs and domains at firewall/proxy
- Disable compromised user accounts
- Preserve evidence (memory dumps, disk images, logs)
- Document all containment actions with timestamps

### Long-Term Containment (Sustained)
- Apply patches to vulnerable systems
- Implement additional network segmentation
- Deploy enhanced monitoring on affected segments
- Rotate credentials for affected systems and accounts
- Update firewall rules and access controls

### Evidence Preservation Checklist
- [ ] Memory dump captured
- [ ] Disk image created
- [ ] Network traffic logs preserved
- [ ] System event logs exported
- [ ] Malware samples collected
- [ ] Chain of custody documented

---

## Phase 4: Eradication

**Objective:** Remove the root cause of the incident and all associated threats.

### Activities
- Remove malware and malicious files from affected systems
- Delete attacker-created user accounts
- Close backdoors and persistence mechanisms
- Remediate vulnerabilities that enabled the incident
- Update antivirus/EDR signatures
- Clean registry entries and scheduled tasks
- Sanitise affected databases and web applications

### Verification
- [ ] Full malware scan completed - clean results
- [ ] Persistence mechanisms verified removed
- [ ] Vulnerability patch confirmed and tested
- [ ] System baseline integrity verified
- [ ] No indicators of compromise (IoCs) remain

---

## Phase 5: Recovery

**Objective:** Restore systems and services to normal operation securely.

### Activities
- Restore systems from clean backups where necessary
- Rebuild compromised systems from trusted images
- Reinstate user access and accounts
- Reconnect systems to production network
- Monitor restored systems closely for 48-72 hours
- Validate business operations and data integrity
- Update documentation for any infrastructure changes

### Recovery Approval Process
| System Type | Approval Required From |
|-------------|-----------------------|
| End-user workstation | IT Support Manager |
| Server | Infrastructure Team Lead |
| Network device | Network Team Lead |
| Critical business application | CISO or IT Director |

### Monitoring During Recovery
- Enhanced SIEM monitoring on recovered assets
- Daily malware scans
- Log review for the first 72 hours
- User activity monitoring for anomalies

---

## Phase 6: Lessons Learned (Post-Incident Review)

**Objective:** Analyse the incident to improve future response capabilities.

### Activities
- Conduct post-incident review meeting within 5 business days
- Complete the Post-Incident Review Template (CSIRT-PIR-005)
- Identify root cause using the 5 Whys technique
- Document timeline of events from detection to resolution
- Evaluate response effectiveness against SLAs
- Identify gaps in controls, processes, and tools
- Develop remediation action items with owners and deadlines
- Update playbooks and SOPs based on lessons learned
- Share relevant threat intelligence with industry peers

### Review Meeting Attendees
- Incident Manager
- Lead Analyst
- Relevant technical teams
- Management representative
- Legal/Compliance (if applicable)

### Key Metrics to Review
- Time to Detect (TTD)
- Time to Respond (TTR)
- Time to Contain (TTC)
- Time to Resolve (TTRes)
- Impact vs. expected impact
- Effectiveness of containment measures
- Communication timeliness and accuracy

---

## Lifecycle Summary

| Phase | Key Action | Lead Role |
|-------|-----------|----------|
| 1. Preparation | Build capabilities before incidents occur | CSIRT Manager |
| 2. Identification | Detect and validate incidents | SOC Analyst |
| 3. Containment | Limit damage and preserve evidence | Incident Manager |
| 4. Eradication | Remove root cause and threats | Security Analyst |
| 5. Recovery | Restore normal operations | Infrastructure Team |
| 6. Lessons Learned | Improve future response | CSIRT Manager |

---

## References
- NIST SP 800-61 Rev. 2 - Computer Security Incident Handling Guide
- ISO/IEC 27035-1:2016 - Information Security Incident Management
- SANS Incident Handler's Handbook
- MITRE ATT&CK Framework for threat mapping
