# Incident Response Playbook (CSIRT-IRP-004)

## Overview

This playbook provides step-by-step instructions for responding to common security incidents. It is designed to be used during active incidents to guide the response team through each phase efficiently and consistently.

## Playbook Index

| ID | Incident Type | Severity | Lead Role |
|----|---------------|----------|----------|
| IRP-001 | Phishing Email | Medium | SOC Analyst |
| IRP-002 | Malware Infection | High | Security Analyst |
| IRP-003 | Ransomware Attack | Critical | Incident Manager |
| IRP-004 | Data Breach | Critical | CISO/Incident Manager |
| IRP-005 | DDoS Attack | High | Network Team Lead |
| IRP-006 | Unauthorised Access | High | Security Analyst |
| IRP-007 | Insider Threat | Medium | Incident Manager |
| IRP-008 | Cloud Compromise | Critical | Cloud Security Lead |

---

## IRP-001: Phishing Email Response

### Trigger
- User reports suspicious email
- Email gateway flags potential phishing
- Security team identifies phishing campaign

### Initial Response (Minutes 0-30)
1. Do NOT open the email or click any links
2. Forward the suspicious email to security@company.com
3. Document the sender, subject, and time received
4. Identify all recipients of the phishing email

### Analysis
- Extract URLs and domain names from the email
- Check URLs against threat intelligence platforms (VirusTotal, URLhaus)
- Analyse email headers for spoofing indicators
- Hash any attachments and check against malware databases
### Containment
- Block sender domain at email gateway
- Block extracted URLs at web proxy/firewall
- Quarantine the phishing email from all recipients
- Reset credentials for any users who clicked links

### Eradication
- Remove phishing emails from all mailboxes
- Blacklist sender domains and IPs
- Update email filtering rules and spam signatures
- Run antivirus scans on affected endpoints

### Recovery
- Communicate with affected users
- Restore any modified data from backups if needed
- Re-enable email access after verification

### Post-Incident
- Update phishing awareness training with real example
- Review and improve email gateway rules
- Document lessons learned

---

## IRP-002: Malware Infection Response

### Trigger
- EDR/antivirus alert on endpoint
- SIEM detects suspicious process behaviour
- User reports slow performance or popups
- Unusual network traffic patterns

### Initial Response (Minutes 0-30)
1. Isolate the affected system from the network immediately
2. Do NOT reboot or power off the system
3. Document the affected system details (hostname, IP, user)
4. Note all EDR/antivirus alerts and indicators

### Analysis
- Capture memory dump for forensic analysis
- Identify malware family and hash (use VirusTotal)
- Map IOCs to MITRE ATT&CK techniques
- Search SIEM for lateral movement indicators
- Check for persistence mechanisms (scheduled tasks, registry, services)

### Containment
- Block malicious IPs/domains at firewall
- Disable affected user account
- Block malware hash at endpoint protection
- Scan other systems for same indicators

### Eradication
- Remove malware using approved tools
- Clean registry entries and startup items
- Remove persistence mechanisms
- Patch exploited vulnerabilities
- Reimage system if infection cannot be fully cleaned

### Recovery
- Restore system from clean backup or rebuild
- Reconnect to network with enhanced monitoring
- Reset compromised credentials
- Verify system integrity before production use

### Post-Incident
- Update endpoint protection signatures
- Review initial infection vector
- Document IOCs for threat intelligence
- Update vulnerability management priorities

---

## IRP-003: Ransomware Attack Response

### Trigger
- Files encrypted with ransom note
- Ransomware appears in EDR/SIEM alerts
- Users report inability to access files
- Network file shares becoming inaccessible

### CRITICAL: Initial Response (Minutes 0-15)
1. Isolate affected systems IMMEDIATELY - disconnect from network
2. Identify the ransomware variant (check ransom note, file extensions)
3. Do NOT pay the ransom - notify management and law enforcement
4. Engage crisis management and executive leadership
5. Preserve all evidence for investigation

### Containment (Minutes 15-60)
- Isolate all potentially affected systems
- Disable network shares and mapped drives
- Block known C2 IPs/domains at perimeter
- Identify patient zero and infection vector
- Secure backup systems - verify they are clean
- Implement emergency access for critical systems only

### Analysis
- Identify ransomware family and strain
- Determine scope of encryption (systems, files, backups)
- Map attack chain using MITRE ATT&CK
- Identify initial access method
- Check for data exfiltration before encryption

### Eradication and Recovery
- Wipe and rebuild all affected systems
- Restore data from verified clean backups
- Do NOT restore from backups that may contain malware
- Reset ALL credentials in affected environment
- Patch vulnerabilities that enabled initial access
- Implement enhanced monitoring on restored systems

### Post-Incident
- Full forensic investigation
- Notify regulators and affected parties (GDPR compliance)
- Review and improve backup strategy (3-2-1 rule)
- Conduct organisation-wide ransomware awareness training
- Implement email authentication (SPF, DKIM, DMARC)
- Deploy application allowlisting

---

## IRP-004: Data Breach Response

### Trigger
- Unauthorised data access detected in logs
- Data loss prevention (DLP) alert
- Third-party notification of breach
- Suspicious bulk data transfer detected

### Initial Response
1. Identify the type of data compromised (PII, financial, IP)
2. Determine scope and number of affected records
3. Engage legal and compliance teams immediately
4. Preserve forensic evidence
5. Do NOT communicate externally without legal approval

### Assessment
- Classify data sensitivity (personal, financial, confidential)
- Determine jurisdictional requirements (GDPR, DPA 2018)
- Identify attack vector and timeline
- Assess if data was exfiltrated or just accessed
- Identify affected individuals or systems

### Containment
- Revoke access for compromised accounts
- Block data exfiltration channels
- Implement additional access controls
- Secure affected databases and file shares

### Notification Requirements
| Regulation | Notification Timeline | Authority |
|------------|---------------------|------------|
| GDPR | 72 hours | ICO (UK) |
| Data Protection Act 2018 | Without undue delay | ICO |
| PCI DSS | Immediately | Card brands/acquirer |
| Internal policy | As per contractual obligations | Affected parties |

### Recovery
- Patch vulnerabilities that enabled breach
- Implement additional security controls
- Reset credentials for affected accounts
- Enhance monitoring on affected data stores
- Conduct penetration testing

### Post-Incident
- Complete ICO notification within 72 hours if required
- Notify affected individuals per regulatory requirements
- Review and update data classification and handling procedures
- Conduct data protection impact assessment (DPIA)
- Document lessons learned and update policies

---

## IRP-005: DDoS Attack Response

### Trigger
- SIEM/monitoring detects traffic spike
- Website/services become unavailable
- Network team reports saturation
- CDN/WAF alerts on attack traffic

### Initial Response
1. Confirm DDoS from traffic analysis (not maintenance or legitimate spike)
2. Engage ISP and DDoS mitigation provider
3. Notify stakeholders of service degradation
4. Activate DDoS response procedures

### Mitigation
- Enable DDoS protection at network perimeter
- Implement rate limiting on affected services
- Route traffic through CDN/mirroring service
- Block attacking IP ranges at firewall
- Adjust WAF rules for attack pattern
- Scale infrastructure if cloud-based

### Recovery
- Monitor for attack continuation
- Gradually restore normal traffic routing
- Validate service functionality
- Review logs for any successful intrusions during attack

### Post-Incident
- Analyse attack vectors and refine defences
- Update DDoS response procedures
- Consider implementing always-on DDoS protection
- Document attack characteristics for threat intelligence

---

## IRP-006: Unauthorised Access Response

### Trigger
- SIEM detects login from unusual location/time
- Failed login threshold exceeded
- Impossible travel alerts
- New admin account creation detected

### Initial Response
1. Immediately disable the compromised account
2. Document all suspicious activity
3. Identify the access method used
4. Check for lateral movement

### Analysis
- Review authentication logs for the account
- Identify the source IP and device
- Check for use of new MFA devices or methods
- Look for privilege escalation attempts
- Map activity to MITRE ATT&CK techniques

### Containment
- Force password reset for affected account
- Review and revoke all active sessions
- Audit other accounts for similar patterns
- Block suspicious IPs at firewall

### Eradication
- Remove any backdoors or persistence
- Patch authentication vulnerabilities
- Review and tighten access controls
- Implement additional MFA requirements

### Recovery
- Restore legitimate user access
- Monitor account for recurring suspicious activity
- Verify no unauthorised changes were made

### Post-Incident
- Review access control policies
- Implement adaptive authentication
- Update user awareness training
- Consider implementing zero-trust architecture

---

## IRP-007: Insider Threat Response

### Trigger
- DLP detects sensitive data transfer
- Unusual access patterns to sensitive systems
- Employee reported suspicious behaviour
- Multiple failed access attempts by internal user

### Initial Response
1. Document all suspicious activity discreetly
2. Engage HR and legal teams
3. Do NOT confront the individual yet
4. Preserve evidence for potential investigation

### Analysis
- Review all system access by the individual
- Check for data exfiltration (email, USB, cloud upload)
- Analyse access patterns and timing
- Interview relevant witnesses (coordinate with HR)

### Containment
- Restrict access to sensitive systems
- Monitor all activity covertly if still investigating
- Revoke physical access if warranted
- Implement additional logging on sensitive resources

### Recovery
- Review and revoke inappropriate access
- Update access control matrices
- Implement enhanced monitoring for sensitive data
- Conduct access recertification

### Post-Incident
- Update insider threat detection procedures
- Review data access policies and training
- Consider implementing user behaviour analytics (UBA)
- Enhance data classification and handling procedures

---

## IRP-008: Cloud Compromise Response

### Trigger
- Cloud monitoring alerts on suspicious activity
- Unauthorised IAM changes detected
- New resources created without approval
- API key/token compromise suspected

### Initial Response
1. Identify the compromised cloud account/service
2. Rotate all credentials and access keys
3. Review and document all changes made
4. Engage cloud provider security team if needed

### Analysis
- Review CloudTrail/Activity Logs for all actions
- Identify compromised credentials and access path
- Check for unauthorised resource creation or modification
- Map actions to MITRE ATT&CK for Cloud techniques
- Assess data exposure in cloud storage (S3, Blob, etc.)

### Containment
- Disable compromised credentials and keys
- Implement stricter IAM policies
- Enable additional logging and monitoring
- Isolate affected cloud resources if possible

### Eradication
- Remove unauthorised resources
- Revoke all suspicious IAM roles and policies
- Delete compromised API keys and tokens
- Patch misconfigurations and vulnerabilities

### Recovery
- Restore legitimate configurations
- Implement cloud security posture management (CSPM)
- Re-enable services with hardened configurations
- Verify data integrity in cloud storage

### Post-Incident
- Review cloud security architecture
- Implement least-privilege IAM policies
- Enable comprehensive cloud logging
- Conduct cloud security training for teams
- Consider implementing cloud-native security tools

---

## General Playbook Usage Notes

### When to Use
- During active security incidents
- As training material for SOC analysts
- For tabletop exercises and simulations

### Customisation
- Update contact details and email addresses
- Adjust escalation paths to match your organisation
- Add or remove playbooks based on your threat landscape
- Regularly review and update based on lessons learned

### Escalation Triggers
| Condition | Escalate To |
|-----------|------------|
| Incident exceeds SLA | Incident Manager |
| Critical/Catastrophic severity | CISO |
| Legal/regulatory implications | Legal + CISO |
| Reputational risk | Executive Team |
| Third-party involvement | Procurement + Legal |

### Tool Integration
- **SIEM**: Wazuh/Splunk for detection and correlation
- **EDR**: Endpoint detection and response actions
- **SOAR**: Automated playbook execution where possible
- **Ticketing**: Jira/ServiceNow for incident tracking
- **Communication**: Secure channels for sensitive information

---

## Document Control

| Field | Value |
|-------|-------|
| Document ID | CSIRT-IRP-004 |
| Version | 1.0 |
| Classification | Internal Use Only |
| Owner | CSIRT Manager |
| Review Frequency | Quarterly |
| Next Review | Q2 2026 |
