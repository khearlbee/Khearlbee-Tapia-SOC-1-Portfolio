# 🛡️ Project 4: Incident Response & Documentation

**Objective:** Document and respond to security incidents discovered in previous projects, create formal incident reports, and develop response procedures.

---

## Overview

Incident response is where detection translates into action. This project focuses on documenting discovered attacks from Projects 1-3 into formal incident reports, creating response playbooks, and establishing procedures for handling similar incidents in the future.

### Key Learning Areas
- Incident classification and severity assessment
- Formal incident report writing
- Timeline reconstruction and analysis
- Root cause analysis (RCA)
- Remediation and recovery procedures
- Communication with stakeholders

---

## Incident Response Framework

### Incident Classification

**Definition:** Determine what happened and categorize for response

| Classification | Description | Examples |
|---|---|---|
| **Malware** | Unauthorized software execution | Trojan, Ransomware, Worm |
| **Unauthorized Access** | Attacker gained system/data access | Brute force, credential theft |
| **Denial of Service** | System/service availability impacted | DDoS, Resource exhaustion |
| **Data Breach** | Sensitive data exposed/exfiltrated | Customer data, credentials |
| **Compliance Violation** | Security policy/regulation breach | PCI-DSS, HIPAA violations |
| **Configuration** | Security misconfiguration exploited | Open shares, weak auth |
| **Social Engineering** | Attacker manipulated users | Phishing, Pretexting |

### Severity Assessment

| Level | Business Impact | Response Time | Actions |
|---|---|---|---|
| **Critical** | Widespread outage, data loss, compliance | < 15 min | Incident declare, full IR team, exec notification |
| **High** | Significant impact, limited scope | < 1 hour | IR escalation, containment, detailed investigation |
| **Medium** | Limited impact, isolated systems | < 4 hours | Investigation, monitoring, remediation planning |
| **Low** | Minimal impact, isolated user | < 24 hours | Log, monitor, routine remediation |

---

## Incident Report Template

### Report Header
```
INCIDENT REPORT
ID: INC-20XX-001
Date: [YYYY-MM-DD]
Reported By: [Name/Team]
Incident Type: [Classification]
Severity: [Critical/High/Medium/Low]
Status: [Investigating/Contained/Resolved/Closed]
```

### Executive Summary
Brief overview suitable for executive/non-technical audience
- What happened (in plain language)
- Systems/data affected
- Business impact
- Current status
- Key recommendation

### Timeline
Chronological sequence of events with specific times

| Time | Event | Evidence |
|---|---|---|
| 2024-01-15 10:23:00 | Brute force attempt detected | SIEM Alert #12345 |
| 2024-01-15 10:25:30 | Successful login from external IP | Windows Event Log 4624 |
| 2024-01-15 10:26:15 | PowerShell execution observed | Process monitoring alert |
| 2024-01-15 10:30:00 | Admin escalation attempted | UAC bypass detected |
| 2024-01-15 10:35:00 | Lateral movement to file server | SMB traffic analysis |

### Indicators of Compromise (IOCs)

| Type | Value | Context | Source |
|---|---|---|---|
| IP Address | 192.0.2.45 | Attacker source | Firewall logs |
| IP Address | 198.51.100.12 | C2 server | SIEM correlation |
| Domain | malicious[.]com | C2 domain | DNS queries |
| File Hash (MD5) | a1b2c3d4e5f6... | Malware binary | Endpoint detection |
| File Hash (SHA256) | 1a2b3c4d5e6f... | Malware binary | Endpoint detection |
| Username | admin_bak | Compromised account | Authentication logs |
| URL | http://internal-server/admin?cmd=... | Exploitation attempt | Web server logs |

### Affected Systems & Users

| Resource | Type | Impact |
|---|---|---|
| HR-SERVER-01 | Windows Server 2019 | Unauthorized access, data accessed |
| John Smith (jsmith) | User Account | Credentials compromised |
| HR Database | Database System | Potential data exposure |
| 15 HR workstations | Endpoints | Lateral movement attempts |

### Investigation Findings

**Root Cause:** [Describe how attack was possible]

Example: Weak password policy allowed brute force attack. Employee used simple password "Admin123!" which was guessed after 47 attempts.

**Attack Vector:** [How attacker gained initial access]

Example: External attacker accessed OWA (Outlook Web Access) with brute-forced credentials.

**Lateral Movement:** [How attacker moved within network]

Example: Attacker used stolen credentials to access file server, then enumerated other systems via SMB.

**Objective:** [What was attacker trying to accomplish]

Example: Data exfiltration of employee personal information (SSN, salary, hire dates).

### Evidence & Documentation

**SIEM Data:**
- Alert ID: [number]
- Query: [SPL or search query]
- Timeline: [date/time range]
- Key fields: [affected IPs, users, systems]

**Network Data:**
- PCAP file: [filename]
- Packets analyzed: [count]
- Key flows: [src→dest:port]
- Suspicious patterns: [description]

**Endpoint Data:**
- Log files: [path/names]
- Event IDs: [Windows/Linux event codes]
- Artifacts: [registry, files, processes]

**Other Sources:**
- Threat intelligence matches: [known IOCs]
- Application logs: [if applicable]
- Database audit logs: [if applicable]

### Containment & Remediation

**Immediate Actions (0-1 hour):**
- [ ] Isolate affected systems from network
- [ ] Reset compromised user passwords
- [ ] Revoke any granted access/tokens
- [ ] Disable compromised accounts
- [ ] Block malicious IPs at firewall

**Short-term Actions (1-24 hours):**
- [ ] Deploy patches/updates on affected systems
- [ ] Scan systems for persistence mechanisms
- [ ] Review and remove unauthorized access
- [ ] Strengthen authentication (MFA, password policy)
- [ ] Update EDR/antivirus signatures

**Long-term Actions (1-30 days):**
- [ ] Conduct full forensic analysis
- [ ] Complete security awareness training
- [ ] Implement security hardening
- [ ] Update incident response procedures
- [ ] Conduct post-incident review

### Recommendations

**Technical Controls:**
1. Implement multi-factor authentication (MFA) for remote access
2. Deploy endpoint detection and response (EDR) on critical systems
3. Enable verbose logging on authentication events
4. Restrict PowerShell execution via application whitelisting
5. Implement network segmentation between departments

**Process Controls:**
1. Establish incident response team and escalation procedures
2. Create runbooks for common attack scenarios
3. Implement security awareness training (phishing, password hygiene)
4. Establish periodic security assessments and penetration testing
5. Create data classification and protection policies

**Policy Controls:**
1. Enforce strong password policy (12+ characters, complexity)
2. Implement account lockout policy (5 failures in 15 minutes)
3. Require MFA for all external access
4. Establish privileged access management (PAM) procedures
5. Create data handling and retention policies

### Lessons Learned

**What Went Well:**
- SIEM detection identified attack quickly
- Rapid escalation prevented data exfiltration
- Team communication was effective

**What Could Improve:**
- Password policy was too weak (should require complexity)
- MFA not implemented for OWA
- Monitoring of lateral movement could be more sensitive

**Preventive Measures for Future:**
1. Enforce MFA on all remote access immediately
2. Increase monitoring on authentication failures
3. Reduce privileged account usage
4. Implement EDR across all systems

---

## Response Playbooks

### Playbook 1: Brute Force Attack Response

**Detection Trigger:**
- SIEM Alert: > 10 failed login attempts from single source in 5 minutes
- Source: Windows Event Log Event ID 4625

**Immediate Response (< 15 min):**
1. Verify alert is not false positive (check source IP reputation)
2. Identify target user account
3. Check if any successful logins occurred after failures
4. If suspicious: Initiate containment

**Containment (15-60 min):**
1. Reset target account password
2. Block source IP at firewall
3. Force logout of any active sessions
4. Review recent access logs for unauthorized activity

**Investigation (1-4 hours):**
1. Examine all failed/successful logins from source IP
2. Check for lateral movement from compromised account
3. Review files accessed by account in timeframe
4. Check other systems for unauthorized access

**Recovery (4-24 hours):**
1. Implement MFA on affected account
2. Review password policy for all accounts
3. Audit privileged account usage
4. Consider credential reset for other high-value accounts

---

### Playbook 2: Malware Detection Response

**Detection Trigger:**
- Antivirus/EDR alert: Malware detected and quarantined
- Behavior: Suspicious process execution or network activity

**Immediate Response (< 15 min):**
1. Isolate affected endpoint from network
2. Document all user activity and running processes
3. Preserve volatile memory dump (if possible)
4. Prevent further execution/propagation

**Containment (15-60 min):**
1. Review file hash against threat intelligence
2. Identify all systems with same file hash
3. Perform full disk scan on affected systems
4. Monitor for C2 communication attempts

**Investigation (1-4 hours):**
1. Extract malware sample for deeper analysis
2. Determine attack vector (email, web, USB, etc.)
3. Identify initial access point and timeline
4. Check for lateral movement or privilege escalation

**Recovery (4-24 hours):**
1. Remove malware from all affected systems
2. Restore systems from clean backups if necessary
3. Verify clean status with endpoint scanning
4. Reimage systems if malware persistence suspected

---

### Playbook 3: Data Exfiltration Response

**Detection Trigger:**
- SIEM Alert: > 10 MB data transfer to external IP
- Network Analysis: Large outbound connection to unusual destination

**Immediate Response (< 15 min):**
1. Identify source and destination IPs and users
2. Block destination IP at firewall
3. Isolate source system from network
4. Preserve evidence before containment

**Containment (15-60 min):**
1. Terminate network connection
2. Identify all files accessed/modified in timeframe
3. Determine what data may have been exposed
4. Notify data protection/privacy team

**Investigation (1-4 hours):**
1. Reconstruct network flow (Wireshark analysis)
2. Examine source system for malware/unauthorized tools
3. Check user account for compromise
4. Determine if exfiltration was successful

**Recovery (4-24 hours):**
1. Reimage compromised system
2. Reset user credentials and MFA
3. Review other systems user had access to
4. Implement data loss prevention (DLP) tools
5. Assess regulatory/compliance impact

---

## Incident Metrics & Reporting

### Key Performance Indicators

| Metric | Target | Formula |
|---|---|---|
| MTTD (Mean Time to Detect) | < 1 hour | Sum of detection times / # incidents |
| MTTR (Mean Time to Respond) | < 4 hours | Sum of response times / # incidents |
| MTRC (Mean Time to Recover) | < 24 hours | Sum of recovery times / # incidents |
| Escalation Rate | 30-50% | High/Critical incidents / Total incidents |
| False Positive Rate | < 20% | False positives / Total alerts |
| Resolution Rate | > 95% | Resolved / Total incidents |

### Quarterly Incident Summary Report

```
Q1 2024 Incident Report
======================

Total Incidents: 47
- Critical: 2 (4%)
- High: 8 (17%)
- Medium: 18 (38%)
- Low: 19 (40%)

Incident Types:
- Unauthorized Access: 15 (32%)
- Malware: 8 (17%)
- Configuration: 12 (26%)
- Data Exposure: 5 (11%)
- Denial of Service: 3 (6%)
- Other: 4 (8%)

Performance Metrics:
- Avg MTTD: 42 minutes (Target: 60)
- Avg MTTR: 3.2 hours (Target: 4)
- Avg MTRC: 18 hours (Target: 24)
- Escalation Rate: 41% (Target: 30-50%)

Trends & Improvements:
- Detection time improved 15% vs Q4
- Focus on weak password policy helped reduce unauthorized access
- MFA implementation prevented 3 high-severity incidents
```

---

## Deliverables

✅ **3+ formal incident reports** using standard template  
✅ **Attack timeline reconstruction** with timestamps and evidence  
✅ **IOC extraction and documentation**  
✅ **3+ incident response playbooks**  
✅ **Root cause analysis (RCA)** for each incident  
✅ **Remediation and recommendations** for each incident  
✅ **Lessons learned documentation**  
✅ **Metrics tracking and reporting**

---

## Tools & Templates

| Resource | Purpose |
|---|---|
| Incident Report Template (markdown) | Standardize documentation |
| Playbook Template | Consistent response procedures |
| IOC Database | Central reference for indicators |
| Timeline Spreadsheet | Track events chronologically |
| Metrics Dashboard | Visualize incident trends |

---

## Challenges & Solutions

| Challenge | Solution |
|---|---|
| Incomplete logs/evidence | Implement comprehensive logging early |
| Unclear incident scope | Use metrics from SIEM/network to bound investigation |
| Stakeholder communication | Prepare summary reports in advance, use templates |
| Time pressure during response | Use playbooks to accelerate triage and containment |
| False positives in incidents | Validate alerts before declaring incident |

---

## Lessons Learned

1. **Documentation is critical:** Written records enable accountability and learning
2. **Speed matters:** Minutes count in early response, preparation saves time
3. **Evidence preservation:** Preserve logs/data immediately during investigation
4. **Communication is key:** Keep stakeholders informed, reduce rumors/panic
5. **Playbooks accelerate response:** Pre-written procedures enable faster decisions
6. **Root cause analysis prevents recurrence:** Fix underlying issues, not just symptoms
7. **Metrics drive improvements:** Track MTTD/MTTR/MTRC to measure progress

---

## Next Steps

- **Present findings to stakeholders** in formal briefing
- **Track remediation actions** through completion
- **Update incident response procedures** based on lessons learned
- **Conduct tabletop exercises** to practice procedures
- **Implement technical improvements** from recommendations

---

## Resources

- [NIST Incident Response Guide](https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-61r2.pdf)
- [Incident Response Best Practices](https://www.sans.org/reading-room/whitepapers/)
- [IOC Sharing & Threat Intelligence](https://attack.mitre.org/)
- [Playbook Templates & Examples](https://www.first.org/)
- [MITRE ATT&CK for RCA](https://attack.mitre.org/)

---

**Evidence Location:** See `/evidence` and `/playbooks` folders for templates and examples
