# 🔍 Project 3: Network Forensics & Packet Analysis

**Objective:** Analyze network traffic at the packet level to identify attack vectors, validate SIEM findings, and understand attacker methodologies.

---

## Overview

While SIEM data provides high-level event summaries, network traffic analysis reveals the granular details of attacks. Using Wireshark and PCAP files, we'll reconstruct attack flows, identify malicious communication patterns, and validate our detection queries from Project 2.

### Key Learning Areas
- PCAP file collection and handling
- Wireshark filter syntax and capabilities
- Protocol analysis and packet examination
- Attack flow reconstruction
- Correlation with SIEM data

---

## Lab Setup

| Component | Configuration |
|---|---|
| **Packet Analyzer** | Wireshark (latest) |
| **Data Source** | BOTSv2 PCAP files or network captures |
| **Protocols** | HTTP, HTTPS, DNS, TCP/IP, SMB |
| **Analysis Scope** | Full packet contents and flows |

---

## Network Analysis Methodology

### Phase 1: PCAP Collection
- Extract PCAP files from BOTSv2 dataset
- Verify file integrity and size
- Document capture timeframe and network scope
- Identify capture points (network segment, tool, method)

### Phase 2: Initial Reconnaissance
- Open PCAP in Wireshark
- Review Statistics > Protocol Hierarchy
- Identify data volume, packet count, duration
- Note unusual protocols or traffic patterns

### Phase 3: Traffic Filtering & Isolation
- Apply display filters to isolate suspicious activity
- Focus on specific IP pairs, ports, or protocols
- Create separate views for different attack stages
- Export filtered results for documentation

### Phase 4: Flow Reconstruction
- Follow TCP streams to reconstruct conversations
- Examine application-layer payloads
- Decode and analyze suspicious content
- Correlate with SIEM alerts

### Phase 5: Findings Documentation
- Screenshot key packet sequences
- Document IOCs (IPs, domains, file hashes)
- Describe attack flow timeline
- Provide remediation recommendations

---

## Wireshark Filter Library

### Protocol-Level Filters

```wireshark
# HTTP Traffic Only
http

# HTTPS/SSL Traffic
ssl or tls

# DNS Queries and Responses
dns

# SMB/CIFS (Windows File Sharing)
smb or smb2

# SSH Traffic
ssh

# FTP (File Transfer)
ftp

# Telnet (Unencrypted Remote Access)
telnet
```

### IP & Port Based Filters

```wireshark
# All traffic from/to specific IP
ip.addr == 192.168.1.100

# Traffic from specific source
ip.src == 192.168.1.100

# Traffic to specific destination
ip.dst == 192.168.1.100

# Specific port (source OR destination)
tcp.port == 443

# Traffic on specific port range
tcp.port >= 1024 AND tcp.port <= 65535

# Non-standard web ports (likely suspicious)
tcp.port != 80 AND tcp.port != 443 AND tcp.port != 8080
```

### Suspicious Activity Filters

```wireshark
# Retransmissions (network issues or scanning)
tcp.analysis.retransmission

# Out-of-order packets (indicating packet loss or attack)
tcp.analysis.out_of_order

# Duplicate ACKs (network distress)
tcp.analysis.duplicate_ack

# Reset flags (connection termination)
tcp.flags.reset == 1

# SYN Flood detection (multiple SYN without ACK)
tcp.flags.syn == 1 AND tcp.flags.ack == 0
```

### Exfiltration Detection Filters

```wireshark
# Large packets (data transfer)
frame.len > 1000

# Multiple connections to same destination
tcp.flags.syn == 1

# DNS requests to suspicious domains
dns and dns.qry.name contains "malicious-pattern"

# FTP traffic (file transfer)
ftp or ftp-data
```

---

## Common Attack Patterns in PCAP

### Attack Pattern 1: Reconnaissance / Port Scanning
**Signature:** Rapid SYN packets to multiple ports from single source

**Wireshark Filter:**
```wireshark
tcp.flags.syn == 1 AND tcp.flags.ack == 0
```

**Expected Findings:**
- SYN packets to many ports in rapid succession
- Few or no SYN-ACK responses
- Multiple destination ports from single source IP

**Evidence to Capture:**
- Protocol Statistics showing port distribution
- TCP Stream showing connection attempts
- Screenshots of port scan pattern

---

### Attack Pattern 2: Web Application Exploitation
**Signature:** HTTP requests with SQL injection, XSS, or path traversal payloads

**Wireshark Filter:**
```wireshark
http and (
  http.request.uri contains "union" or
  http.request.uri contains "select" or
  http.request.uri contains "../" or
  http.request.uri contains "%2e%2e"
)
```

**Expected Findings:**
- Unusual characters or encoding in HTTP requests
- Large parameter values
- Repeated similar requests with variations
- Error responses (500, 403) after requests

**Evidence to Capture:**
- Full HTTP request/response pairs
- Decoded payload content
- Timeline of exploitation attempts

---

### Attack Pattern 3: Data Exfiltration
**Signature:** Large data transfers to external IPs on non-standard ports

**Wireshark Filter:**
```wireshark
ip.dst != 10.0.0.0/8 AND
tcp.port > 1024 AND
tcp.port < 65535 AND
frame.len > 1000
```

**Expected Findings:**
- Large packets or multiple packets in rapid sequence
- Non-standard destination ports
- External IP addresses
- Potential obfuscation or compression

**Evidence to Capture:**
- Flow statistics (bytes sent/received)
- Timeline of transfer
- Payload content (if readable)
- Destination IP geolocation

---

### Attack Pattern 4: Lateral Movement (SMB/RDP)
**Signature:** Multiple failed/successful authentications on administrative ports

**Wireshark Filter:**
```wireshark
tcp.port == 135 or tcp.port == 139 or tcp.port == 445 or tcp.port == 3389
```

**Expected Findings:**
- Authentication traffic on SMB (445) or RDP (3389)
- Multiple connections from non-admin source
- Successful sessions after authentication attempts
- Internal network traffic (10.x.x.x)

**Evidence to Capture:**
- Source/destination IP pairs
- Timestamps and session duration
- Error/success indicators
- File access patterns (SMB)

---

## Sample PCAP Analysis: Attack Flow Reconstruction

### Scenario: Inbound Compromise with Data Exfiltration

**Step 1: Identify Entry Point**
```wireshark
# Find initial compromise traffic
tcp.flags.syn == 1 AND ip.dst == 192.168.1.50 AND tcp.dstport > 1024
```

**Step 2: Examine Exploitation**
```wireshark
# Look for HTTP exploitation on compromised system
http and ip.src == 192.168.1.50 AND http.request.method == "POST"
```

**Step 3: Identify Command Execution**
```wireshark
# DNS queries indicating C2 contact
dns and ip.src == 192.168.1.50
```

**Step 4: Detect Exfiltration**
```wireshark
# Outbound data transfer
ip.src == 192.168.1.50 AND ip.dst != 10.0.0.0/8 AND frame.len > 1000
```

---

## TCP Stream Analysis

### Following a Suspicious Connection

1. **Right-click on packet** → "Follow → TCP Stream"
2. **View reconstruction** of entire conversation
3. **Change data format:**
   - ASCII: Readable text communication
   - EBCDIC: Mainframe encoding
   - Hex Dump: Raw bytes
   - Raw: Full packet data
   - C Arrays: For documentation

### Example: Extracting Malicious File

From a TCP stream showing file transfer:
1. Follow the TCP stream
2. Change view to "Raw"
3. Copy hex data to file
4. Use `xxd` or `hexdump` to validate
5. Extract file and analyze with VirusTotal

---

## Correlation with SIEM Data

### Matching Wireshark Findings to SIEM Alerts

| SIEM Alert | Network Evidence | PCAP Filter |
|---|---|---|
| "Brute Force" | Failed auth attempts | `tcp.dstport == 22` or `tcp.dstport == 3389` |
| "Suspicious Port" | Connection to non-standard port | `tcp.dstport > 10000 AND tcp.dstport < 20000` |
| "DNS Anomaly" | Unusual domain queries | `dns AND dns.qry.name` |
| "Data Exfil" | Large outbound transfer | `ip.dst != 10.0.0.0/8 AND frame.len > 1000` |
| "Lateral Movement" | Internal SMB traffic | `tcp.dstport == 445` |

### Validation Process

1. Extract IOCs from SIEM alert (IP, port, domain, user)
2. Build Wireshark filter to isolate related traffic
3. Review packet sequence and content
4. Confirm attack pattern matches expected behavior
5. Document findings with screenshots

---

## Tools & Techniques

| Task | Tool/Method |
|---|---|
| PCAP capture | Wireshark, tcpdump, network tap |
| Display filtering | Wireshark built-in filters |
| Flow analysis | Follow TCP Stream, statistics |
| Packet examination | Packet Details panel, hex viewer |
| File extraction | Wireshark export, custom scripts |
| Timeline reconstruction | Packet timestamps, time-ordered sorting |

---

## Deliverables

✅ **PCAP files analyzed and documented**  
✅ **Wireshark filter library with descriptions**  
✅ **3+ attack patterns identified and reconstructed**  
✅ **TCP stream analysis with findings**  
✅ **Screenshots of suspicious traffic**  
✅ **Correlation matrix: SIEM alerts ↔ Network evidence**  
✅ **IOC extraction and documentation**

---

## Key Findings Expected from BOTSv2

Typical network forensics discoveries:
- **Scanning activity** from external IPs on multiple ports
- **HTTP exploitation** attempts targeting web applications
- **DNS queries** to suspicious domains or unusual patterns
- **C2 communication** on non-standard ports
- **Large file transfers** to external systems
- **Lateral movement** within internal network

---

## Challenges & Solutions

| Challenge | Solution |
|---|---|
| PCAP files are very large | Filter to relevant time periods, split into segments |
| Encrypted traffic (HTTPS/TLS) can't be read | Examine metadata, IP flows, timing, certificate info |
| Too much noise in unfiltered data | Start with broad protocol filters, then narrow down |
| Difficult to correlate with SIEM | Use timestamps and IP addresses as join keys |
| Malicious payloads may be encoded | Use hex viewer, strings, or extraction tools |

---

## Lessons Learned

1. **Packet-level analysis is forensically rigorous:** Every bit of evidence is preserved
2. **SIEM and network analysis complement each other:** One finds events, one shows details
3. **Timestamps are critical:** Essential for correlating across tools
4. **Baseline traffic patterns matter:** Know what's normal before hunting
5. **Encrypted traffic still has metadata:** IP, port, timing, and flow patterns tell story
6. **TCP streams reveal context:** Application-level activity not visible in summarized logs

---

## Next Steps

- **Project 4:** Document these findings in formal incident reports
- **Create incident response procedures** based on attack patterns discovered
- **Build detection rules** for these attacks in SIEM

---

## Resources

- [Wireshark User Guide](https://www.wireshark.org/docs/)
- [Wireshark Display Filters Reference](https://www.wireshark.org/docs/dfref/)
- [Packet Analysis with Wireshark](https://www.packetanalysis.org/)
- [NetworkMiner (Alternative Tool)](https://www.netresec.com/?page=NetworkMiner)
- [PCAP Analysis Best Practices](https://resources.infosecinstitute.com/topics/packet-analysis/)

---

**Evidence Location:** See `/evidence` folder for PCAP files and analysis screenshots
