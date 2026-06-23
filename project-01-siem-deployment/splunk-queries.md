# Splunk Query Library

## Project 1: Core Queries with Sunburst Highlighting

### Query 1: Event Volume Baseline
```spl
index=botsv2
| stats count as total_events
| eval status="ready" 
| table total_events, status
```
**Purpose:** Validate data ingestion  
**Expected Result:** 69M+ events from BOTSv2 dataset

---

### Query 2: Top Source IPs (Sunburst Alert on High Count)
```spl
index=botsv2 sourcetype=stream:*
| stats count as connection_count by src_ip
| sort - connection_count
| head 10
| eval alert_level=if(connection_count > 50000, "🟠 HIGH", "Normal")
```
**Purpose:** Identify top talkers  
**Sunburst Alert Threshold:** > 50,000 connections

---

### Query 3: Authentication Timeline
```spl
index=botsv2 sourcetype=WinEventLog:Security EventCode=4624
| timechart count by user span=1h
| rename count as "Login_Count"
```
**Purpose:** Monitor user authentication patterns  
**Color Coding:** Use Sunburst (#ffa602) for authentication spikes

---

### Query 4: HTTP Methods Distribution
```spl
index=botsv2 sourcetype=stream:http
| stats count as method_count by http_method
| eval method_pct=round(method_count*100/sum(method_count),2)
| table http_method, method_count, method_pct
```
**Purpose:** Baseline HTTP activity  
**Dashboard Panel:** Use Mocha (#432c1c) background

---

### Query 5: Destination Port Analysis
```spl
index=botsv2 sourcetype=stream:tcp
| stats count as port_count by dest_port
| sort - port_count
| eval status=if(dest_port IN (80, 443, 22, 53, 445), "Standard", "🟠 REVIEW")
```
**Purpose:** Identify unusual port usage  
**Highlight Non-Standard:** Sunburst color

---

### Query 6: Failed Login Detection
```spl
index=botsv2 sourcetype=WinEventLog:Security EventCode=4625
| stats count as failed_attempts by user, src_ip
| where failed_attempts > 10
| eval severity=if(failed_attempts > 20, "🟠 CRITICAL", "🟡 HIGH")
```
**Purpose:** Brute force detection  
**Alert Level:** Critical (Sunburst) if > 20 failures

---

## Advanced Queries for Projects 2-4

### Threat Hunting: Suspicious PowerShell
```spl
index=botsv2 sourcetype=WinEventLog:Security CommandLine=*powershell*
| stats count as ps_executions by user, host, CommandLine
| where ps_executions > 1
| eval risk="🟠 INVESTIGATE"
```

### Network Exfiltration Detection
```spl
index=botsv2 sourcetype=stream:tcp dest_ip NOT IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, user
| where total_bytes > 10485760
| eval alert="🟠 DATA_EXFIL_SUSPECTED"
```

### DNS Anomaly Detection
```spl
index=botsv2 sourcetype=dns
| stats count as query_count by src_ip, query
| search query_count > 100
| eval anomaly_score=query_count/100
| eval status=if(anomaly_score > 5, "🟠 HIGH_RISK", "Monitor")
```

---

## Dashboard Color Application

**Use Sunburst (#ffa602) for:**
- Alert badges and critical indicators
- Important statistics and KPIs
- Call-to-action buttons
- Threshold violations

**Use Mocha (#432c1c) for:**
- Panel backgrounds
- Text and labels
- Dashboard frames
- Section headers

---

*All queries reference BOTSv2 dataset. Update index names and sourcetypes for production use.*
