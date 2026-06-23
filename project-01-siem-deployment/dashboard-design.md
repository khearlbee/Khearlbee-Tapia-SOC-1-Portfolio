# Project 1: Dashboard Design & Layout

## Dashboard Overview: SOC Operations Center

**Dashboard Name:** Security Operations Monitoring Hub  
**Color Scheme:** Sunburst (#ffa602) + Mocha (#432c1c)  
**Purpose:** Real-time visibility into security events and threats

---

## Panel Specifications

### Panel 1: Total Events Ingested (Single Value)
- **Background Color:** Mocha (#432c1c)
- **Text Color:** White (#ffffff)
- **Value Color:** Sunburst (#ffa602)
- **SPL Query:** `index=botsv2 | stats count`
- **Display:** Large font, prominent placement
- **Use:** Verify ongoing data collection

---

### Panel 2: Event Volume Over Time (Timechart)
- **Background Color:** Mocha (#432c1c)
- **Line Color:** Sunburst (#ffa602)
- **X-Axis:** Time (hourly)
- **Y-Axis:** Event count
- **SPL Query:** `index=botsv2 | timechart count span=1h`
- **Use:** Identify traffic anomalies and spikes

---

### Panel 3: Top 10 Source IPs (Bar Chart)
- **Background Color:** Mocha (#432c1c)
- **Bar Color:** Sunburst (#ffa602)
- **SPL Query:** `index=botsv2 sourcetype=stream:* | stats count by src_ip | sort -count | head 10`
- **Use:** Identify most active systems
- **Alert:** Highlight bars > 50k events

---

### Panel 4: HTTP Method Distribution (Pie Chart)
- **Background Color:** Mocha (#432c1c)
- **Slice Colors:** Sunburst (#ffa602) primary, lighter shades for variants
- **SPL Query:** `index=botsv2 sourcetype=stream:http | stats count by http_method`
- **Use:** Baseline normal HTTP activity

---

### Panel 5: Active Users (Table)
- **Background Color:** Mocha (#432c1c)
- **Header Color:** Sunburst (#ffa602)
- **Text Color:** White (#ffffff)
- **SPL Query:** `index=botsv2 sourcetype=WinEventLog:Security EventCode=4624 | stats count as logins by user | sort -logins`
- **Use:** Monitor authentication patterns

---

### Panel 6: Top Destination Ports (Bar Chart)
- **Background Color:** Mocha (#432c1c)
- **Standard Ports (80,443,22,53,445):** Light gray
- **Non-Standard Ports:** Sunburst (#ffa602) with highlight
- **SPL Query:** `index=botsv2 sourcetype=stream:tcp | stats count by dest_port | sort -count | head 15`
- **Use:** Detect suspicious port usage

---

### Panel 7: Authentication Failures (Timechart)
- **Background Color:** Mocha (#432c1c)
- **Failure Line Color:** Sunburst (#ffa602)
- **Threshold Line:** Red dashed at 10 failures/hour
- **SPL Query:** `index=botsv2 sourcetype=WinEventLog:Security EventCode=4625 | timechart count by user span=1h | stats avg(*) as avg_failures`
- **Use:** Early detection of brute force attacks

---

### Panel 8: Data Transfer Volume (Bar Chart)
- **Background Color:** Mocha (#432c1c)
- **Normal Traffic:** Light color
- **Large Transfers (>1GB):** Sunburst (#ffa602) with alert
- **SPL Query:** `index=botsv2 sourcetype=stream:tcp | stats sum(bytes_out) as outbound_bytes by src_ip, dest_ip | sort -outbound_bytes`
- **Use:** Detect data exfiltration

---

## Dashboard Layout Template

```
┌─────────────────────────────────────────────────────────────┐
│ 🟠 SECURITY OPERATIONS MONITORING HUB                        │
│ Last Updated: [Timestamp] | Color: #ffa602/#432c1c          │
└─────────────────────────────────────────────────────────────┘

┌─────────────────┬─────────────────┬─────────────────┐
│ Total Events    │ Event Volume    │ Active Users    │
│ [69M]           │ [Timechart]     │ [Count: 150]    │
│ Status: 🟠 OK   │ Trend: ↑ 15%    │ Peak: 10-11am   │
└─────────────────┴─────────────────┴─────────────────┘

┌────────────────────────────────────────────────────┐
│ Top Source IPs (External Threats)                  │
│ [Bar Chart - Sunburst Colored]                     │
│ 45.77.65.211: 9,500 events 🟠 MONITOR             │
│ 198.51.100.45: 8,200 events                       │
│ 192.0.2.100: 7,100 events                         │
└────────────────────────────────────────────────────┘

┌──────────────────┬──────────────────┐
│ HTTP Methods     │ Destination Ports │
│ [Pie Chart]      │ [Bar Chart]       │
│ GET: 85%         │ 443: 45%          │
│ POST: 12%        │ 80: 35%           │
│ Other: 3%        │ Unusual: 5% 🟠   │
└──────────────────┴──────────────────┘

┌────────────────────────────────────────────────────┐
│ Failed Authentication Attempts (Brute Force Monitor)│
│ [Timechart - Sunburst Alert Line]                  │
│ Threshold: 10/hour | Current: 7/hour | Status: ✓  │
└────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────┐
│ Data Transfer Volume Analysis                      │
│ [Bar Chart - Largest Transfers Highlighted]        │
│ Top Transfer: 450MB to 198.51.100.45 🟠 REVIEW   │
└────────────────────────────────────────────────────┘
```

---

## Color Application Guide

### Alert States (Sunburst #ffa602 Usage)
- **🟠 Critical Alert:** Sunburst background with white text
- **🟠 High Risk:** Sunburst text on Mocha background
- **🟡 Medium Alert:** Orange-tinted panel border
- **✓ Normal:** Green checkmark or gray text

### Dashboard Interaction
- **Drill-Down:** Click panel to Sunburst-highlighted details
- **Time Range Picker:** Sunburst button for apply
- **Filter Tags:** Mocha background with Sunburst text
- **Refresh Rate:** Live updates with Sunburst pulse indicator

---

## Performance Notes

- **Refresh Interval:** 5 minutes (can be adjusted for real-time)
- **Search Acceleration:** Use data models for timecharts
- **Cache:** Enable for non-critical panels
- **Row Spacing:** 20px for readability with Mocha background

---

## Presentation Tips

1. **Start with Total Events** to show scale of data
2. **Use timechart** to explain normal vs. anomalous patterns
3. **Highlight in Sunburst** any suspicious indicators
4. **Use Mocha background** for professional appearance
5. **Pause on key findings** for audience discussion

---

*Dashboard should be updated every 5 minutes with latest data. Print to PDF with Sunburst/Mocha colors preserved for stakeholder reports.*
