# Lab 5: Python SOC Tool - 02 Parser Module

## Overview

The Parser Module (`parser.py`) is responsible for reading and parsing various log file formats commonly encountered in SOC operations. It provides a unified interface for extracting structured data from unstructured or semi-structured log entries.

---

## Supported Log Formats

| Format | Example |
|--------|---------|
| Syslog | `<13>Jan 15 10:30:00 host sshd[1234]: Failed password for root` |
| Apache Access Log | `192.168.1.100 - - [15/Jan/2026:10:30:00 +0000] "GET /admin HTTP/1.1" 404` |
| Firewall (IPTables) | `Jan 15 10:30:00 firewall kernel: IN=eth0 OUT= SRC=10.0.0.1 DST=192.168.1.1` |
| Windows Event Log | `EventID 4625 - An account failed to log on` |

---

## Implementation Approach

### 1. Syslog Parser
- Regex-based pattern matching
- Extracts: timestamp, hostname, service, PID, message

### 2. Apache Access Log Parser
- Regex or Apache combined log format parser
- Extracts: IP, timestamp, HTTP method, URL, status code, user-agent

### 3. Firewall Log Parser
- Extracts: source IP, destination IP, port, action (ALLOW/DENY)

### 4. Windows Event Log Parser (Optional)
- PyEVT or XML-based parsing
- Extracts: EventID, source, level, message

---

## Code Structure

```python
def parse_log_line(line: str, log_type: str) -> dict:
    """Parse a single log line based on log type."""
    if log_type == 'syslog':
        return parse_syslog(line)
    elif log_type == 'apache':
        return parse_apache(line)
    # ... etc

def parse_log_file(filepath: str, log_type: str) -> list:
    """Parse an entire log file and return list of parsed records."""
    records = []
    with open(filepath, 'r') as f:
        for line in f:
            parsed = parse_log_line(line.strip(), log_type)
            if parsed:
                records.append(parsed)
    return records
```

---

## Error Handling

- Graceful handling of malformed log lines
- Logging of parse failures for later review
- Support for encoding issues (UTF-8, Latin-1)

---

## Related Modules

- [03-IOC-Extraction.md](./03-IOC-Extraction.md) — IOC extraction from parsed data
- [05-Reporting.md](./05-Reporting.md) — Reporting on parsed results
