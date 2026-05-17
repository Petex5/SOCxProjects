# Lab 5: Python SOC Tool Development

## Overview

This lab focuses on building a practical Python-based SOC analyst tool. You will develop a command-line Python application that automates common SOC tasks such as log parsing, IP reputation checking, indicator of compromise (IOC) extraction, and alert generation. This lab builds your Python scripting proficiency in a security operations context.

## Objectives

- Build a functional Python SOC tool from scratch
- Parse and analyse log files programmatically
- Integrate with public threat intelligence APIs (e.g., VirusTotal, AbuseIPDB)
- Extract and catalogue Indicators of Compromise (IOCs)
- Implement error handling and logging in security tools
- Create a modular, reusable codebase following best practices

## Tasks

1. **Set Up Development Environment**
   - Install Python 3.x and required libraries (requests, argparse, json, logging)
   - Set up a virtual environment for the project
   - Create the project directory structure

2. **Build Log Parser Module**
   - Write a function to parse common log formats (syslog, Windows Event Log, Apache access log)
   - Extract relevant fields: timestamp, source IP, destination IP, event type, status code
   - Output parsed data to a structured format (JSON or CSV)

3. **Build IP Reputation Checker**
   - Integrate with the AbuseIPDB API to check IP addresses against abuse reports
   - Implement rate limiting and error handling for API calls
   - Cache results to avoid redundant API requests

4. **Build IOC Extractor**
   - Parse log files for indicators: IP addresses, domain names, file hashes (MD5, SHA256), URLs
   - Use regular expressions to identify and extract IOCs
   - Output IOCs to a structured report file

5. **Build Alert Generator**
   - Define alert thresholds (e.g., more than 5 failed login attempts from same IP)
   - Generate alert notifications in a structured format
   - Include severity levels (Low, Medium, High, Critical)

6. **Integrate and Test**
   - Combine all modules into a single CLI application using argparse
   - Test with sample log data
   - Add a help command (--help) to document usage
   - Write a README with installation and usage instructions

## Deliverables

- Complete Python SOC tool with all modules functional
- Sample log files for testing
- requirements.txt listing all dependencies
- README documentation with usage examples
- Code comments explaining key functions

## Skills

- Python programming (functions, modules, error handling, file I/O)
- Regular expressions for pattern matching
- REST API integration
- JSON and CSV data handling
- Command-line interface design
- Security log analysis
- Virtual environments and dependency management

## Tools

- Python 3.x
- pip (Python package manager)
- VS Code or PyCharm
- Git for version control
- AbuseIPDB API (free tier)
- VirusTotal API (free tier)
- Sample log files (Apache, syslog, Windows Event Log)

## Resources

- Python Documentation: https://docs.python.org/3/
- AbuseIPDB API: https://docs.abuseipdb.com/
- VirusTotal API: https://developers.virustotal.com/reference
- Real Python - Python API Tutorial: https://realpython.com/python-api/
- Python argparse Module: https://docs.python.org/3/library/argparse.html
- Regex101 - Test Regular Expressions: https://regex101.com/

---

## How to Use soc-analyzer.py

The tool provides five main commands: `parse`, `extract`, `intel`, `alert`, and `report`.

### Quick Start

```
python soc-analyzer.py --help
```

This displays the help menu with all available commands and options.

### Command 1: Parse Logs

Parses a log file and displays statistics.

**Syntax:**
```bash
python soc-analyzer.py parse -f <logfile> [--format <type>] [--search <keyword>]
```

**Examples:**

1. Parse an Apache access log:
```bash
python soc-analyzer.py parse -f access.log --format apache
```

2. Parse a syslog file:
```bash
python soc-analyzer.py parse -f /var/log/syslog --format syslog
```

3. Search for a specific term in parsed logs:
```bash
python soc-analyzer.py parse -f auth.log --search "Failed password"
```

### Command 2: Extract IOCs

Extracts Indicators of Compromise from a file.

**Syntax:**
```bash
python soc-analyzer.py extract -f <file> [--type <iotype>] [-o <output.json>]
```

**Examples:**

1. Extract all IOCs from a log file:
```bash
python soc-analyzer.py extract -f firewall.log
```

2. Extract only IP addresses:
```bash
python soc-analyzer.py extract -f auth.log --type ipv4
```

3. Extract IOCs and save to a JSON file:
```bash
python soc-analyzer.py extract -f malware.log -o extracted_iocs.json
```

### Command 3: Check Threat Intelligence

Checks IP addresses against threat intelligence databases.

**Syntax:**
```bash
python soc-analyzer.py intel --ip <ip> | -f <ipfile> [-o <output.json>]
```

**Examples:**

1. Check a single suspicious IP:
```bash
python soc-analyzer.py intel --ip 192.168.100.50
```

2. Check multiple IPs from a file:
```bash
python soc-analyzer.py intel -f suspicious_ips.txt
```

3. Save threat intelligence report to JSON:
```bash
python soc-analyzer.py intel -f iocs.txt -o threat_intel_report.json
```

### Command 4: Generate Alert

Generates a structured security alert.

**Syntax:**
```bash
python soc-analyzer.py alert -t <type> -s <severity> [--src <ip>] [--dst <ip>] [-d <description>]
```

**Examples:**

1. Generate a high-severity brute force alert:
```bash
python soc-analyzer.py alert -t "Brute Force Attack" -s high --src 10.0.0.15 -d "Multiple failed SSH attempts detected"
```

2. Generate a critical ransomware alert:
```bash
python soc-analyzer.py alert -t "Ransomware Indicator" -s critical -d "Encrypted file extensions detected"
```

3. Generate a medium alert with destination:
```bash
python soc-analyzer.py alert -t "Data Exfiltration" -s medium --src 192.168.1.50 --dst 203.0.113.10 -d "Large outbound data transfer"
```

### Command 5: Generate Full Report

Runs all modules and compiles a comprehensive analysis report.

**Syntax:**
```bash
python soc-analyzer.py report -f <logfile> -o <report.json> [-v]
```

**Examples:**

1. Generate a full report from a firewall log:
```bash
python soc-analyzer.py report -f firewall.log -o report.json
```

2. Generate a report with verbose console output:
```bash
python soc-analyzer.py report -f auth.log -o auth_analysis.json -v
```

3. Generate a report from multiple log sources (run separately then compare):
```bash
python soc-analyzer.py report -f apache.log -o apache_report.json
python soc-analyzer.py report -f syslog.log -o syslog_report.json
```

---

## Step-by-Step Workflow: Real-World SOC Investigation

Below is a complete workflow demonstrating how a SOC analyst would use the tool during an incident.

### Scenario: Investigating Suspicious Activity on a Web Server

**Step 1 - Parse the Access Log**

Start by parsing the Apache access log to understand activity patterns:

```bash
python soc-analyzer.py parse -f access.log --format apache
```

Look for unusual patterns such as:
- Multiple requests from the same IP
- Requests to sensitive paths (e.g., `/admin`, `/wp-admin`)
- Non-standard user agents

**Step 2 - Extract IOCs**

Extract all indicators from the access log:

```bash
python soc-analyzer.py extract -f access.log -o access_iocs.json
```

Review the JSON output for:
- Suspicious IP addresses
- Malicious URLs or domains
- File hashes if any

**Step 3 - Check Threat Intelligence**

Create a text file with suspicious IPs found in Step 2, then check each one:

```bash
python soc-analyzer.py intel -f suspicious_ips.txt -o threat_check.json
```

Interpret results:
- Abuse score > 50: high confidence suspicious
- Abuse score 10-50: investigate further
- Abuse score 0-10: likely benign

**Step 4 - Generate Alerts**

For each confirmed threat, generate an alert:

```bash
python soc-analyzer.py alert -t "Web Attack" -s high --src 203.0.113.45 -d "SQL injection attempts from known malicious IP"
python soc-analyzer.py alert -t "Brute Force" -s medium --src 198.51.100.22 -d "Multiple failed login attempts detected"
```

**Step 5 - Generate Final Report**

Compile everything into a final report:

```bash
python soc-analyzer.py report -f access.log -o investigation_report.json -v
```

This produces a JSON report combining all module results, ready for:
- Sharing with the incident response team
- Storing in the ticketing system
- Archiving for future reference

---

## Quick Reference Table

| Command | Short Flag | Description |
|---------|-----------|-------------|
| `python soc-analyzer.py parse` | `-f, --file` | Parse and analyze a log file |
| `python soc-analyzer.py extract` | `-f, -o` | Extract IOCs and save to JSON |
| `python soc-analyzer.py intel` | `--ip, -f, -o` | Check IP reputation |
| `python soc-analyzer.py alert` | `-t, -s, --src` | Generate a security alert |
| `python soc-analyzer.py report` | `-f, -o, -v` | Generate full analysis report |
| `python soc-analyzer.py --help` | | Show all available options |

---

## Tips for Best Results

1. **Always use verbose mode (`-v`)** when generating reports during active investigations to see real-time output.
2. **Run `extract` before `intel`** to get a list of IOCs, then check those IOCs against threat intelligence.
3. **Save outputs to JSON** (`-o`) for easy sharing and integration with other SOC tools.
4. **Use `--search` with `parse`** to quickly filter large log files for specific events.
5. ** Keep a threat intel IP list** updated regularly for quick bulk checking during incidents.
