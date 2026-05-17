# Lab 5: Python SOC Tool - 01 Tool Overview

## Introduction

This document provides an overview of the Python-based Security Operations Center (SOC) tool developed in this lab. The tool is designed to automate common SOC analyst tasks including log parsing, indicator of compromise (IOC) extraction, threat intelligence lookup, and report generation.

---

## Purpose

- Automate repetitive SOC analyst workflows
- Provide a modular, extensible CLI tool for security investigations
- Demonstrate Python proficiency in a cybersecurity context

---

## Architecture

```
soc_tool/
├── main.py             # Entry point / CLI
├── parser.py           # Log parsing module
├── ioc_extractor.py    # IOC extraction module
├── threat_intel.py     # Threat intelligence lookups
├── reporter.py         # Report generation module
└── utils.py            # Shared utilities
```

---

## Features

| Feature | Description |
|---------|-------------|
| Log Parsing | Parse and analyse common log formats (Syslog, Apache, Firewall) |
| IOC Extraction | Extract IPs, URLs, domains, hashes from text |  |
| Threat Intel | Query AbuseIPDB and VirusTotal APIs |
| Reporting | Generate structured investigation reports |

---

## Requirements

- Python 3.8+
- requests
- argparse
- json
- logging

---

## Potential API Integrations

- **AbuseIPDB** — IP reputation scoring
- **VirusTotal** — File and URL hash lookups
- **AlienVault OTX** — Open threat intelligence feed

---

## Next Steps

Refer to the following module documentation:

1. [02-Parser-Module.md](./02-Parser-Module.md) — Log parsing implementation
2. [03-IOC-Extraction.md](./03-IOC-Extraction.md) — IOC extraction logic
3. [04-Threat-Intel.md](./04-Threat-Intel.md) — Threat intelligence integration
4. [05-Reporting.md](./05-Reporting.md) — Report generation
