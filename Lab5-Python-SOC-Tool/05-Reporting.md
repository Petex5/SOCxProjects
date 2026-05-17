# Lab 5: Python SOC Tool - 05 Reporting

## Overview

The Reporting Module (`reporter.py`) generates structured investigation reports from the data collected by the parser, IOC extraction, and threat intelligence modules. Reports serve as the final output for SOC analysts to review findings and take action.

---

## Supported Report Formats

| Format | Use Case | Tools |
|--------|----------|-------|
| Markdown (`.md`) | Human-readable reports, documentation | Built-in string formatting |
| JSON (`.json`) | Machine-readable output, API integration | Python `json` module |
| HTML (`.html`) | Formatted browser-viewable reports | `jinja2` template engine |
| CSV (`.csv`) | Spreadsheet-compatible IOC lists | Python `csv` module |

---

## Report Sections

### 1. Executive Summary
- Investigation overview (source logs, time range)
- Total IOCs found by category
- Risk level assessment (LOW / MEDIUM / HIGH / CRITICAL)
- Key findings summary

### 2. IOC Inventory
- Table of all discovered IOCs
- Columns: IOC, Type, Risk Level, Source, Intel Summary

### 3. Threat Intelligence Findings
- AbuseIPDB scores and categories
- VirusTotal detection ratios
- AlienVault OTX pulse matches

### 4. Recommendations
- Suggested remediation actions
- Network segments requiring attention
- Block/allow decisions for firewall

### 5. Appendix
- Full raw data export
- API response logs
- Tool version and run metadata

---

## Code Structure

```python
def generate_markdown_report(data: dict, output_path: str):
    """Generate a Markdown investigation report."""
    with open(output_path, 'w') as f:
        f.write('# SOC Investigation Report\n\n')
        f.write(f'## Generated: {data["timestamp"]}\n\n')
        # ... sections

def generate_json_report(data: dict, output_path: str):
    """Generate a JSON report for machine processing."""
    import json
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
```

---

## Template Engine (Optional)

For HTML reports, `jinja2` provides flexible templating:

```python
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader('templates/'))
template = env.get_template('report.html')
html_output = template.render(report=data)
```

---

## Related Modules

- [01-Tool-Overview.md](./01-Tool-Overview.md) — Tool architecture overview
- [02-Parser-Module.md](./02-Parser-Module.md) — Parsed log data source
- [03-IOC-Extraction.md](./03-IOC-Extraction.md) — Extracted IOC data
- [04-Threat-Intel.md](./04-Threat-Intel.md) — Enriched threat intel data
