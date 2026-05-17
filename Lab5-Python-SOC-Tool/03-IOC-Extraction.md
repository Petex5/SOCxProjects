# Lab 5: Python SOC Tool - 03 IOC Extraction

## Overview

The IOC Extraction Module (`ioc_extractor.py`) scans parsed log data and raw text for Indicators of Compromise (IOCs). These are pieces of data that suggest a system may be compromised, such as malicious IP addresses, domains, URLs, file hashes, and suspicious email addresses.

---

## IOC Types Extracted

| IOC Type | Description | Example |
|----------|-------------|--------|
| IPv4 Address | Network location identifier | `192.168.1.100` |
| IPv6 Address | Extended network identifier | `2001:0db8:85a3::8a2e` |
| Domain | Hostname or FQDN | `evil-domain.xyz` |
| URL | Full web address | `http://malware.site/payload.exe` |
| MD5 Hash | File fingerprint (32 chars) | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA256 Hash | File fingerprint (64 chars) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Email Address | Suspicious sender address | `attacker@phish.com` |

---

## Implementation Approach

### 1. Regex-Based Extraction

```python
import re

IOC_PATTERNS = {
    'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'domain': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
    'url': r'https?://[\w\-./?=&]+',
    'md5': r'\b[a-f0-9]{32}\b',
    'sha256': r'\b[a-f0-9]{64}\b',
    'email': r'\b[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}\b'
}

def extract_iocs(text: str) -> dict:
    """Extract all supported IOC types from text."""
    results = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            results[ioc_type] = list(set(matches))  # Deduplicate
    return results
```

### 2. Validation and Filtering
- IPv4 validation: filter out `0.0.0.0`, `127.0.0.1`, and private ranges
- Domain validation: check TLD legitimacy
- Hash validation: verify correct length and hex characters only

### 3. Post-Processing
- Deduplication across all extracted IOCs
- Categorisation by IOC type
- JSON serialisation for output

---

## Output Format

```json
{
  "ipv4": ["192.168.1.1", "10.0.0.5"],
  "domain": ["suspicious.site", "malware.net"],
  "url": ["http://evil.com/payload.exe"],
  "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
  "email": ["hacker@phish.com"]
}
```

---

## Related Modules

- [02-Parser-Module.md](./02-Parser-Module.md) — Source of parsed log data
- [04-Threat-Intel.md](./04-Threat-Intel.md) — Enrichment of extracted IOCs
