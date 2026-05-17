# Lab 5: Python SOC Tool - 04 Threat Intelligence

## Overview

The Threat Intelligence Module (`threat_intel.py`) enriches extracted IOCs by querying public threat intelligence services. This allows SOC analysts to determine the reputation, history, and risk level of suspicious indicators in real time.

---

## Supported Threat Intel Services

| Service | API | Free Tier | Use Case |
|---------|-----|-----------|----------|
| AbuseIPDB | REST API | Yes (1000 req/day) | IP reputation scoring |
| VirusTotal | REST API v3 | Yes (4 req/min) | File hash, URL, domain lookups |
| AlienVault OTX | REST API | Yes | Open threat intelligence pulses |

---

## Implementation Approach

### 1. AbuseIPDB Integration

- Endpoint: `https://api.abuseipdb.com/api/v2/check`
- Input: IPv4 address
- Output: Abuse score (0-100), category, reports count

```python
import requests

def check_abuseipdb(ip: str, api_key: str) -> dict:
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    response = requests.get(url, headers=headers, params=params)
    return response.json()
```

### 2. VirusTotal Integration

- Endpoints: `/files/{hash}`, `/urls`, `/domains/{domain}`
- Input: MD5/SHA256 hash, URL, or domain
- Output: Detection ratio, community score, last analysis date

### 3. AlienVault OTX Integration

- Endpoint: `https://otx.alienvault.com/api/v1/indicators/`{`type`}/{indicator}
- Input: Any IOC type (IP, domain, URL, hash)
- Output: Pulse references, threat types, confidence levels

---

## Rate Limiting and Caching

- Implement request throttling per API limits
- Cache results locally (SQLite or JSON) to avoid redundant API calls
- Add exponential backoff on rate-limit responses (HTTP 429)

---

## Output Format (Aggregated Threat Intel)

```json
{
  "ioc": "192.168.1.100",
  "type": "ipv4",
  "sources": {
    "abuseipdb": {
      "score": 75,
      "reports": 12,
      "categories": ["Brute-force", "SSH"]
    },
    "virustotal": {
      "detections": 8,
      "total_engines": 65
    }
  },
  "risk_level": "HIGH"
}
```

---

## Related Modules

- [03-IOC-Extraction.md](./03-IOC-Extraction.md) — IOCs to enrich
- [05-Reporting.md](./05-Reporting.md) — Include threat intel in reports
