#!/usr/bin/env python3
"""
PhishingInvestigator - Automated Phishing Email Investigation Tool
=================================================================

A comprehensive Python tool for automating phishing email investigations.
Supports .eml and .msg file formats, performs email header analysis,
extracts indicators of compromise (IOCs), conducts threat intelligence
lookups, and generates structured investigation reports.

Author: SOCxProjects
Version: 1.0.0
License: MIT
"""

import argparse
import email
import re
import hashlib
import json
import os
import sys
import socket
import whois
import ipaddress
from datetime import datetime
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, unquote

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False
    print("[!] Warning: 'olefile' not installed. .msg file support disabled.")
    print("    Install with: pip install olefile")

try:
    import tldextract
    TLD_AVAILABLE = True
except ImportError:
    TLD_AVAILABLE = False
    print("[!] Warning: 'tldextract' not installed. Full domain analysis disabled.")
    print("    Install with: pip install tldextract")


# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

VERSION = "1.0.0"
AUTHOR = "SOCxProjects"
REPORT_DIR = "phishing_reports"

# Regex patterns for IOC extraction
REGEX_EMAIL = r'[\w\.\-\+]+@[\w\.\-]+\.\w+'
REGEX_IP = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
REGEX_DOMAIN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
REGEX_URL = r'https?://[\w\-\./\?=%&#:;@+]+\w'
REGEX_MD5 = r'\b[a-fA-F0-9]{32}\b'
REGEX_SHA1 = r'\b[a-fA-F0-9]{40}\b'
REGEX_SHA256 = r'\b[a-fA-F0-9]{64}\b'

# Known malicious TLDs (high-risk)
SUSPICIOUS_TLDS = {
    '.top', '.xyz', '.site', '.gq', '.ml', '.cf', '.tk', '.cc', '.pw',
    '.work', '.click', '.link', '.download', '.racing', '.win', '.bid',
    '.loan', '.stream', '.trade', '.date', '.ovh', '.club', '.live'
}

# Header fields for authentication checks
AUTH_HEADERS = {
    'spf': ['Received-SPF', 'Authentication-Results'],
    'dkim': ['DKIM-Signature', 'Authentication-Results'],
    'dmarc': ['Authentication-Results', 'DMARC-Filter']
}

# ============================================================================
# CLASS: EmailParser
# ============================================================================

class EmailParser:
    """Parses .eml and .msg email files and extracts header information."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_extension = os.path.splitext(file_path)[1].lower()
        self.headers: Dict[str, str] = {}
        self.subject: str = ""
        self.sender: str = ""
        self.recipients: List[str] = []
        self.body_text: str = ""
        self.body_html: str = ""
        self.attachments: List[Dict[str, Any]] = []
        self.raw_content: bytes = b""

    def parse(self) -> bool:
        """Main parse method - routes to appropriate handler based on file type."""
        try:
            with open(self.file_path, 'rb') as f:
                self.raw_content = f.read()

            if self.file_extension == '.eml':
                return self._parse_eml()
            elif self.file_extension == '.msg' and OLEFILE_AVAILABLE:
                return self._parse_msg()
            else:
                print(f"[!] Error: Unsupported file type: {self.file_extension}")
                return False
        except FileNotFoundError:
            print(f"[!] Error: File not found: {self.file_path}")
            return False
        except Exception as e:
            print(f"[!] Error parsing file: {str(e)}")
            return False

    def _parse_eml(self) -> bool:
        """Parse a standard .eml email file."""
        try:
            msg = email.message_from_bytes(self.raw_content)
            self.headers = dict(msg.items())
            self.subject = self._decode_header(msg.get('Subject', ''))
            self.sender = self._decode_header(msg.get('From', ''))

            # Parse recipients
            to_header = msg.get('To', '')
            cc_header = msg.get('Cc', '')
            if to_header:
                self.recipients.extend(self._parse_recipients(to_header))
            if cc_header:
                self.recipients.extend(self._parse_recipients(cc_header))

            # Extract body and attachments
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition', ''))

                    if 'attachment' in content_disposition or content_type == 'application/octet-stream':
                        self._extract_attachment(part)
                    elif content_type == 'text/plain':
                        payload = part.get_payload(decode=True)
                        if payload:
                            self.body_text = self._decode_payload(payload)
                    elif content_type == 'text/html':
                        payload = part.get_payload(decode=True)
                        if payload:
                            self.body_html = self._decode_payload(payload)
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    self.body_text = self._decode_payload(payload)

            print(f"[+] Successfully parsed .eml file: {self.file_path}")
            return True
        except Exception as e:
            print(f"[!] Error parsing .eml: {str(e)}")
            return False

    def _parse_msg(self) -> bool:
        """Parse a .msg file using olefile."""
        if not OLEFILE_AVAILABLE:
            print("[!] Error: olefile not available for .msg parsing")
            return False
        try:
            ole = olefile.OleFileIO(self.file_path)

            # Extract the email properties
            props = ole ole.get_properties(
                '\x05SummaryInformation'
            )

            # Get body text
            body_stream = ole.openstream(
                '__substg1.0_1000001F'
            )
            self.body_text = body_stream.read().decode('utf-16-le', errors='ignore')

            # Get subject
            subject_stream = ole.openstream(
                '__substg1.0_0037001F'
            )
            self.subject = subject_stream.read().decode('utf-16-le', errors='ignore')

            # Get sender
            try:
                sender_stream = ole.openstream(
                    '__substg1.0_0C1F001F'
                )
                self.sender = sender_stream.read().decode('utf-16-le', errors='ignore')
            except:
                self.sender = "Unknown"

            # Extract attachments
            for entry in ole.listdir():
                if len(entry) == 2 and entry[0].startswith('__attach'):
                    try:
                        name_stream = ole.openstream(
                            f"__attach_version1.0_#{entry[-1]}__substg1.0_3707001F"
                        )
                        filename = name_stream.read().decode('utf-16-le', errors='ignore')
                        self.attachments.append({'filename': filename})
                    except:
                        pass

            ole.close()
            print(f"[+] Successfully parsed .msg file: {self.file_path}")
            return True
        except Exception as e:
            print(f"[!] Error parsing .msg: {str(e)}")
            return False

    def _decode_header(self, header_value: str) -> str:
        """Decode MIME-encoded email headers."""
        if not header_value:
            return ""
        try:
            decoded = email.header.decode_header(header_value)
            result = []
            for part, encoding in decoded:
                if isinstance(part, bytes):
                    result.append(part.decode(encoding or 'utf-8', errors='replace'))
                else:
                    result.append(part)
            return ''.join(result)
        except Exception:
            return str(header_value)

    def _decode_payload(self, payload: bytes) -> str:
        """Decode email body payload."""
        try:
            return payload.decode('utf-8', errors='replace')
        except Exception:
            try:
                return payload.decode('latin-1', errors='replace')
            except Exception:
                return payload.decode('ascii', errors='replace')

    def _parse_recipients(self, recipients_str: str) -> List[str]:
        """Parse recipients string into list of email addresses."""
        emails = re.findall(REGEX_EMAIL, recipients_str)
        return emails

    def _extract_attachment(self, part) -> None:
        """Extract attachment metadata and content."""
        attachment_info = {
            'filename': self._decode_header(part.get_filename() or 'unknown'),
            'content_type': part.get_content_type(),
            'size': len(part.get_payload(decode=True) or b''),
            'hash_md5': '',
            'hash_sha256': ''
        }

        payload = part.get_payload(decode=True)
        if payload:
            attachment_info['hash_md5'] = hashlib.md5(payload).hexdigest()
            attachment_info['hash_sha256'] = hashlib.sha256(payload).hexdigest()

        self.attachments.append(attachment_info)


# ============================================================================
# CLASS: HeaderAnalyzer
# ============================================================================

class HeaderAnalyzer:
    """Analyzes email headers for authentication (SPF, DKIM, DMARC) and routing."""

    def __init__(self, headers: Dict[str, str]):
        self.headers = headers
        self.spoofing_indicators: List[str] = []
        self.auth_results: Dict[str, str] = {}
        self.received_chain: List[Dict[str, Any]] = []

    def analyze(self) -> Dict[str, Any]:
        """Run full header analysis."""
        results = {}

        results['spf_result'] = self.check_spf()
        results['dkim_result'] = self.check_dkim()
        results['dmarc_result'] = self.check_dmarc()
        results['spoofing_indicators'] = self.detect_spoofing()
        results['received_chain'] = self.parse_received_headers()
        results['originating_ip'] = self.extract_originating_ip()
        results['reply_to_mismatch'] = self.check_reply_to_mismatch()
        results['return_path_mismatch'] = self.check_return_path_mismatch()
        results['urgency_indicators'] = self.detect_urgency_indicators()

        return results

    def check_spf(self) -> Dict[str, str]:
        """Check SPF authentication result."""
        for header, value in self.headers.items():
            if 'Received-SPF' in header or 'spf=' in value.lower():
                if 'pass' in value.lower():
                    return {'status': 'PASS', 'details': value}
                elif 'fail' in value.lower():
                    return {'status': 'FAIL', 'details': value}
                elif 'softfail' in value.lower():
                    return {'status': 'SOFTFAIL', 'details': value}
                elif 'neutral' in value.lower():
                    return {'status': 'NEUTRAL', 'details': value}
                else:
                    return {'status': 'UNKNOWN', 'details': value}
        return {'status': 'NOT_PRESENT', 'details': 'No SPF header found'}

    def check_dkim(self) -> Dict[str, str]:
        """Check DKIM signature presence and result."""
        dkim_headers = []
        auth_results = self.headers.get('Authentication-Results', '')

        # Check Authentication-Results for DKIM
        if 'dkim=' in auth_results.lower():
            if 'dkim=pass' in auth_results.lower():
                return {'status': 'PASS', 'details': auth_results}
            elif 'dkim=fail' in auth_results.lower():
                return {'status': 'FAIL', 'details': auth_results}
            elif 'dkim=none' in auth_results.lower():
                return {'status': 'NOT_SIGNED', 'details': auth_results}

        # Check for DKIM-Signature header
        for header, value in self.headers.items():
            if 'DKIM-Signature' in header:
                dkim_headers.append(value)

        if dkim_headers:
            return {'status': 'SIGNED', 'details': f'{len(dkim_headers)} DKIM signature(s) found'}
        return {'status': 'NOT_PRESENT', 'details': 'No DKIM header found'}

    def check_dmarc(self) -> Dict[str, str]:
        """Check DMARC authentication result."""
        auth_results = self.headers.get('Authentication-Results', '')

        if 'dmarc=pass' in auth_results.lower():
            return {'status': 'PASS', 'details': auth_results}
        elif 'dmarc=fail' in auth_results.lower():
            return {'status': 'FAIL', 'details': auth_results}
        elif 'dmarc=none' in auth_results.lower():
            return {'status': 'NO_POLICY', 'details': auth_results}
        elif 'dmarc=' in auth_results.lower():
            return {'status': 'PRESENT', 'details': auth_results}

        dmarc_header = self.headers.get('DMARC-Filter', '')
        if dmarc_header:
            return {'status': 'PRESENT', 'details': dmarc_header}

        return {'status': 'NOT_PRESENT', 'details': 'No DMARC header found'}

    def detect_spoofing(self) -> List[str]:
        """Detect common email spoofing indicators."""
        indicators = []

        from_addr = self.headers.get('From', '')
        reply_to = self.headers.get('Reply-To', '')
        return_path = self.headers.get('Return-Path', '')
        sender = self.headers.get('Sender', '')

        # Reply-To mismatch
        if reply_to and from_addr and reply_to != from_addr:
            from_domain = from_addr.split('@')[-1].strip() if '@' in from_addr else ''
            reply_domain = reply_to.split('@')[-1].strip() if '@' in reply_to else ''
            if from_domain and reply_domain and from_domain != reply_domain:
                indicators.append(f"Reply-To ({reply_to}) differs from From ({from_addr})")

        # Return-Path mismatch
        if return_path:
            return_domain = return_path.split('@')[-1].strip() if '@' in return_path else ''
            if from_addr:
                from_domain = from_addr.split('@')[-1].strip() if '@' in from_addr else ''
                if return_path.startswith('<'):
                    return_path = return_path.strip('<>')
                if return_path and return_path.split('@')[-1] != from_domain:
                    indicators.append(f"Return-Path ({return_path}) differs from From domain ({from_domain})")

        # Homograph attack detection (lookalike domains)
        lookalike_patterns = {
            'microsoft': ['micros0ft', 'microsft', 'rnicrosoft'],
            'apple': ['appIe', 'appla'],
            'google': ['gooqle', '9oogle'],
            'amazon': ['amazzon', 'arnazon'],
            'paypal': ['paypaI', 'paypa1'],
            'netflix': ['netf1ix', 'netfl1x']
        }

        for brand, variants in lookalike_patterns.items():
            if any(v in from_addr.lower() for v in variants):
                indicators.append(f"Possible typosquatting: detected '{brand}' variant in From address")

        # Check for suspicious display name
        display_name = from_addr.split('<')[0].strip().rstrip('"') if '<' in from_addr else ''
        suspicious_names = ['IT Support', 'Security Team', 'Account Verification', 'Administrator']
        if any(name.lower() in display_name.lower() for name in suspicious_names):
            indicators.append(f"Suspicious display name detected: '{display_name}'")

        return indicators

    def check_reply_to_mismatch(self) -> bool:
        """Check if Reply-To differs from From."""
        from_addr = self.headers.get('From', '')
        reply_to = self.headers.get('Reply-To', '')
        return reply_to and from_addr and reply_to != from_addr

    def check_return_path_mismatch(self) -> bool:
        """Check if Return-Path domain differs from From domain."""
        from_addr = self.headers.get('From', '')
        return_path = self.headers.get('Return-Path', '').strip('<>')
        if from_addr and return_path:
            from_domain = from_addr.split('@')[-1].strip() if '@' in from_addr else ''
            return_path_domain = return_path.split('@')[-1].strip() if '@' in return_path else ''
            return from_domain != return_path_domain
        return False

    def parse_received_headers(self) -> List[Dict[str, str]]:
        """Parse and parse email routing from Received headers."""
        received_headers = []

        # Collect all Received headers in order
        for key, value in self.headers.items():
            if key == 'Received':
                if isinstance(value, list):
                    received_headers.extend(value)
                else:
                    received_headers.append(value)

        results = []
        for i, received in enumerate(reversed(received_headers)):
            hop = {'hop_number': i + 1, 'raw': received, 'server': '', 'ip': '', 'date': ''}

            # Extract 'by' server
            by_match = re.search(r'by\s+([^\s;]+)', received, re.IGNORECASE)
            if by_match:
                hop['server'] = by_match.group(1).strip(';')

            # Extract IP from 'from' clause
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
            if ip_match:
                hop['ip'] = ip_match.group(1)

            # Extract date
            date_match = re.search(r'with\s+[^;]+;\s*([^;]+)', received)
            if not date_match:
                date_match = re.search(r';\s*([^;]+)', received)
            if date_match:
                hop['date'] = date_match.group(1).strip()

            results.append(hop)

        return results

    def extract_originating_ip(self) -> str:
        """Extract the originating IP address from headers."""
        received_headers = []
        for key, value in self.headers.items():
            if key == 'Received':
                if isinstance(value, list):
                    received_headers.extend(value)
                else:
                    received_headers.append(value)

        # The last 'Received' header typically has the originating IP
        for received in reversed(received_headers):
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
            if ip_match:
                return ip_match.group(1)

        # Try X-Originating-IP header
        return self.headers.get('X-Originating-IP', '').strip('<> ')

    def detect_urgency_indicators(self) -> List[str]:
        """Detect urgency keywords in subject line."""
        subject = self.headers.get('Subject', '').lower()
        urgency_words = [
            'urgent', 'immediate', 'action required', 'suspended',
            'expire', 'confirm now', 'last warning', 'unusual activity',
            'verify immediately', 'account locked', 'security alert',
            'required action', 'update now', 'suspended account'
        ]

        found = []
        for word in urgency_words:
            if word in subject:
                found.append(word)

        return found


# ============================================================================
# CLASS: IOCExtractor
# ============================================================================

class IOCExtractor:
    """Extracts indicators of compromise from email content."""

    def __init__(self, body_text: str, body_html: str, headers: Dict[str, str]):
        self.body_text = body_text
        self.body_html = body_html
        self.headers = headers
        self.all_content = f"{body_text} {body_html}"
        self.iocs: Dict[str, List[Dict[str, Any]]] = {
            'domains': [],
            'urls': [],
            'ip_addresses': [],
            'emails': [],
            'file_hashes': [],
            'filenames': []
        }

    def extract_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Extract all IOC types."""
        self._extract_domains()
        self._extract_urls()
        self._extract_ips()
        self._extract_emails()
        self._extract_file_hashes()
        return self.iocs

    def _extract_domains(self) -> None:
        """Extract and analyze domains."""
        domains = set(re.findall(REGEX_DOMAIN, self.all_content))

        # Filter out common benign domains
        benign_domains = {
            'microsoft.com', 'office.com', 'outlook.com', 'live.com',
            'google.com', 'gmail.com', 'googleusercontent.com',
            'facebook.com', 'twitter.com', 'linkedin.com',
            'amazon.com', 'apple.com', 'youtube.com',
            'github.com', 'stackoverflow.com'
        }

        for domain in domains:
            # Skip subdomains of benign domains and local/network addresses
            if domain.endswith(tuple(benign_domains)):
                continue

            # Skip IP-based domains
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                continue

            # Skip common CDNs
            if any(cd in domain for cd in ['cdn', 'cloudfront', 'akamai', 'fastly']):
                continue

            domain_info = {
                'domain': domain,
                'is_suspicious_tld': False,
                'brand_impersonation': None,
                'typosquatting_target': None
            }

            # Check for suspicious TLD
            domain_ext = '.' + domain.split('.')[-1]
            if domain_ext.lower() in SUSPICIOUS_TLDS:
                domain_info['is_suspicious_tld'] = True

            # Brand impersonation detection
            brand_keywords = {
                'microsoft': r'micros\w*soft|microsoft|office365|o365',
                'google': r'google|gmail|g\s*mail',
                'apple': r'apple|icloud|mac\s*os',
                'amazon': r'amazon|amzn',
                'paypal': r'paypal|pay\s*pal',
                'netflix': r'netflix|netf\s*lix',
                'facebook': r'facebook|meta|fb',
                'linkedin': r'linkedin|lnkd',
                'dropbox': r'dropbox|drop\s*box'
            }

            for brand, pattern in brand_keywords.items():
                if re.search(pattern, domain, re.IGNORECASE) and brand not in domain.lower():
                    domain_info['brand_impersonation'] = brand.title()
                    break
                elif brand in domain.lower():
                    # Check for typosquatting
                    known_typos = {
                        'microsoft': 'microsoft.com',
                        'google': 'google.com',
                        'apple': 'apple.com',
                        'amazon': 'amazon.com',
                        'paypal': 'paypal.com'
                    }
                    if brand in known_typos and domain.lower() != known_typos[brand]:
                        domain_info['typosquatting_target'] = brand.title()

            self.iocs['domains'].append(domain_info)

    def _extract_urls(self) -> None:
        """Extract URLs and analyze them."""
        urls = re.findall(REGEX_URL, self.all_content)
        seen_urls = set()

        for url in urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)

            parsed = urlparse(unquote(url))
            url_info = {
                'original_url': url,
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'domain': parsed.hostname or '',
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'is_ip_url': False,
                'is_shortened': False,
                'suspicious_patterns': []
            }

            # Check if URL uses IP instead of domain
            if parsed.hostname and re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.hostname):
                url_info['is_ip_url'] = True
                url_info['suspicious_patterns'].append('URL uses IP address instead of domain')

            # Detect URL shorteners
            shortener_domains = {
                'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'tr.im',
                'is.gd', 'ow.ly', 'buff.ly', 'amzn.to', 'short.link'
            }
            if parsed.netloc.lower() in shortener_domains or any(s in parsed.netloc for s in ['short', 'link', 'redir']):
                url_info['is_shortened'] = True
                url_info['suspicious_patterns'].append('URL shortener detected')

            # Check for suspicious patterns
            if '..' in url:
                url_info['suspicious_patterns'].append('Double dot in URL')
            if '@' in parsed.netloc:
                url_info['suspicious_patterns'].append('Credentials in URL ( phishing technique)')
            if parsed.scheme != 'https' and any(kw in parsed.netloc.lower() for kw in ['login', 'account', 'secure', 'verify']):
                url_info['suspicious_patterns'].append('Non-HTTPS URL for sensitive operation')
            if len(parsed.netloc) > 50:
                url_info['suspicious_patterns'].append('Suspiciously long domain')

            self.iocs['urls'].append(url_info)

    def _extract_ips(self) -> None:
        """Extract IP addresses."""
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = set(re.findall(ip_pattern, self.all_content))

        # Also check headers for IPs
        for key, value in self.headers.items():
            found = re.findall(ip_pattern, str(value))
            ips.update(found)

        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                ip_info = {
                    'ip': ip,
                    'version': ip_obj.version,
                    'is_private': ip_obj.is_private,
                    'is_loopback': ip_obj.is_loopback,
                    'is_reserved': ip_obj.is_reserved,
                    'is_global': ip_obj.is_global,
                    'geo_info': {}
                }

                # GeoIP lookup (basic implementation)
                if REQUESTS_AVAILABLE and ip_obj.is_global:
                    try:
                        response = requests.get(
                            f'http://ip-api.com/json/{ip}',
                            timeout=5
                        )
                        if response.status_code == 200:
                            geo_data = response.json()
                            ip_info['geo_info'] = {
                                'country': geo_data.get('country', ''),
                                'region': geo_data.get('regionName', ''),
                                'city': geo_data.get('city', ''),
                                'isp': geo_data.get('isp', ''),
                                'org': geo_data.get('org', ''),
                                'as': geo_data.get('as', '')
                            }
                    except Exception:
                        pass

                self.iocs['ip_addresses'].append(ip_info)
            except ValueError:
                continue

    def _extract_emails(self) -> None:
        """Extract email addresses from content."""
        emails = set(re.findall(REGEX_EMAIL, self.all_content))

        for email_addr in emails:
            email_info = {
                'email': email_addr,
                'local_part': email_addr.split('@')[0] if '@' in email_addr else '',
                'domain': email_addr.split('@')[1] if '@' in email_addr else '',
                'is_from_header': False,
                'is_in_body': True


# ============================================================================
# CLASS: ThreatIntelligence
# ============================================================================

class ThreatIntelligence:
    """Perform threat intelligence lookups on extracted IOCs."""

    def __init__(self, iocs: Dict[str, List[Dict[str, Any]]]):
        self.iocs = iocs
        self.results: Dict[str, Any] = {}

    def lookup_all(self) -> Dict[str, Any]:
        """Perform all available threat intel lookups."""
        if not REQUESTS_AVAILABLE:
            print("[!] requests library not available. Skipping threat intel lookups.")
            return {'error': 'requests library not available'}

        self.results = {
            'domains': [],
            'ips': [],
            'urls': [],
            'hashes': [],
            'whois_lookups': [],
            'virustotal_lookups': []
        }

        self._lookup_domains()
        self._lookup_ips()
        self._whois_lookup()
        self._virustotal_lookup()

        return self.results

    def _lookup_domains(self) -> None:
        """Check domain reputation via public APIs."""
        print("[i] Performing domain reputation lookups...")

        for domain_info in self.iocs.get('domains', []):
            domain = domain_info.get('domain', '')
            if not domain:
                continue

            result = {
                'domain': domain,
                'categories': [],
                'reputation': 'unknown',
                'ip': '',
                'nameservers': [],
                'sample_malware_urls': []
            }

            try:
                # DNS lookup for IP
                ip = socket.gethostbyname(domain)
                result['ip'] = ip
            except socket.gaierror:
                result['ip'] = 'NXDOMAIN (domain does not resolve)'
                result['reputation'] = 'suspicious - domain does not resolve'

            try:
                # NS lookup
                ns_records = socket.getaddrinfo(domain, None)
                # Try to get MX/NX records
                result['nameservers'] = [item[4][0] for item in ns_records[:5]]
            except:
                pass

            self.results['domains'].append(result)
            print(f"  [+] {domain}: IP={result['ip']}, NS={len(result['nameservers'])}")

    def _lookup_ips(self) -> None:
        """Check IP reputation."""
        print("[i] Performing IP reputation lookups...")

        for ip_info in self.iocs.get('ip_addresses', []):
            ip = ip_info.get('ip', '')
            if not ip or ip_info.get('is_private', False):
                continue

            result = {
                'ip': ip,
                'abuse_contact': '',
                'threat_score': 0,
                'threat_types': [],
                'last_reported': ''
            }

            try:
                # AbuseIPDB-style lookup (simplified)
                response = requests.get(
                    f'http://api.hackertarget.com/ipapi/?q={ip}',
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json() if response.text.startswith('{') else {}
                    result['threat_score'] = data.get('score', 0)
            except:
                pass

            self.results['ips'].append(result)

    def _whois_lookup(self) -> None:
        """Perform WHOIS lookups on suspicious domains."""
        print("[i] Performing WHOIS lookups...")

        for domain_info in self.iocs.get('domains', []):
            domain = domain_info.get('domain', '')
            if not domain:
                continue

            whois_result = {
                'domain': domain,
                'registrar': '',
                'creation_date': '',
                'expiration_date': '',
                'registrant_country': '',
                'name_servers': [],
                'status': [],
                'age_days': 0,
                'is_recently_registered': False
            }

            try:
                w = whois.whois(domain)
                whois_result['registrar'] = str(w.registrar) if hasattr(w, 'registrar') and w.registrar else ''
                whois_result['creation_date'] = str(w.creation_date) if hasattr(w, 'creation_date') and w.creation_date else ''
                whois_result['expiration_date'] = str(w.expiration_date) if hasattr(w, 'expiration_date') and w.expiration_date else ''
                whois_result['registrant_country'] = str(w.country) if hasattr(w, 'country') and w.country else ''
                whois_result['name_servers'] = list(w.name_servers) if hasattr(w, 'name_servers') and w.name_servers else []
                whois_result['status'] = list(w.status) if hasattr(w, 'status') and w.status else []

                # Calculate domain age
                if w.creation_date:
                    created = w.creation_date
                    if isinstance(created, list):
                        created = created[0]
                    if isinstance(created, datetime):
                        age = datetime.now() - created
                        whois_result['age_days'] = age.days
                        whois_result['is_recently_registered'] = age.days < 30
            except Exception as e:
                whois_result['error'] = str(e)

            self.results['whois_lookups'].append(whois_result)
            print(f"  [+] WHOIS: {domain} - Registrar: {whois_result['registrar'][:30] if whois_result['registrar'] else 'N/A'}")

    def _virustotal_lookup(self) -> None:
        """Generate VirusTotal lookup URLs (requires API key for full lookup)."""
        print("[i] Generating VirusTotal lookup URLs...")

        # Domain lookups
        for domain_info in self.iocs.get('domains', []):
            domain = domain_info.get('domain', '')
            if not domain:
                continue
            vt_url = f"https://www.virustotal.com/gui/domain/{domain}"
            self.results['virustotal_lookups'].append({
                'type': 'domain',
                'value': domain,
                'url': vt_url
            })

        # IP lookups
        for ip_info in self.iocs.get('ip_addresses', []):
            ip = ip_info.get('ip', '')
            if not ip:
                continue
            vt_url = f"https://www.virustotal.com/gui/ip-address/{ip}"
            self.results['virustotal_lookups'].append({
                'type': 'ip',
                'value': ip,
                'url': vt_url
            })

        # URL lookups
        for url_info in self.iocs.get('urls', []):
            url = url_info.get('original_url', '')
            if not url:
                continue
            vt_url = f"https://www.virustotal.com/gui/search/{url}"
            self.results['virustotal_lookups'].append({
                'type': 'url',
                'value': url,
                'url': vt_url
            })

        print(f"  [+] Generated {len(self.results['virustotal_lookups'])} VirusTotal lookup URLs")


# ============================================================================
# CLASS: ReportGenerator
# ============================================================================

class ReportGenerator:
    """Generates structured investigation reports in JSON and Markdown formats."""

    def __init__(self, parser: EmailParser, header_analysis: Dict, iocs: Dict,
                 threat_intel: Dict, output_dir: str = REPORT_DIR):
        self.parser = parser
        self.header_analysis = header_analysis
        self.iocs = iocs
        self.threat_intel = threat_intel
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_id = f"PHIR-{self.timestamp}"

    def generate_all(self) -> Dict[str, str]:
        """Generate all report formats."""
        os.makedirs(self.output_dir, exist_ok=True)

        outputs = {}
        outputs['json'] = self.generate_json()
        outputs['markdown'] = self.generate_markdown()
        outputs['html'] = self.generate_console_output()

        return outputs

    def _calculate_risk_score(self) -> Tuple[int, str]:
        """Calculate overall phishing risk score (0-100)."""
        score = 0
        factors = []

        # SPF/DKIM/DMARC failures (30 points max)
        spf = self.header_analysis.get('spf_result', {}).get('status', '')
        dmarc = self.header_analysis.get('dmarc_result', {}).get('status', '')
        dkim = self.header_analysis.get('dkim_result', {}).get('status', '')

        if spf in ['FAIL', 'SOFTFAIL']:
            score += 15
            factors.append('SPF authentication failed')
        elif spf == 'NOT_PRESENT':
            score += 5
            factors.append('SPF header not present')

        if dmarc in ['FAIL', 'NOT_PRESENT']:
            score += 10
            factors.append('DMARC authentication failed or not present')

        if dkim in ['FAIL', 'NOT_PRESENT']:
            score += 5
            factors.append('DKIM authentication failed or not present')

        # Spoofing indicators (20 points max)
        spoofing_count = len(self.header_analysis.get('spoofing_indicators', []))
        if spoofing_count > 0:
            score += min(spoofing_count * 5, 20)
            factors.append(f'{spoofing_count} spoofing indicator(s) detected')

        # Suspicious TLDs (15 points)
        suspicious_tlds = sum(1 for d in self.iocs.get('domains', []) if d.get('is_suspicious_tld'))
        if suspicious_tlds > 0:
            score += min(suspicious_tlds * 5, 15)
            factors.append(f'{suspicious_tlds} suspicious TLD domain(s) found')

        # Brand impersonation (15 points)
        impersonations = sum(1 for d in self.iocs.get('domains', []) if d.get('brand_impersonation'))
        if impersonations > 0:
            score += min(impersonations * 5, 15)
            factors.append(f'{impersonations} brand impersonation domain(s) found')

        # Recently registered domains (10 points)
        recent_domains = sum(1 for w in self.threat_intel.get('whois_lookups', [])
                            if w.get('is_recently_registered', False))
        if recent_domains > 0:
            score += min(recent_domains * 5, 10)
            factors.append(f'{recent_domains} recently registered domain(s) found')

        # URL suspicious patterns (10 points)
        suspicious_urls = sum(len(u.get('suspicious_patterns', []))
                             for u in self.iocs.get('urls', []))
        if suspicious_urls > 0:
            score += min(suspicious_urls * 2, 10)
            factors.append(f'{suspicious_urls} suspicious URL pattern(s) detected')

        # Urgency indicators (5 points)
        urgency_count = len(self.header_analysis.get('urgency_indicators', []))
        if urgency_count > 0:
            score += min(urgency_count, 5)
            factors.append(f'{urgency_count} urgency keyword(s) in subject')

        # Determine severity level
        if score >= 75:
            severity = 'CRITICAL'
        elif score >= 50:
            severity = 'HIGH'
        elif score >= 25:
            severity = 'MEDIUM'
        elif score > 0:
            severity = 'LOW'
        else:
            severity = 'INFORMATIONAL'

        return score, severity

    def generate_json(self) -> str:
        """Generate JSON format report."""
        score, severity = self._calculate_risk_score()

        report = {
            'report_id': self.report_id,
            'generated_at': datetime.now().isoformat(),
            'tool_version': VERSION,
            'source_file': self.parser.file_path,
            'severity': {
                'score': score,
                'level': severity,
                'factors': self.header_analysis.get('spoofing_indicators', [])
            },
            'email_summary': {
                'subject': self.parser.subject,
                'from': self.parser.sender,
                'to': self.parser.recipients,
                'has_attachments': len(self.parser.attachments) > 0,
                'attachment_count': len(self.parser.attachments)
            },
            'header_analysis': self.header_analysis,
            'iocs': self.iocs,
            'threat_intelligence': self.threat_intel,
            'attachments': self.parser.attachments
        }

        # Save to file
        filename = f"{self.output_dir}/{self.report_id}_report.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"[+] JSON report saved: {filename}")
        return filename

    def generate_markdown(self) -> str:
        """Generate Markdown format report."""
        score, severity = self._calculate_risk_score()

        md = f"""# Phishing Investigation Report

**Report ID:** {self.report_id}
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool:** PhishingInvestigator v{VERSION}
**Source File:** {self.parser.file_path}

---

## Risk Assessment

| Metric | Value |
|--------|-------|
| Risk Score | {score}/100 |
| Severity Level | **{severity}** |
| SPF Status | {self.header_analysis.get('spf_result', {}).get('status', 'N/A')} |
| DKIM Status | {self.header_analysis.get('dkim_result', {}).get('status', 'N/A')} |
| DMARC Status | {self.header_analysis.get('dmarc_result', {}).get('status', 'N/A')} |
| Spoofing Indicators | {len(self.header_analysis.get('spoofing_indicators', []))} |

### Risk Factors

"""

        # Add risk factors
        spf = self.header_analysis.get('spf_result', {}).get('status', '')
        dmarc = self.header_analysis.get('dmarc_result', {}).get('status', '')
        dkim = self.header_analysis.get('dkim_result', {}).get('status', '')

        if spf in ['FAIL', 'SOFTFAIL']:
            md += "- [X] SPF authentication failed\n"
        if dmarc in ['FAIL', 'NOT_PRESENT']:
            md += "- [X] DMARC authentication failed or not present\n"
        if dkim in ['FAIL', 'NOT_PRESENT']:
            md += "- [X] DKIM authentication failed or not present\n"

        for indicator in self.header_analysis.get('spoofing_indicators', []):
            md += f"- [X] {indicator}\n"

        suspicious_tlds = [d['domain'] for d in self.iocs.get('domains', []) if d.get('is_suspicious_tld')]
        for domain in suspicious_tlds:
            md += f"- [X] Suspicious TLD domain found: {domain}\n"

        md += f"""
---

## Email Summary

| Field | Value |
|-------|-------|
| Subject | {self.parser.subject} |
| From | {self.parser.sender} |
| To | {', '.join(self.parser.recipients)} |
| Attachments | {len(self.parser.attachments)} |

---

## Indicators of Compromise

### Domains

"""

        for domain in self.iocs.get('domains', []):
            flags = []
            if domain.get('is_suspicious_tld'):
                flags.append('Suspicious TLD')
            if domain.get('brand_impersonation'):
                flags.append(f"Brand impersonation: {domain['brand_impersonation']}")
            if domain.get('typosquatting_target'):
                flags.append(f"Typosquatting: {domain['typosquatting_target']}")
            flag_str = ', '.join(flags) if flags else 'None'
            md += f"- **{domain['domain']}** - {flag_str}\n"

        md += "\n### URLs\n\n"
        for url in self.iocs.get('urls', [])[:10]:  # Limit to first 10
            issues = url.get('suspicious_patterns', [])
            issue_str = ', '.join(issues) if issues else 'None detected'
            md += f"- `{url['original_url'][:80]}...` - {issue_str}\n"

        md += "\n### IP Addresses\n\n"
        for ip in self.iocs.get('ip_addresses', [])[:10]:
            geo = ip.get('geo_info', {})
            location = f"{geo.get('country', 'Unknown')}, {geo.get('city', 'Unknown')}"
            md += f"- **{ip['ip']}** - {location} ({ip['version']})\n"

        if self.parser.attachments:
            md += "\n### Attachments\n\n| Filename | Type | Size | MD5 | SHA256 |\n|----------|------|------|-----|--------|\n"
            for att in self.parser.attachments:
                md += f"| {att['filename']} | {att['content_type']} | {att['size']} bytes | {att['hash_md5']} | {att['hash_sha256']} |\n"

        md += f"""
---

## Threat Intelligence

### WHOIS Lookup Results

"""

        for whois_result in self.threat_intel.get('whois_lookups', []):
            if whois_result.get('error'):
                md += f"- **{whois_result['domain']}**: Error - {whois_result['error']}\n"
            else:
                md += f"""
- **{whois_result['domain']}**
  - Registrar: {whois_result.get('registrar', 'N/A')}
  - Created: {whois_result.get('creation_date', 'N/A')}
  - Age: {whois_result.get('age_days', 'N/A')} days ({'RECENTLY REGISTERED' if whois_result.get('is_recently_registered') else 'Established'})
  - Country: {whois_result.get('registrant_country', 'N/A')}
"""

        md += "\n### VirusTotal Lookups\n\n"
        for vt in self.threat_intel.get('virustotal_lookups', [])[:10]:
            md += f"- [{vt['type'].upper()}: {vt['value'][:50]}...]({vt['url']})\n"

        md += f"""

---

## Header Analysis

### Authentication Results

| Header | Result |
|--------|--------|
| SPF | {self.header_analysis.get('spf_result', {}).get('status', 'N/A')} |
| DKIM | {self.header_analysis.get('dkim_result', {}).get('status', 'N/A')} |
| DMARC | {self.header_analysis.get('dmarc_result', {}).get('status', 'N/A')} |
| Reply-To Mismatch | {'Yes' if self.header_analysis.get('reply_to_mismatch') else 'No'} |
| Return-Path Mismatch | {'Yes' if self.header_analysis.get('return_path_mismatch') else 'No'} |

### Email Routing

| Hop | Server | IP | Date |
|-----|--------|-----|------|
"""

        for hop in self.header_analysis.get('received_chain', [])[:5]:
            md += f"| {hop.get('hop_number', '')} | {hop.get('server', 'N/A')[:30]} | {hop.get('ip', 'N/A')} | {hop.get('date', 'N/A')[:20]} |\n"

        if self.header_analysis.get('urgency_indicators'):
            md += f"\n### Urgency Indicators\n\n- {', '.join(self.header_analysis['urgency_indicators'])}\n"

        md += "\n---\n\n*Generated by PhishingInvestigator - SOCxProjects*\n"

        # Save to file
        filename = f"{self.output_dir}/{self.report_id}_report.md"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md)

        print(f"[+] Markdown report saved: {filename}")
        return filename

    def generate_console_output(self) -> str:
        """Generate and print formatted console output."""
        score, severity = self._calculate_risk_score()

        separator = "=" * 70

        print("\n" + separator)
        print("  P H I S H I N G   I N V E S T I G A T I O N   R E P O R T")
        print(separator)
        print(f"  Report ID:     {self.report_id}")
        print(f"  Source File:   {self.parser.file_path}")
        print(f"  Generated:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Tool Version:  v{VERSION} - SOCxProjects")
        print(separator)

        print("\n>>> RISK ASSESSMENT")
        print("-" * 40)
        score_bar = "#" * int(score / 5) + "." * (20 - int(score / 5))
        print(f"  Risk Score:    [{score_bar}] {score}/100")
        print(f"  Severity:      {severity}")
        print(f"  SPF:           {self.header_analysis.get('spf_result', {}).get('status', 'N/A')}")
        print(f"  DKIM:          {self.header_analysis.get('dkim_result', {}).get('status', 'N/A')}")
        print(f"  DMARC:         {self.header_analysis.get('dmarc_result', {}).get('status', 'N/A')}")

        print("\n>>> EMAIL SUMMARY")
        print("-" * 40)
        print(f"  Subject:    {self.parser.subject[:60]}...")
        print(f"  From:       {self.parser.sender}")
        print(f"  Recipients: {', '.join(self.parser.recipients[:3])}{'...' if len(self.parser.recipients) > 3 else ''}")
        print(f"  Attachments: {len(self.parser.attachments)}")

        print("\n>>> INDICATORS OF COMPROMISE")
        print("-" * 40)
        print(f"  Domains:     {len(self.iocs.get('domains', []))}")
        print(f"  URLs:        {len(self.iocs.get('urls', []))}")
        print(f"  IP Addresses: {len(self.iocs.get('ip_addresses', []))}")
        print(f"  Emails:      {len(self.iocs.get('emails', []))}")
        print(f"  File Hashes: {len(self.iocs.get('file_hashes', []))}")

        suspicious = [d for d in self.iocs.get('domains', []) if d.get('is_suspicious_tld') or d.get('brand_impersonation')]
        if suspicious:
            print(f"\n  [!] {len(suspicious)} suspicious domain(s) flagged:")
            for d in suspicious:
                flags = []
                if d.get('is_suspicious_tld'):
                    flags.append('suspicious TLD')
                if d.get('brand_impersonation'):
                    flags.append(f"impersonates {d['brand_impersonation']}")
                print(f"      - {d['domain']} ({', '.join(flags)})")

        if self.header_analysis.get('spoofing_indicators'):
            print("\n>>> SPOOFING INDICATORS")
            print("-" * 40)
            for indicator in self.header_analysis['spoofing_indicators']:
                print(f"  [!] {indicator}")

        print("\n" + separator)
        print(f"  REPORTS SAVED TO: {self.output_dir}/")
        print(separator)

        return f"{self.output_dir}/console_output.txt"


# ============================================================================
# CLASS: PhishingInvestigator (Main Orchestrator)
# ============================================================================

class PhishingInvestigator:
    """Main orchestrator class that coordinates the investigation workflow."""

    def __init__(self, file_path: str, output_dir: str = REPORT_DIR,
                 include_threat_intel: bool = True, verbose: bool = True):
        self.file_path = file_path
        self.output_dir = output_dir
        self.include_threat_intel = include_threat_intel
        self.verbose = verbose
        self.parser: Optional[EmailParser] = None
        self.header_analysis: Dict = {}
        self.iocs: Dict = {}
        self.threat_intel: Dict = {}
        self.report: Optional[ReportGenerator] = None

    def investigate(self) -> Dict[str, Any]:
        """Run the full investigation pipeline."""
        results = {'success': False, 'error': None}

        print(f"\n{'='*60}")
        print(f"  PhishingInvestigator v{VERSION} - SOCxProjects")
        print(f"{'='*60}")
        print(f"\n[*] Analyzing file: {self.file_path}\n")

        # Step 1: Parse the email
        print("[Step 1/4] Parsing email file...")
        self.parser = EmailParser(self.file_path)
        if not self.parser.parse():
            results['error'] = 'Failed to parse email file'
            return results

        print(f"  Subject: {self.parser.subject}")
        print(f"  From: {self.parser.sender}")
        print(f"  Recipients: {len(self.parser.recipients)}")
        print(f"  Attachments: {len(self.parser.attachments)}\n")

        # Step 2: Header analysis
        print("[Step 2/4] Analyzing email headers...")
        analyzer = HeaderAnalyzer(self.parser.headers)
        self.header_analysis = analyzer.analyze()
        print(f"  SPF: {self.header_analysis.get('spf_result', {}).get('status')}")
        print(f"  DKIM: {self.header_analysis.get('dkim_result', {}).get('status')}")
        print(f"  DMARC: {self.header_analysis.get('dmarc_result', {}).get('status')}")
        print(f"  Originating IP: {self.header_analysis.get('originating_ip', 'N/A')}")
        spoofing = self.header_analysis.get('spoofing_indicators', [])
        if spoofing:
            print(f"  [WARN] {len(spoofing)} spoofing indicator(s) detected!")
        print()

        # Step 3: IOC extraction
        print("[Step 3/4] Extracting indicators of compromise...")
        extractor = IOCExtractor(
            self.parser.body_text,
            self.parser.body_html,
            self.parser.headers
        )
        self.iocs = extractor.extract_all()
        print(f"  Domains: {len(self.iocs.get('domains', []))}")
        print(f"  URLs: {len(self.iocs.get('urls', []))}")
        print(f"  IP Addresses: {len(self.iocs.get('ip_addresses', []))}")
        print(f"  Emails: {len(self.iocs.get('emails', []))}")
        print(f"  File Hashes: {len(self.iocs.get('file_hashes', []))}\n")

        # Step 4: Threat intelligence
        if self.include_threat_intel and REQUESTS_AVAILABLE:
            print("[Step 4/4] Performing threat intelligence lookups...")
            threat_intel = ThreatIntelligence(self.iocs)
            self.threat_intel = threat_intel.lookup_all()
            print(f"  WHOIS lookups: {len(self.threat_intel.get('whois_lookups', []))}")
            print(f"  VirusTotal URLs: {len(self.threat_intel.get('virustotal_lookups', []))}\n")
        elif self.include_threat_intel and not REQUESTS_AVAILABLE:
            print("[Step 4/4] Skipping threat intel (requests library not available)\n")
            self.threat_intel = {'error': 'requests not available'}
        else:
            self.threat_intel = {}

        # Generate reports
        print("[Final] Generating investigation reports...")
        self.report = ReportGenerator(
            self.parser,
            self.header_analysis,
            self.iocs,
            self.threat_intel,
            self.output_dir
        )
        self.report.generate_all()

        results['success'] = True
        results['risk_score'] = self.report._calculate_risk_score()
        results['report_id'] = self.report.report_id
        results['output_dir'] = self.output_dir

        return results

      # --- COMMAND LINE INTERFACE ---

def main():
    """Main entry point for the phishing investigation tool."""
    parser = argparse.ArgumentParser(
        description="PhishingInvestigator - Automated Phishing Email Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishing-investigator.py suspicious_email.eml
  python phishing-investigator.py -i phishing.eml -o ./reports -t
  python phishing-investigator.py -i email.msg --output-dir /tmp
"""
    )
    
    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to the email file (.eml or .msg)"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="./phishing_reports",
        help="Output directory for generated reports (default: ./phishing_reports)"
    )
    parser.add_argument(
        "-t", "--threat-intel",
        action="store_true",
        help="Enable threat intelligence lookups (WHOIS, VirusTotal)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Generate only JSON report (skip Markdown)"
    )
    
    args = parser.parse_args()
    
    print("="*60)
    print("  PhishingInvestigator - SOCxProjects")
    print("="*60)
    print()
    
    print(f"[*] Input file: {args.input}")
    print(f"[*] Output directory: {args.output_dir}")
    print(f"[*] Threat intelligence: {'Enabled' if args.threat_intel else 'Disabled'}")
    print(f"[*] Verbose: {'Yes' if args.verbose else 'No'}")
    print(f"[*] JSON only: {'Yes' if args.json_only else 'No'}")
    print()
    
    investigator = PhishingInvestigator(
        email_path=args.input,
        output_dir=args.output_dir,
        include_threat_intel=args.threat_intel,
        json_only=args.json_only,
        verbose=args.verbose
    )
    
    try:
        results = investigator.investigate()
        
        print()
        print("="*60)
        print("  INVESTIGATION COMPLETE")
        print("="*60)
        print(f"[*] Success: {results.get('success', False)}")
        print(f"[*] Risk Score: {results.get('risk_score', 'N/A')}/100")
        print(f"[*] Report ID: {results.get('report_id', 'N/A')}")
        print(f"[*] Output directory: {results.get('output_dir', 'N/A')}")
        
    except FileNotFoundError:
        print(f"[!] Error: File '{args.input}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
