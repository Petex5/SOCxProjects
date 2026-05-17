#!/usr/bin/env python3
"""
soc-analyzer.py - Python SOC Analyzer Tool
A modular command-line tool for SOC analysts that automates:
- Log parsing and analysis
- IOC extraction (IPs, domains, URLs, hashes)
- IP reputation checking via threat intelligence APIs
- Alert generation and reporting

Author: SOCxProjects Lab 5
Version: 1.0.0
"""

import argparse
import re
import json
import csv
import sys
import logging
from datetime import datetime
from collections import Counter
from typing import Dict, List, Optional, Tuple

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# =============================================================================
# IOC EXTRACTION PATTERNS (Module 1)
# =============================================================================

class IOCExtractor:
    """Extract Indicators of Compromise from log data and text."""

    PATTERNS = {
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'url': r'https?://[\w./?=&%#-]+',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
    }

    def __init__(self):
        self.compiled_patterns = {name: re.compile(pattern) for name, pattern in self.PATTERNS.items()}
        self.results: Dict[str, List[str]] = {name: [] for name in self.PATTERNS}

    def extract_from_text(self, text: str) -> Dict[str, List[str]]:
        for name, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            self.results[name].extend(matches)
        self._deduplicate()
        return self.results

    def extract_from_file(self, filepath: str) -> Dict[str, List[str]]:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.extract_from_text(content)
        except FileNotFoundError:
            logger.error(f"File not found: {filepath}")
            return self.results
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return self.results

    def extract_from_log_lines(self, lines: List[str]) -> Dict[str, List[str]]:
        for line in lines:
            self.extract_from_text(line)
        return self.results

    def _deduplicate(self):
        for name in self.results:
            self.results[name] = list(set(self.results[name]))

    def clear(self):
        for name in self.results:
            self.results[name] = []

    def summary(self) -> Dict[str, int]:
        return {name: len(items) for name, items in self.results.items()}

logger.info("[IOC] IOC extraction module loaded.")

# =============================================================================
# LOG PARSER MODULE (Module 2)
# =============================================================================

class LogParser:
    """Parse and analyse structured log files (Syslog, Apache, Windows Event Logs)."""

    APACHE_COMBINED = (
        r'(?P<ip>[\d.]+)\s+-\s+-\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>[^"]+)\s+[^"]+"\s+'
        r'(?P<status>\d+)\s+(?P<size>\d+)'
    )

    SYSLOG_FORMAT = (
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+'
        r'(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<host>[\w.-]+)\s+'
        r'(?P<process>[\w_-]+)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)'
    )

    COMMON_FORMAT = (
        r'(?P<host>[\w.-]+)\s+'
        r'(?P<ident>\S+)?\s*'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'(?P<message>.*)'
    )

    def __init__(self, log_format: str = 'auto'):
        self.log_format = log_format
        self.parsed_lines: List[Dict] = []
        self._compile_patterns()

    def _compile_patterns(self):
        self.patterns = {
            'apache': re.compile(self.APACHE_COMBINED),
            'syslog': re.compile(self.SYSLOG_FORMAT),
            'common': re.compile(self.COMMON_FORMAT),
        }

    def detect_format(self, line: str) -> str:
        for name, pattern in self.patterns.items():
            if pattern.match(line):
                return name
        return 'unknown'

    def parse_line(self, line: str) -> Optional[Dict]:
        if self.log_format == 'auto':
            fmt = self.detect_format(line)
        else:
            fmt = self.log_format
        if fmt == 'unknown':
            return {'raw': line.strip()}
        match = self.patterns[fmt].match(line)
        if match:
            return match.groupdict()
        return {'raw': line.strip()}

    def parse_file(self, filepath: str) -> List[Dict]:
        self.parsed_lines = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parsed = self.parse_line(line)
                    if parsed:
                        self.parsed_lines.append(parsed)
            logger.info(f"[Parser] Parsed {len(self.parsed_lines)} lines from {filepath}")
        except FileNotFoundError:
            logger.error(f"[Parser] File not found: {filepath}")
        except Exception as e:
            logger.error(f"[Parser] Error: {e}")
        return self.parsed_lines

    def search(self, keyword: str) -> List[Dict]:
        return [line for line in self.parsed_lines
                if keyword.lower() in str(line).lower()]

    def get_statistics(self) -> Dict:
        if not self.parsed_lines:
            return {}
        hosts = Counter(p.get('host', 'N/A') for p in self.parsed_lines)
        return {
            'total_lines': len(self.parsed_lines),
            'unique_hosts': len(hosts),
            'top_hosts': dict(hosts.most_common(5)),
        }

logger.info("[Parser] Log parser module loaded.")

# =============================================================================
# THREAT INTELLIGENCE (Module 3)
# =============================================================================
class ThreatIntel:
    """Check IP reputation via threat intelligence APIs."""

    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

    def __init__(self, abuseipdb_key: str = None, virustotal_key: str = None):
        self.abuseipdb_key = abuseipdb_key
        self.virustotal_key = virustotal_key
        self.results: Dict[str, Dict] = {}

    def check_ip(self, ip: str) -> Dict:
        """Check single IP reputation (simulated without external calls)."""
        import metrics
        logger.info(f"[ThreatIntel] Checking IP: {ip}")
        result = {
            "ip": ip,
            "reputation": "unknown",
            "abuse_score": 0,
            "categories": [],
            "last_reported": None,
            "reported_count": 0
        }
        self.results[ip] = result
        logger.info(f"[ThreatIntel] IP check complete for {ip}")
        return result

    def check_multiple_ips(self, ips: List[str]) -> List[Dict]:
        """Check multiple IPs and return all results."""
        return [self.check_ip(ip) for ip in ips]

    def get_summary(self) -> Dict:
        """Get summary of all threat intelligence checks."""
        total = len(self.results)
        suspicious = sum(1 for r in self.results.values() if r.get("abuse_score", 0) > 50)
        return {
            "total_checked": total,
            "suspicious_count": suspicious,
            "clean_count": total - suspicious
        }

    @staticmethod
    def check_ip_online(ip: str, api_key: str, provider: str = "abuseipdb") -> Dict:
        """Actually call threat intelligence API (requires valid key)."""
        try:
            import requests
            if provider == "abuseipdb":
                headers = {"Key": api_key, "Accept": "application/json"}
                response = requests.get(
                    f"{ThreatIntel.ABUSEIPDB_URL}?ipAddress={ip}",
                    headers=headers
                )
                data = response.json()
                return {
                    "ip": ip,
                    "abuse_score": data.get("data", {}).get("abuseConfidenceScore", 0),
                    "reported_count": data.get("data", {}).get("totalReports", 0)
                }
        except Exception as e:
            logger.error(f"[ThreatIntel] API error: {e}")
        return {"ip": ip, "error": str(e)}

logger.info("[ThreatIntel] Threat intelligence module loaded.")

# =============================================================================
# ALERT GENERATOR (Module 4)
# =============================================================================
class AlertGenerator:
    """Generate security alerts based on parsed data and threat intelligence."""

    ALERT_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }

    def __init__(self):
        self.alerts: List[Dict] = []

    def generate_alert(self, alert_type: str, severity: str, source_ip: str = None,
                       destination_ip: str = None, description: str = "",
                       confidence: int = 50) -> Dict:
        """Generate a single security alert."""
        level = self.ALERT_LEVELS.get(severity.lower(), 1)
        alert = {
            "id": f"ALERT-{len(self.alerts) + 1:05d}",
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "severity": severity,
            "level": level,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "description": description,
            "confidence": confidence,
            "status": "new",
            "analyst_assigned": None
        }
        self.alerts.append(alert)
        logger.info(f"[AlertGen] Alert generated: {alert['id']} - {severity} - {alert_type}")
        return alert

    def update_status(self, alert_id: str, status: str, analyst: str = None) -> bool:
        """Update alert status."""
        for alert in self.alerts:
            if alert["id"] == alert_id:
                alert["status"] = status
                if analyst:
                    alert["analyst_assigned"] = analyst
                logger.info(f"[AlertGen] Alert {alert_id} updated to {status}")
                return True
        return False

    def filter_by_severity(self, min_severity: str = "low") -> List[Dict]:
        """Filter alerts by minimum severity level."""
        min_level = self.ALERT_LEVELS.get(min_severity.lower(), 1)
        return [a for a in self.alerts if a["level"] >= min_level]

    def export_to_csv(self, filepath: str) -> None:
        """Export alerts to CSV file."""
        if not self.alerts:
            logger.warning("[AlertGen] No alerts to export")
            return
        try:
            with open(filepath, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=self.alerts[0].keys())
                writer.writeheader()
                writer.writerows(self.alerts)
            logger.info(f"[AlertGen] Alerts exported to {filepath}")
        except Exception as e:
            logger.error(f"[AlertGen] Export error: {e}")

    def get_summary(self) -> Dict:
        """Get alert summary statistics."""
        by_severity = Counter(a["severity"].lower() for a in self.alerts)
        by_status = Counter(a["status"] for a in self.alerts)
        return {
            "total_alerts": len(self.alerts),
            "by_severity": dict(by_severity),
            "by_status": dict(by_status)
        }

logger.info("[AlertGen] Alert generator module loaded.")

# =============================================================================
# REPORT GENERATOR (Module 5)
# =============================================================================
class ReportGenerator:
    """Generate analysis reports from SOC data."""

    def __init__(self):
        self.report_data: Dict = {}

    def compile_report(self, ioc_extractor: object = None, parser: object = None,
                       threat_intel: object = None, alert_gen: object = None) -> Dict:
        """Compile all module data into a single report."""
        self.report_data = {
            "report_id": f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "tool_version": "1.0.0",
            "modules": {}
        }
        if parser:
            self.report_data["modules"]["parser"] = parser.get_statistics()
        if threat_intel:
            self.report_data["modules"]["threat_intel"] = threat_intel.get_summary()
        if alert_gen:
            self.report_data["modules"]["alerts"] = alert_gen.get_summary()
        if ioc_extractor:
            self.report_data["modules"]["iocs"] = {
                k: len(v) for k, v in ioc_extractor.results.items()
            }
        logger.info("[ReportGen] Report compiled successfully")
        return self.report_data

    def export_to_json(self, filepath: str) -> None:
        """Export report to JSON file."""
        try:
            with open(filepath, "w") as f:
                json.dump(self.report_data, f, indent=2)
            logger.info(f"[ReportGen] Report exported to {filepath}")
        except Exception as e:
            logger.error(f"[ReportGen] JSON export error: {e}")

    def print_report(self) -> None:
        """Print report to console."""
        print("\n" + "=" * 60)
        print("  SOC ANALYZER REPORT")
        print("=" * 60)
        print(f"Report ID: {self.report_data.get('report_id', 'N/A')}")
        print(f"Generated: {self.report_data.get('generated_at', 'N/A')}")
        print("-" * 60)
        for mod, data in self.report_data.get("modules", {}).items():
            print(f"\n[Module: {mod.upper()}]")
            for k, v in data.items():
                print(f"  {k}: {v}")
        print("=" * 60 + "\n")

logger.info("[ReportGen] Report generator module loaded.")

# =============================================================================
# MAIN EXECUTION
# =============================================================================
def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="soc-analyzer",
        description="SOC Analyzer Tool - Modular security log analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python soc-analyzer.py parse -f /var/log/auth.log
  python soc-analyzer.py extract -f sample.log
  python soc-analyzer.py report -f sample.log -o report.json
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Parse subcommand
    parse_p = subparsers.add_parser("parse", help="Parse and analyze log file")
    parse_p.add_argument("-f", "--file", required=True, help="Path to log file")
    parse_p.add_argument("-F", "--format", default="auto",
                         help="Log format (auto|syslog|apache|cisco)")
    parse_p.add_argument("-s", "--search", help="Search keyword in parsed logs")

    # Extract subcommand
    extract_p = subparsers.add_parser("extract", help="Extract IOCs from file")
    extract_p.add_argument("-f", "--file", required=True, help="Path to file")
    extract_p.add_argument("-t", "--type", help="Specific IOC type to extract")
    extract_p.add_argument("-o", "--output", help="Output file (JSON)")

    # Threat intel subcommand
    intel_p = subparsers.add_parser("intel", help="Check threat intelligence")
    intel_p.add_argument("-i", "--ip", help="IP address to check")
    intel_p.add_argument("-f", "--file", help="File with IPs (one per line)")
    intel_p.add_argument("-o", "--output", help="Output file (JSON)")

    # Alert subcommand
    alert_p = subparsers.add_parser("alert", help="Generate alert")
    alert_p.add_argument("-t", "--type", required=True, help="Alert type")
    alert_p.add_argument("-s", "--severity", default="medium",
                         help="Severity (low|medium|high|critical)")
    alert_p.add_argument("--src", help="Source IP")
    alert_p.add_argument("--dst", help="Destination IP")
    alert_p.add_argument("-d", "--description", default="", help="Alert description")

    # Report subcommand
    report_p = subparsers.add_parser("report", help="Generate full analysis report")
    report_p.add_argument("-f", "--file", required=True, help="Path to log file")
    report_p.add_argument("-o", "--output", default="soc_report.json",
                          help="Output report file")
    report_p.add_argument("-v", "--verbose", action="store_true",
                          help="Enable verbose output")
    args = parser.parse_args()

    if not args.command:
        print("\nSOC Analyzer v1.0.0 - Modular Security Log Analysis Tool")
        print("=" * 50)
        print("Modules:")
        print("  [1] IOC Extraction - Extract IPs, domains, hashes, URLs")
        print("  [2] Log Parser     - Parse syslog, Apache, Cisco logs")
        print("  [3] Threat Intel   - IP reputation checking")
        print("  [4] Alert Gen      - Generate security alerts")
        print("  [5] Report         - Compile analysis reports")
        print("=" * 50)
        print("\nUse: soc-analyzer.py <command> --help")
        print("Commands: parse, extract, intel, alert, report")
        return

    logger.info(f"[Main] Starting {args.command} command...")

    try:
        # Command dispatch
        if args.command == "parse":
            lp = LogParser(fmt=args.format)
            data = lp.parse_file(args.file)
            if args.search:
                results = lp.search(args.search)
                print(json.dumps(results, indent=2))
            else:
                stats = lp.get_statistics()
                print(json.dumps(stats, indent=2))

        elif args.command == "extract":
            ext = IOCExtractor()
            results = ext.extract_from_file(args.file)
            if args.type and args.type in results:
                results = {args.type: results[args.type]}
            output = json.dumps(results, indent=2)
            if args.output:
                with open(args.output, "w") as f:
                    f.write(output)
                print(f"IOCs saved to {args.output}")
            else:
                print(output)

        elif args.command == "intel":
            ti = ThreatIntel()
            if args.ip:
                result = ti.check_ip(args.ip)
                print(json.dumps(result, indent=2))
            elif args.file:
                with open(args.file) as f:
                    ips = [line.strip() for line in f if line.strip()]
                results = ti.check_multiple_ips(ips)
                output = json.dumps(results, indent=2)
                if args.output:
                    with open(args.output, "w") as out:
                        out.write(output)
                    print(f"Threat intel results saved to {args.output}")
                else:
                    print(output)
            else:
                print("No IP or file specified for threat intel check")

        elif args.command == "alert":
            ag = AlertGenerator()
            alert = ag.generate_alert(
                alert_type=args.type,
                severity=args.severity,
                source_ip=args.src,
                destination_ip=args.dst,
                description=args.description
            )
            print(json.dumps(alert, indent=2))
            print(f"Alert {alert['id']} generated.")

        elif args.command == "report":
            lp = LogParser()
            ext = IOCExtractor()
            ti = ThreatIntel()
            ag = AlertGenerator()

            lp.parse_file(args.file)
            ext.extract_from_file(args.file)

            report_gen = ReportGenerator()
            report_gen.compile_report(
                ioc_extractor=ext, parser=lp,
                threat_intel=ti, alert_gen=ag
            )
            report_gen.export_to_json(args.output)
            print(f"Report saved to {args.output}")
            if args.verbose:
                report_gen.print_report()

        else:
            logger.error(f"Unknown command: {args.command}")
            parser.print_help()

    except FileNotFoundError as e:
        logger.error(f"File not found: {e.filename}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

    logger.info(f"[Main] {args.command} completed.")


if __name__ == "__main__":
    main()
