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
